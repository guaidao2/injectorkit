"""Finding the call that opens an archive.

An uploaded phar is inert on its own. PHP 8 does not deserialize a metadata blob
when something reads inside the archive - only when the application asks for the
metadata - so the chain needs a place in the target that opens an archive it was
pointed at. That place is what this looks for, and it is a real thing to look
for: applications load configuration, caches and bundles out of phar files, and
the call is ordinary framework code.

It is found by the error it produces. Give a value that is not an archive and PHP
says so in its own words:

    Cannot create phar '/etc/passwd', file extension (or combination) not
    recognised or the directory does not exist

That sentence only appears when the value reached `new Phar(...)`. It is proof
of the call site rather than a symptom of one, which is what makes it worth
sending a request for - and the same sentence is what tells us which parameter
to aim the archive at.

The value is a plain path, deliberately. `phar:///path` is answered by whatever
`is_file()` sits in front of the constructor, because a stream wrapper is not a
path a file check accepts - which is how the first version of this got the wrong
answer on a target that was in fact vulnerable.
"""

from __future__ import annotations

from dataclasses import dataclass

# PHP's own words when a value reaches the Phar constructor and is not an
# archive. Each one has to mean the constructor was *reached*: a bare "phar
# error" is not in the list because PHP also says it about an archive that was
# opened and found wanting, which is a different fact about the target.
OPENS_ARCHIVES = (
    "cannot create phar",
    "unable to open phar",
    "not a phar archive",
    "invalid phar archive",
    "file extension (or combination) not recognised",
)

# What it says when the value is fine but the file is not there, which is a
# different failure and says nothing about a constructor.
NOT_THERE = (
    "no such file",
    "does not exist",
    "failed to open stream",
    "no such config",
)


@dataclass
class ArchiveSink:
    """A parameter the target hands to something that opens archives."""

    param: str = ""
    payload: str = ""
    evidence: str = ""
    # The value produced PHP's Phar-constructor error rather than a plain
    # not-found, which is what separates a call site from an ordinary read.
    confirmed: bool = False

    def describe(self) -> str:
        if not self.confirmed:
            return ""
        return (
            f"{self.param} is handed to something that opens archives: pointing it at a "
            f"file that is not one makes PHP say so ({self.evidence})"
        )


def looks_like_archive_sink(body: str) -> str:
    """PHP's own complaint about a value that reached the Phar constructor."""
    lowered = (body or "").lower()
    for marker in OPENS_ARCHIVES:
        if marker in lowered:
            index = lowered.find(marker)
            line = body[max(0, index - 60) : index + 160].strip().splitlines()[0]
            return line.strip()
    return ""


def looks_like_missing(body: str) -> bool:
    """A plain not-found, which says nothing about a constructor."""
    lowered = (body or "").lower()
    return any(marker in lowered for marker in NOT_THERE) and not looks_like_archive_sink(body)


def probe_archive_sink(ctx, param, marker_path: str = "/etc/passwd") -> ArchiveSink:
    """Point one parameter at a file that is not an archive and read the answer.

    `/etc/passwd` is the value because it is a real file that exists on any POSIX
    target: a not-found error would be ambiguous, and this one is not. What comes
    back separates the two failures that matter - the target opening archives
    from the target merely looking for a file.
    """
    from .inject import inject

    request, exchange = inject(ctx, param, marker_path, "probe.archive-sink")
    body = exchange.response.text
    if exchange.response.error:
        return ArchiveSink()

    evidence = looks_like_archive_sink(body)
    if evidence:
        return ArchiveSink(
            param=param.key(),
            payload=marker_path,
            evidence=evidence[:200],
            confirmed=True,
        )
    return ArchiveSink()
