"""Which PHP is answering, because the answer changes what is possible.

Phar metadata used to deserialize whenever an archive was touched. PHP 8.0
stopped that - from its own UPGRADING notes:

    "Phar: Metadata associated with a phar will no longer be automatically
     unserialized, to fix potential security vulnerabilities due to object
     instantiation, autoloading, etc."

So on a PHP 8 target the whole file-function route is gone and only an explicit
`Phar::getMetadata()` call reaches a gadget. On PHP 7 it is the other way round:
`file_exists()`, `stat()`, `md5_file()` and the rest reach one on their own,
which is what makes a phar upload dangerous without any code path that looks
like deserialization.

Establishing the version is therefore not a nicety. It decides whether a run
should be trying to get an archive touched by any file function it can reach, or
looking for the one application call that asks for the metadata. Getting it
wrong sends the whole chain down a route that cannot work on that target.

Three places the answer comes from, cheapest first, and they are checked in that
order because the first is a header and the last is a request that may not be
answered at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# `X-Powered-By: PHP/8.4.24`, and the same string in a `Server` header on some
# configurations.
_POWERED_BY = re.compile(r"PHP/(\d+)\.(\d+)(?:\.(\d+))?", re.I)

# What a phpinfo() page says, and what an error page says when it names itself.
_PHPINFO = re.compile(r"PHP Version\s*</td>\s*<td[^>]*>\s*([\d.]+)", re.I)
_ERROR_PAGE = re.compile(r"PHP\s+(\d+\.\d+\.\d+)", re.I)


@dataclass
class PhpVersion:
    """What is known about the version, and what it implies."""

    version: str = ""
    source: str = ""

    @property
    def known(self) -> bool:
        return bool(self.version)

    @property
    def major(self) -> int:
        try:
            return int(self.version.split(".")[0])
        except (ValueError, IndexError):
            return 0

    @property
    def automatic_phar_metadata(self) -> bool:
        """Whether merely touching an archive deserializes its metadata.

        True before PHP 8, false from 8.0 onward. This is the single fact the
        phar chain turns on.
        """
        return 0 < self.major < 8

    def describe(self) -> str:
        if not self.known:
            return "the PHP version was not established"
        if self.automatic_phar_metadata:
            return (
                f"PHP {self.version} ({self.source}): an archive's metadata is deserialized when "
                "the archive is opened, so any file function reaching one is enough"
            )
        return (
            f"PHP {self.version} ({self.source}): an archive's metadata is not deserialized by "
            "opening it, so the application has to ask for it - Phar::getMetadata() is the call "
            "that reaches a gadget"
        )


def from_headers(headers) -> PhpVersion:
    """The version a response admits to, which costs nothing to read."""
    for name in ("X-Powered-By", "Server"):
        value = headers.get(name) if headers else None
        if not value:
            continue
        match = _POWERED_BY.search(value)
        if match:
            patch = f".{match.group(3)}" if match.group(3) else ""
            return PhpVersion(version=f"{match.group(1)}.{match.group(2)}{patch}", source=name)
    return PhpVersion()


def from_body(body: str) -> PhpVersion:
    """The version a page says about itself, when it says anything.

    A phpinfo() page states it outright. So does the error page a fatal error
    produces, which is often reachable on a target where nothing else is. And so
    does a file read off the target - a composer lock, a build file, a php.ini -
    because the shape is the same wherever it came from.
    """
    if not body:
        return PhpVersion()
    match = _PHPINFO.search(body)
    if match:
        return PhpVersion(version=match.group(1), source="a phpinfo() page")
    match = _ERROR_PAGE.search(body)
    if match:
        return PhpVersion(version=match.group(1), source="an error page")
    return PhpVersion()
