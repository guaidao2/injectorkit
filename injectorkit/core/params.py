"""The parameter model: where a value lives, and how to rewrite exactly it.

A parameter is addressed by location, raw name, and which occurrence of that
name it is. The engine never re-encodes a whole request to change one value:
rewriting a query string through a URL parser would reorder the surviving
parameters, drop duplicates and normalise encodings, and the request that then
reaches the target is not the one we will report as evidence.

So every rewrite happens on the raw text. A value is replaced in place, and
nothing around it moves.

A JSON body is the one place where that rule bends. The document has to stay
parseable, so the field is addressed by path - `user.url`, `items[0].href` - and
the document is rebuilt around it. Everything else keeps its value, though not
necessarily its spacing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import quote, unquote

from .httpmsg import Request

# Names that are never worth injecting into: a request for a form is answered
# by a fresh token, and a button is not a value the application reads.
DEFAULT_SKIP = (
    "csrf_token", "csrftoken", "_csrf", "csrfmiddlewaretoken",
    "authenticity_token", "__requestverificationtoken", "xsrf_token",
    "_token", "nonce", "submit", "commit", "button",
)


# Headers an application is likely to read as input rather than as transport -
# the ones that decide who the caller is, or where the request came from. A
# header outside this list still gets injected when the operator names it with
# -H: saying "this one" is a clearer statement than any default.
INJECTABLE_HEADERS = frozenset(
    {
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "x-originating-ip",
        "x-client-ip",
        "client-ip",
        "forwarded",
        "referer",
        "origin",
        "authorization",
        "x-auth-token",
        "x-api-key",
        "x-original-url",
        "x-rewrite-url",
        "x-http-method-override",
    }
)


class Where(str, Enum):
    """Where in a request a value lives."""

    QUERY = "query"
    BODY = "body"
    COOKIE = "cookie"
    HEADER = "header"
    PATH = "path"
    JSON = "json"
    # A parameter whose value is itself a JSON document, e.g.
    # `?json={"ref":"http://..."}` - the field inside is what carries the URL.
    JSON_EMBED = "json-embed"
    # One part of a multipart/form-data body.
    MULTIPART = "multipart"
    # The filename a multipart part declares. A part that carries a file is
    # addressed twice: by its field name, which is the value the application
    # reads, and by this, which is the name the file will be stored under. Only
    # the second one reaches a path, so it is a position of its own.
    MULTIPART_FILENAME = "multipart-filename"


class Encode(str, Enum):
    """How a value is spelled on the wire."""

    NONE = "none"
    URL = "url"
    DOUBLE = "double"

    def apply(self, value: str) -> str:
        if self is Encode.URL:
            return quote(value, safe="")
        if self is Encode.DOUBLE:
            return quote(quote(value, safe=""), safe="")
        return value


@dataclass(frozen=True)
class Param:
    """One injectable position in a request."""

    where: Where
    name: str
    value: str
    occurrence: int = 0
    header: str = ""
    # For JSON_EMBED: the path inside the document carried by the parameter,
    # and where that parameter itself lives.
    embed_path: str = ""
    embed_where: Where | None = None

    def key(self) -> str:
        """Stable identifier used in sessions, evidence and skip lists."""
        suffix = f"#{self.occurrence}" if self.occurrence else ""
        if self.where is Where.HEADER:
            return f"header:{self.header}{suffix}"
        if self.where is Where.JSON_EMBED and self.embed_path:
            return f"{self.name} -> {self.embed_path}"
        return f"{self.where.value}:{self.name}{suffix}"

    def describe(self) -> str:
        return self.key()


def split_url(url: str) -> tuple[str, str, str]:
    """Split a URL into (base, query, fragment) without normalising anything."""
    base, _, rest = url.partition("#")
    fragment = rest
    path, _, query = base.partition("?")
    return path, query, fragment


def join_url(base: str, query: str, fragment: str = "") -> str:
    url = base
    if query:
        url += "?" + query
    if fragment:
        url += "#" + fragment
    return url


def extract_params(
    request: Request,
    skip: tuple[str, ...] = DEFAULT_SKIP,
    max_params: int = 32,
    extra_headers: frozenset[str] = frozenset(),
) -> list[Param]:
    """List the injectable positions of a request, in a stable order.

    `extra_headers` are header names to treat as injectable in addition to the
    usual set - what the operator named with -H.
    """
    params: list[Param] = []
    skipped = {name.lower() for name in skip}

    for where, name, value, occurrence in _query_pairs(request.url):
        if name.lower() in skipped:
            continue
        params.append(Param(where=where, name=name, value=value, occurrence=occurrence))

    for where, name, value, occurrence in _header_pairs(request, extra_headers):
        if name.lower() in skipped:
            continue
        params.append(Param(where=where, name=name, value=value, occurrence=occurrence, header=name))

    for where, name, value, occurrence in _body_pairs(request):
        if name.lower() in skipped:
            continue
        params.append(Param(where=where, name=name, value=value, occurrence=occurrence))

    for where, name, value, occurrence in _cookie_pairs(request):
        if name.lower() in skipped:
            continue
        params.append(Param(where=where, name=name, value=value, occurrence=occurrence))

    for where, name, value, occurrence in _json_pairs(request):
        if name.lower() in skipped:
            continue
        params.append(Param(where=where, name=name, value=value, occurrence=occurrence))

    for param in _embedded_json_params(request, skipped):
        params.append(param)

    for where, name, value, occurrence in _multipart_pairs(request):
        if name.lower() in skipped:
            continue
        params.append(Param(where=where, name=name, value=value, occurrence=occurrence))

    return params[:max_params]


def extract_named(request: Request, key: str) -> Param | None:
    """Find one parameter by its key, as printed by :meth:`Param.describe`."""
    for param in extract_params(request, skip=(), extra_headers=frozenset({"*"})):
        if param.key() == key or param.name == key:
            return param
    return None


def rewrite(request: Request, param: Param, value: str, encode: Encode = Encode.NONE) -> Request:
    """Return a copy of the request with this parameter's value replaced."""
    out = request.clone()
    raw = encode.apply(value)
    out.label = f"{param.key()} = {value}"

    if param.where is Where.QUERY:
        base, query, fragment = split_url(out.url)
        out.url = join_url(base, _replace_pair(query, param, raw), fragment)
    elif param.where is Where.BODY:
        body = _replace_pair(out.body.decode("latin-1"), param, raw)
        out.body = body.encode("latin-1")
        out.headers.set("Content-Length", str(len(out.body)))
    elif param.where is Where.COOKIE:
        header = out.headers.get("Cookie", "") or ""
        out.headers.set("Cookie", _replace_cookie(header, param, raw))
    elif param.where is Where.HEADER:
        out.headers.set(param.header, raw)
    elif param.where is Where.PATH:
        out.url = _replace_path_segment(out.url, param, raw)
    elif param.where is Where.JSON:
        body = _set_json(out.body, param.name, raw)
        out.body = body
        out.headers.set("Content-Length", str(len(body)))
    elif param.where is Where.JSON_EMBED:
        # The raw value, not the encoded one: a JSON string needs escaping, not
        # percent-encoding, and only the document around it goes on the wire
        # encoded. Encoding the field as well hands the application a URL it
        # cannot fetch.
        _rewrite_embedded(out, param, value)
    elif param.where is Where.MULTIPART:
        _rewrite_multipart(out, param, raw)
    return out


def rewrite_name(request: Request, param: Param, name: str, value: str, encode: Encode = Encode.NONE) -> Request:
    """Replace a parameter's name and value together (document-store operators)."""
    out = request.clone()
    raw_name = encode.apply(name)
    raw_value = encode.apply(value)
    out.label = f"{param.key()} -> {name} = {value}"

    if param.where is Where.QUERY:
        base, query, fragment = split_url(out.url)
        out.url = join_url(base, _replace_pair(query, param, raw_value, raw_name), fragment)
    elif param.where is Where.BODY:
        body = _replace_pair(out.body.decode("latin-1"), param, raw_value, raw_name)
        out.body = body.encode("latin-1")
        out.headers.set("Content-Length", str(len(out.body)))
    return out


# ------------------------------------------------------------------ internals


def _query_pairs(url: str) -> list[tuple[Where, str, str, int]]:
    _, query, _ = split_url(url)
    return _pairs(query, Where.QUERY, "&")


def _header_pairs(
    request: Request, extra: frozenset[str] = frozenset()
) -> list[tuple[Where, str, str, int]]:
    """Headers worth injecting into, by name.

    Not every header: rewriting Accept-Encoding tells nobody anything and costs a
    request. This is the set an application is likely to read as input rather
    than as transport - the ones that decide who the caller is, or where the
    request came from - plus any name in `extra`, which is what the operator
    passed with -H. A house authentication header is the case that matters:
    naming it is the only way the tool can know the application reads it.
    """
    out: list[tuple[Where, str, str, int]] = []
    for name, value in request.headers.items():
        if name.lower() in INJECTABLE_HEADERS or name.lower() in extra:
            out.append((Where.HEADER, name, value, 0))
    return out


def _body_pairs(request: Request) -> list[tuple[Where, str, str, int]]:
    content_type = (request.headers.get("Content-Type") or "").lower()
    if "application/x-www-form-urlencoded" not in content_type:
        return []
    return _pairs(request.body.decode("latin-1"), Where.BODY, "&")


def _cookie_pairs(request: Request) -> list[tuple[Where, str, str, int]]:
    header = request.headers.get("Cookie")
    if not header:
        return []
    return _pairs(header, Where.COOKIE, ";")


def _json_pairs(request: Request) -> list[tuple[Where, str, str, int]]:
    """Every string field of a JSON body, addressed by path.

    An application that hands a JSON body to a fetcher is as reachable as one
    with a query parameter, and a scanner that only reads the query string walks
    straight past it. Nested objects and arrays are flattened so a field inside
    `{"user": {"avatar": ...}}` is addressable like any other.
    """
    content_type = (request.headers.get("Content-Type") or "").lower()
    if "json" not in content_type or not request.body:
        return []
    try:
        document = json.loads(request.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return []

    out: list[tuple[Where, str, str, int]] = []
    _collect_json(document, "", out, limit=64)
    return out


def _collect_json(node: object, prefix: str, out: list, limit: int) -> None:
    if len(out) >= limit:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            _collect_json_value(value, path, out, limit)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            path = f"{prefix}[{index}]"
            _collect_json_value(value, path, out, limit)


def _collect_json_value(value: object, path: str, out: list, limit: int) -> None:
    if len(out) >= limit:
        return
    if isinstance(value, str):
        out.append((Where.JSON, path, value, 0))
    elif isinstance(value, (dict, list)):
        _collect_json(value, path, out, limit)


def pollute(request: Request, param: Param, value: str, encode: Encode = Encode.URL) -> Request:
    """Send the parameter twice: the request's own value first, the payload last.

    A filter that reads one value per name judges the first occurrence; a runtime
    that keeps the last one executes the second. Both are looking at the same
    request, and neither is looking at the other's string - which is why this is
    worth trying when no rewrite of the value gets through.

    Only positions that can carry a duplicate are handled: a query string, a form
    body, a cookie. Everything else comes back unchanged.
    """
    out = request.clone()
    encoded = encode.apply(value)

    if param.where is Where.QUERY:
        base, query, fragment = split_url(out.url)
        joined = f"{query}&{param.name}={encoded}" if query else f"{param.name}={encoded}"
        out.url = join_url(base, joined, fragment)
    elif param.where is Where.BODY:
        body = out.body.decode("latin-1")
        body = f"{body}&{param.name}={encoded}" if body else f"{param.name}={encoded}"
        out.body = body.encode("latin-1")
        out.headers.set("Content-Length", str(len(out.body)))
    elif param.where is Where.COOKIE:
        header = out.headers.get("Cookie", "") or ""
        joined = f"{header}; {param.name}={encoded}" if header else f"{param.name}={encoded}"
        out.headers.set("Cookie", joined)
    elif param.where is Where.HEADER:
        # A second occurrence of the same header, the original left in place. A
        # filter reading the first value and a framework keeping the last are
        # looking at different strings out of one request - the same disagreement
        # as a duplicated query parameter, in a place fewer filters watch.
        out.headers.add(param.header, encoded)
    else:
        return out

    return out


def _embedded_json_params(request: Request, skipped: set[str]) -> list[Param]:
    """Parameters whose value is itself a JSON document.

    `?json={"ref":"http://..."}` carries the URL one level down. Treating the
    whole value as an opaque string replaces the document and tests nothing;
    the field inside is the parameter.
    """
    found: list[Param] = []
    sources = (
        (Where.QUERY, _query_pairs(request.url)),
        (Where.BODY, _body_pairs(request)),
        (Where.COOKIE, _cookie_pairs(request)),
    )
    for outer, pairs in sources:
        for _, name, value, occurrence in pairs:
            if name.lower() in skipped or len(found) >= 16:
                continue
            stripped = unquote(value).strip()
            if not stripped.startswith(("{", "[")):
                continue
            try:
                document = json.loads(stripped)
            except ValueError:
                continue
            fields: list[tuple[Where, str, str, int]] = []
            _collect_json(document, "", fields, limit=8)
            for _, path, field_value, _ in fields:
                found.append(
                    Param(
                        where=Where.JSON_EMBED,
                        name=name,
                        value=field_value,
                        occurrence=occurrence,
                        embed_path=path,
                        embed_where=outer,
                    )
                )
    return found


def _rewrite_embedded(request: Request, param: Param, new_value: str) -> None:
    """Replace one field inside a JSON document carried by a parameter."""
    outer_value = _outer_value(request, param)
    if outer_value is None:
        return
    try:
        document = json.loads(outer_value)
    except ValueError:
        return
    if not _assign_json(document, param.embed_path, new_value):
        return
    rebuilt = quote(json.dumps(document, ensure_ascii=False, separators=(",", ":")), safe="")

    if param.embed_where is Where.QUERY:
        base, query, fragment = split_url(request.url)
        request.url = join_url(base, _replace_pair_in(query, param, rebuilt, "&"), fragment)
    elif param.embed_where is Where.BODY:
        body = _replace_pair_in(request.body.decode("latin-1"), param, rebuilt, "&")
        request.body = body.encode("latin-1")
        request.headers.set("Content-Length", str(len(request.body)))
    elif param.embed_where is Where.COOKIE:
        header = request.headers.get("Cookie", "") or ""
        request.headers.set("Cookie", _replace_pair_in(header, param, rebuilt, ";"))


def _outer_value(request: Request, param: Param) -> str | None:
    """Read the parameter that carries the document, decoded."""
    if param.embed_where is Where.QUERY:
        _, query, _ = split_url(request.url)
        return _find_pair_value(query, param.name, param.occurrence, "&")
    if param.embed_where is Where.BODY:
        return _find_pair_value(request.body.decode("latin-1"), param.name, param.occurrence, "&")
    if param.embed_where is Where.COOKIE:
        header = request.headers.get("Cookie", "") or ""
        return _find_pair_value(header, param.name, param.occurrence, ";")
    return None


def _find_pair_value(raw: str, name: str, occurrence: int, separator: str) -> str | None:
    seen = 0
    for part in raw.split(separator):
        candidate, sep, value = part.partition("=")
        if not sep:
            continue
        key = candidate.strip() if separator == ";" else candidate
        if key != name:
            continue
        if seen == occurrence:
            text = value.strip() if separator == ";" else value
            return unquote(text)
        seen += 1
    return None


def _replace_pair_in(raw: str, param: Param, new_value: str, separator: str) -> str:
    """`_replace_pair` with the separator named by the caller."""
    if not raw:
        return f"{param.name}={new_value}"
    parts = raw.split(separator)
    seen = 0
    for index, part in enumerate(parts):
        name, sep, _ = part.partition("=")
        if not sep:
            continue
        candidate = name.strip() if separator == ";" else name
        if candidate != param.name:
            continue
        if seen == param.occurrence:
            prefix = " " if separator == ";" else ""
            parts[index] = f"{prefix}{name}={new_value}"
            joined = separator.join(parts)
            return joined.strip() if separator == ";" else joined
        seen += 1
    return raw + separator + f"{param.name}={new_value}"


def _multipart_boundary(request: Request) -> str:
    content_type = request.headers.get("Content-Type") or ""
    if "multipart/form-data" not in content_type.lower():
        return ""
    for piece in content_type.split(";"):
        piece = piece.strip()
        if piece.lower().startswith("boundary="):
            return piece[len("boundary="):].strip('"')
    return ""


def _multipart_parts(body: bytes, boundary: str) -> list[bytes]:
    marker = b"--" + boundary.encode("latin-1")
    return [chunk for chunk in body.split(marker)[1:] if chunk.strip() not in (b"", b"--")]


def _part_name(part: bytes) -> str | None:
    head, _, _ = part.partition(b"\r\n\r\n")
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-disposition:"):
            for piece in line.decode("latin-1").split(";"):
                piece = piece.strip()
                if piece.lower().startswith("name="):
                    return piece[len("name="):].strip('"')
    return None


def _part_filename(part: bytes) -> str | None:
    """The filename a part declares, if it declares one."""
    head, _, _ = part.partition(b"\r\n\r\n")
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-disposition:"):
            for piece in line.decode("latin-1").split(";"):
                piece = piece.strip()
                if piece.lower().startswith("filename="):
                    return piece[len("filename="):].strip().strip('"')
    return None


def _part_value(part: bytes) -> bytes:
    _, separator, content = part.partition(b"\r\n\r\n")
    if not separator:
        return b""
    return content[:-2] if content.endswith(b"\r\n") else content


def _multipart_pairs(request: Request) -> list[tuple[Where, str, str, int]]:
    """Every part of a multipart body: its field value, and its filename.

    An upload form hands one of its fields to the application just like a query
    parameter does, and a scanner that only reads `application/x-www-form-urlencoded`
    bodies never sees it. A part carrying a file has a second value worth having:
    the name the file is stored under.
    """
    boundary = _multipart_boundary(request)
    if not boundary or not request.body:
        return []
    out: list[tuple[Where, str, str, int]] = []
    seen: dict[str, int] = {}
    for part in _multipart_parts(request.body, boundary):
        name = _part_name(part)
        if name is None:
            continue
        occurrence = seen.get(name, 0)
        seen[name] = occurrence + 1
        out.append((Where.MULTIPART, name, _part_value(part).decode("latin-1"), occurrence))
        filename = _part_filename(part)
        if filename is not None:
            out.append((Where.MULTIPART_FILENAME, name, filename, occurrence))
    return out


def _replace_part_filename(head: bytes, new_name: str) -> bytes:
    """Rewrite the filename in a part's Content-Disposition, keeping the rest."""
    lines = head.split(b"\r\n")
    for index, line in enumerate(lines):
        if not line.lower().startswith(b"content-disposition:"):
            continue
        pieces = line.decode("latin-1").split(";")
        for position, piece in enumerate(pieces):
            if piece.strip().lower().startswith("filename="):
                pieces[position] = f' filename="{new_name}"'
        lines[index] = ";".join(pieces).encode("latin-1")
    return b"\r\n".join(lines)


def _rewrite_multipart(request: Request, param: Param, new_value: str) -> None:
    """Replace the filename or the content of one part, leaving the rest alone."""
    boundary = _multipart_boundary(request)
    if not boundary:
        return
    marker = b"--" + boundary.encode("latin-1")
    chunks = request.body.split(marker)
    seen = 0
    for index in range(1, len(chunks)):
        part = chunks[index]
        if _part_name(part) != param.name:
            continue
        if seen == param.occurrence:
            head, separator, content = part.partition(b"\r\n\r\n")
            if not separator:
                return
            if param.where is Where.MULTIPART_FILENAME:
                chunks[index] = _replace_part_filename(head, new_value) + separator + content
            else:
                chunks[index] = head + separator + new_value.encode("latin-1") + b"\r\n"
            request.body = marker.join(chunks)
            request.headers.set("Content-Length", str(len(request.body)))
            return
        seen += 1


def _set_json(body: bytes, path: str, value: str) -> bytes:
    """Rebuild the document with one field replaced.

    The shape is preserved - every other field keeps its value - though spacing
    may not survive, which is the price of keeping the document parseable.
    """
    try:
        document = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return body
    if not _assign_json(document, path, value):
        return body
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _assign_json(document: object, path: str, value: str) -> bool:
    tokens = _path_tokens(path)
    if not tokens:
        return False
    node = document
    for token in tokens[:-1]:
        if isinstance(token, int):
            if not isinstance(node, list) or token >= len(node):
                return False
            node = node[token]
        else:
            if not isinstance(node, dict) or token not in node:
                return False
            node = node[token]

    last = tokens[-1]
    if isinstance(last, int):
        if isinstance(node, list) and last < len(node):
            node[last] = value
            return True
        return False
    if isinstance(node, dict) and last in node:
        node[last] = value
        return True
    return False


def _path_tokens(path: str) -> list:
    """`a.b[0].c` -> ["a", "b", 0, "c"]."""
    return [
        int(part[1:-1]) if part.startswith("[") else part
        for part in re.findall(r"[^.\[\]]+|\[\d+\]", path)
    ]


def _pairs(raw: str, where: Where, separator: str) -> list[tuple[Where, str, str, int]]:
    out: list[tuple[Where, str, str, int]] = []
    if not raw:
        return out
    seen: dict[str, int] = {}
    for part in raw.split(separator):
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        if separator == ";":
            name, value = name.strip(), value.strip()
        occurrence = seen.get(name, 0)
        seen[name] = occurrence + 1
        out.append((where, name, value, occurrence))
    return out


def _replace_pair(raw: str, param: Param, new_value: str, new_name: str | None = None) -> str:
    if not raw:
        return f"{new_name or param.name}={new_value}"
    separator = ";" if param.where is Where.COOKIE else "&"
    parts = raw.split(separator)
    seen = 0
    for index, part in enumerate(parts):
        name, sep, _ = part.partition("=")
        if not sep:
            continue
        candidate = name.strip() if separator == ";" else name
        if candidate != param.name:
            continue
        if seen == param.occurrence:
            prefix = " " if separator == ";" else ""
            parts[index] = f"{prefix}{new_name or name}={new_value}"
            return separator.join(parts).strip() if separator == ";" else separator.join(parts)
        seen += 1
    # The parameter moved or vanished since it was discovered; appending keeps
    # the injection meaningful instead of silently testing nothing.
    return raw + separator + f"{new_name or param.name}={new_value}"


def _replace_cookie(header: str, param: Param, new_value: str) -> str:
    return _replace_pair(header, param, new_value)


def _replace_path_segment(url: str, param: Param, new_value: str) -> str:
    base, query, fragment = split_url(url)
    parts = base.split("/")
    for index in range(len(parts) - 1, -1, -1):
        if parts[index] == param.value:
            parts[index] = new_value
            return join_url("/".join(parts), query, fragment)
    return url
