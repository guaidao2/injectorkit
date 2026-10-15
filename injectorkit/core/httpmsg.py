"""The request model.

Everything the engine touches is a Request: what the user typed on the command
line, what a raw capture parsed into, what an action rewrote, what a module
stored as evidence. One model means an action can be replayed byte for byte and
a finding can carry the exact bytes that produced it.

Two properties matter and are easy to lose by accident:

* headers are an ordered, case-preserving list, never a dict. A dict sorts and
  collapses, and the request that arrives at a target is then not the request
  that was tested.
* parameter rewriting happens on the raw text of the request, not on a parsed
  structure. Every other parameter keeps its original encoding, so a reproducer
  gets the same bytes we sent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Sequence

CRLF = b"\r\n"


class Headers:
    """An ordered, case-preserving header list.

    Lookup and replacement are case-insensitive, as HTTP requires; storage keeps
    the original spelling, because a client's header casing is part of what a
    target's fingerprinting may look at.
    """

    __slots__ = ("_items",)

    def __init__(self, pairs: Sequence[tuple[str, str]] | None = None) -> None:
        self._items: list[tuple[str, str]] = list(pairs or [])

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, name: str) -> bool:
        return self.get(name) is not None

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def names(self) -> list[str]:
        return [name for name, _ in self._items]

    def get(self, name: str, default: str | None = None) -> str | None:
        lowered = name.lower()
        for existing, value in self._items:
            if existing.lower() == lowered:
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [value for existing, value in self._items if existing.lower() == lowered]

    def set(self, name: str, value: str) -> None:
        """Replace the first occurrence in place, keeping its position."""
        lowered = name.lower()
        for index, (existing, _) in enumerate(self._items):
            if existing.lower() == lowered:
                self._items[index] = (existing, value)
                return
        self._items.append((name, value))

    def add(self, name: str, value: str) -> None:
        self._items.append((name, value))

    def delete(self, name: str) -> None:
        lowered = name.lower()
        self._items = [
            (existing, value)
            for existing, value in self._items
            if existing.lower() != lowered
        ]

    def clone(self) -> "Headers":
        return Headers(self._items)

    def to_bytes(self) -> bytes:
        return CRLF.join(
            f"{name}: {value}".encode("latin-1", "replace")
            for name, value in self._items
        )


@dataclass
class Request:
    """One HTTP request, stored as the bytes that would go on the wire."""

    method: str = "GET"
    url: str = ""
    headers: Headers = field(default_factory=Headers)
    body: bytes = b""
    # Engine bookkeeping, never serialised onto the wire.
    timeout: float | None = None
    label: str = ""

    def clone(self) -> "Request":
        return Request(
            method=self.method,
            url=self.url,
            headers=self.headers.clone(),
            body=bytes(self.body),
            timeout=self.timeout,
            label=self.label,
        )

    # ---------------------------------------------------------------- parsing

    @classmethod
    def parse(cls, data: bytes | str) -> "Request":
        """Parse a raw HTTP request as saved by a proxy or an intercepting tool.

        Only the request line, the headers and the body are read. A request
        target in absolute form (``GET http://host/path HTTP/1.1``) is kept as
        written in ``url``; the engine resolves it when sending.

        Header lines are normalised to LF while parsing, but the body is left
        byte for byte: a multipart boundary is a CRLF sequence and a binary body
        is not text, so normalising either one silently corrupts the request
        that gets sent.
        """
        if isinstance(data, str):
            data = data.encode("latin-1", "replace")

        raw_head, separator, body = data.partition(b"\r\n\r\n")
        if not separator:
            raw_head, _, body = data.partition(b"\n\n")
        head = raw_head.replace(b"\r\n", b"\n")

        lines = head.split(b"\n")
        if not lines or not lines[0].strip():
            raise ValueError("raw request has no request line")
        parts = lines[0].decode("latin-1").split(" ")
        if len(parts) < 2:
            raise ValueError("malformed request line: " + lines[0].decode("latin-1"))
        method, target = parts[0], parts[1]
        headers = Headers()
        for line in lines[1:]:
            if not line.strip():
                continue
            name, sep, value = line.decode("latin-1").partition(":")
            if not sep:
                continue
            headers.add(name.strip(), value.strip())
        return cls(method=method.upper(), url=target, headers=headers, body=body)

    @classmethod
    def from_url(
        cls,
        url: str,
        method: str = "GET",
        headers: Sequence[tuple[str, str]] | None = None,
        body: bytes | str | None = None,
    ) -> "Request":
        request = cls(method=method.upper(), url=url, headers=Headers(headers))
        if isinstance(body, str):
            body = body.encode()
        request.body = body or b""
        if request.body and not request.headers.get("Content-Type"):
            request.headers.set("Content-Type", "application/x-www-form-urlencoded")
        if request.body:
            request.headers.set("Content-Length", str(len(request.body)))
        return request

    # ------------------------------------------------------------ serialising

    def to_bytes(self) -> bytes:
        """Render the request as it would be written to the wire."""
        head = [f"{self.method} {self.url} HTTP/1.1".encode("latin-1", "replace")]
        head.extend(self.headers.to_bytes().split(CRLF) if len(self.headers) else [])
        return CRLF.join(head) + CRLF + CRLF + self.body

    def describe(self) -> str:
        """A one-line label for logs and evidence."""
        label = f"{self.method} {self.url}"
        return f"{label} [{self.label}]" if self.label else label

    # -------------------------------------------------------------- utilities

    def host(self) -> str:
        from urllib.parse import urlsplit

        netloc = urlsplit(self.url).netloc or _netloc_from_absolute(self.url)
        return netloc.split("@")[-1].split(":")[0].lower()


def parse_headers(values) -> list[tuple[str, str]]:
    """Turn repeated `-H "Name: Value"` flags into header pairs.

    The flag is one string with a colon in it, and a header list is pairs; the
    conversion has to happen somewhere, and doing it next to the header model is
    what keeps every caller from rediscovering it.
    """
    out: list[tuple[str, str]] = []
    for item in values or ():
        name, separator, value = str(item).partition(":")
        if not separator:
            continue
        out.append((name.strip(), value.strip()))
    return out


def _netloc_from_absolute(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).netloc


@dataclass
class Response:
    """One HTTP response, kept with the timing the engine measured for it."""

    status: int = 0
    reason: str = ""
    headers: Headers = field(default_factory=Headers)
    body: bytes = b""
    elapsed: float = 0.0
    error: str = ""

    @property
    def text(self) -> str:
        """Body decoded for matching. Latin-1 never fails and never loses a byte."""
        return self.body.decode("latin-1", "replace")

    def header(self, name: str) -> str:
        return self.headers.get(name, "") or ""

    @property
    def ok(self) -> bool:
        return not self.error and 0 < self.status < 600


@dataclass
class Exchange:
    """A request, its response, and the action that produced them."""

    request: Request
    response: Response
    action: str = ""

    def render(self) -> str:
        if self.response.error:
            head = f"[{self.action}] {self.request.describe()} -> error: {self.response.error}"
        else:
            head = (
                f"[{self.action}] {self.request.describe()} -> "
                f"{self.response.status} ({len(self.response.body)} bytes, "
                f"{self.response.elapsed * 1000:.0f} ms)"
            )
        return head
