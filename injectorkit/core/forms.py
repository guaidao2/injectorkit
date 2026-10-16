"""The forms a page declares, turned into the requests a browser would send.

A single URL only reaches the parameters that are in the URL. Login pages,
search boxes and upload widgets put theirs in a form body instead, and a tool
that only reads the address tests none of them. Reading the page's own form
declarations is what closes that gap.

The parser is the standard library's; a page is not a document that has to be
perfect, so anything unparseable simply yields no forms rather than an error.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin

from .httpmsg import Request

# Input types that carry no value worth injecting.
_SKIP_TYPES = {"submit", "button", "reset", "file", "image", "checkbox", "radio"}


@dataclass
class Field:
    name: str
    value: str = ""
    kind: str = "text"


@dataclass
class Form:
    action: str = ""
    method: str = "GET"
    enctype: str = ""
    fields: list[Field] = field(default_factory=list)

    def describe(self) -> str:
        names = ", ".join(field.name for field in self.fields) or "(no fields)"
        return f"{self.method} {self.action or '(this page)'} [{names}]"


class _Parser(HTMLParser):
    """Collects form declarations, ignoring everything else."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[Form] = []
        self._current: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        if tag == "form":
            self._current = Form(
                action=values.get("action", ""),
                method=(values.get("method") or "GET").upper(),
                enctype=(values.get("enctype") or "").lower(),
            )
            return
        if self._current is None or tag not in ("input", "textarea", "select"):
            return

        name = values.get("name")
        if not name:
            return
        kind = (values.get("type") or tag).lower()
        if kind in _SKIP_TYPES:
            return
        self._current.fields.append(Field(name=name, value=values.get("value", ""), kind=kind))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def parse_forms(document: str, base_url: str) -> list[Form]:
    """Every form the document declares, with actions resolved to absolute URLs."""
    parser = _Parser()
    try:
        parser.feed(document)
    except Exception:  # a malformed page is not an error, it just has fewer forms
        pass
    if parser._current is not None:  # a form left open at the end still counts
        parser.forms.append(parser._current)

    for form in parser.forms:
        form.action = urljoin(base_url, form.action) if form.action else base_url
    return parser.forms


def form_request(form: Form, base_url: str) -> Request:
    """The request a browser would send when this form is submitted.

    GET puts the fields in the query, POST puts them in the body, and a
    multipart form gets a real multipart body with a fresh boundary - which is
    the only way the fields behind an upload widget are reachable at all.
    """
    action = urljoin(base_url, form.action) if form.action else base_url
    pairs = [(f.name, f.value) for f in form.fields]

    if form.method == "GET":
        separator = "&" if "?" in action else "?"
        return Request.from_url(f"{action}{separator}{urlencode(pairs)}", method="GET")

    if "multipart/form-data" in form.enctype:
        boundary = "----ikform" + secrets.token_hex(8)
        return Request.from_url(
            action,
            method="POST",
            headers=[("Content-Type", f"multipart/form-data; boundary={boundary}")],
            body=encode_multipart(pairs, boundary),
        )

    return Request.from_url(action, method="POST", body=urlencode(pairs))


@dataclass
class FilePart:
    """One file in a multipart body: the field it goes in, and what it is called."""

    field: str
    filename: str
    content: bytes
    content_type: str = "application/octet-stream"


def encode_multipart(
    pairs: list[tuple[str, str]],
    boundary: str,
    files: list[FilePart] | None = None,
) -> bytes:
    """A multipart body, with CRLF where the format says CRLF.

    A file part is not a field part with a long value. It carries a `filename`,
    and an empty `Content-Type` where a field has none - the two differences that
    decide whether a server treats it as an upload or as a string, and a body
    that gets them wrong is answered by a form parser that simply ignores it.
    """
    lines: list[bytes] = []
    for name, value in pairs:
        lines.append(f"--{boundary}".encode())
        lines.append(f'Content-Disposition: form-data; name="{name}"'.encode())
        lines.append(b"")
        lines.append(str(value).encode("utf-8"))

    for part in files or []:
        lines.append(f"--{boundary}".encode())
        lines.append(
            f'Content-Disposition: form-data; name="{part.field}"; '
            f'filename="{part.filename}"'.encode()
        )
        lines.append(f"Content-Type: {part.content_type}".encode())
        lines.append(b"")
        lines.append(part.content)

    lines.append(f"--{boundary}--".encode())
    lines.append(b"")
    return b"\r\n".join(lines)
