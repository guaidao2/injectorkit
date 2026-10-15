#!/usr/bin/env python3
"""A signature WAF in front of the lab application.

    python3 waf.py 8081

Sits between the caller and /opt/injectorkit-lab/www and refuses requests whose
query carries a payload a signature is supposed to catch. It is deliberately
naive in the way real signature filters are naive: it matches literals in the
request as it arrives, before any decoding the application will do.

What it is for: proving whether the engine notices a refusal, climbs its
mutation ladder, and gets through - or finds that no spelling works and says so
instead of reporting nothing.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import sys
import unicodedata
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

UPSTREAM = "http://127.0.0.1:8080"

# Profile A knows the dotted form and the usual scheme literals. Address
# spellings walk straight past it.
PROFILE_A = (
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "127.0.0.1",
    "localhost",
    "gopher://",
    "dict://",
    "file://",
    "php://",
    "expect://",
    "phar://",
    "0x7f",
)

# Profile B is the same idea, one step further along: it knows the dotted form
# *and* the obvious ways of writing an address without dots. It is here to test
# the thing a cross-target memory can get wrong - a prior learned against A
# ("decimal addresses work") is worth nothing here, and if the engine still
# spends its budget on it first, that is negative transfer made visible.
PROFILE_B = (
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "127.0.0.1",
    "localhost",
    "2852039166",  # 169.254.169.254 as one number
    "2130706433",  # 127.0.0.1 as one number
    "0x",          # hexadecimal spelling
    "0177",        # octal spelling
    "gopher://",
    "dict://",
    "file://",
    "php://",
)

# Profile C does not search for bad strings at all: it parses the destination
# out of the request and asks what the address means. Dotted, short, integer,
# octal, hexadecimal and IPv4-mapped spellings all collapse to the same answer,
# which is the point - a filter that understands addresses has no spelling gap
# left to walk through, and the engine should report a closed surface instead of
# a clean target.
PROFILE_C_PATTERNS = ()

# Profile D is a different idea entirely: it does not look for bad input, it
# requires good input. The only host the application may fetch is the
# application itself, so nothing on the blocklists matters any more - the way
# through is a redirect the target follows on its own behalf.
WHITELIST_HOSTS = ("127.0.0.1",)

PROFILES = {
    "a": {"type": "blocklist", "signatures": PROFILE_A},
    "b": {"type": "blocklist", "signatures": PROFILE_B},
    "c": {"type": "semantic"},
    "d": {"type": "whitelist", "allowed": WHITELIST_HOSTS},
    # Judges the first value of each parameter and ignores the rest. A common
    # shape: the filter takes `query["x"]`, an application-language parser takes
    # the last one, and the two never look at the same string.
    "e": {"type": "blocklist", "signatures": PROFILE_A, "hpp": "first"},
}

REFUSAL = b"Request blocked: the parameter you supplied is not allowed (lab-waf)"

DANGEROUS_SCHEME = re.compile(r"(gopher|dict|file|php|phar|expect|data):", re.IGNORECASE)


def _internal_host(host: str) -> bool:
    """Whether a host names somewhere inside, whatever spelling it uses.

    This is what a rule set that keeps up looks like: it does not search the
    text for known-bad strings, it parses the destination and asks what the
    address means. Every dotted, short, integer, octal, hexadecimal and
    IPv4-mapped spelling collapses to the same judgement.
    """
    if not host:
        return False
    # A trailing dot is how an absolute name is written, and a resolver ignores
    # it - so a filter that does not strip it is looking at a different string
    # from the one the client will resolve.
    host = host.strip("[]").rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    if host in ("metadata.google.internal", "100.100.100.200"):
        return True

    address = None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            # inet_aton accepts a.b.c.d, a.b.c, a.b and one integer, in decimal,
            # octal or hexadecimal - the same spellings an HTTP client accepts.
            address = ipaddress.ip_address(socket.inet_aton(host))
        except (OSError, ValueError):
            return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
    )


def _semantic_block(path: str) -> bool:
    """Judge every URL the request carries, and the schemes it names.

    The judgement happens on the fully decoded form, which is what a rule set
    that keeps up does - decoding once leaves a double-encoded payload looking
    like an encoded string, and letting it through on that basis is the classic
    way a filter is walked past.
    """
    raw = _normalise(path)
    if DANGEROUS_SCHEME.search(raw):
        return True
    for value in _parameter_values(raw):
        if _internal_host(urlsplit(value).hostname or ""):
            return True
    return False


def _parameter_values(path: str, mode: str = "") -> list[str]:
    """Every value of every parameter, or only the first when asked.

    `mode == "first"` reproduces a filter that reads one value per name and
    stops: it never sees a second occurrence, while the application reading the
    same request may take the last one.
    """
    query = parse_qs(urlsplit(path).query)
    if mode == "first":
        return [values[0] for values in query.values() if values]
    return [value for values in query.values() for value in values]


def _normalise(path: str) -> str:
    """What a strict rule set does before matching.

    Encoding is undone until it stops changing anything, Unicode is folded to
    its compatibility form, and comments and whitespace are dropped - the
    transformations a signature that keeps up with evasions has to apply.
    """
    text = unquote(path)
    for _ in range(4):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    text = unicodedata.normalize("NFKC", text)
    for token in ("/**/", "/*!*/", " ", "\t", "\n", "\r", "\\"):
        text = text.replace(token, "")
    return text.lower()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def _handle(self, method: str) -> None:
        if self._blocked(self.path):
            self._refuse()
            return
        self._forward(method)

    def _blocked(self, path: str) -> bool:
        profile = self.server.profile  # type: ignore[attr-defined]
        if profile["type"] == "whitelist":
            return not self._allowed(path, profile["allowed"])
        if profile["type"] == "semantic":
            return _semantic_block(path)
        raw = _normalise(path) if profile.get("normalise") else unquote(path).lower()
        if "patterns" in profile:
            return any(re.search(pattern, raw) for pattern in profile["patterns"])
        if profile.get("hpp") == "first":
            for value in _parameter_values(raw, "first"):
                if any(signature in value for signature in profile["signatures"]):
                    return True
            return False
        return any(signature in raw for signature in profile["signatures"])

    @staticmethod
    def _allowed(path: str, allowed: tuple[str, ...]) -> bool:
        """A whitelist reads the destination out of the parameter and judges it."""
        query = parse_qs(urlsplit(path).query)
        for values in query.values():
            for value in values:
                host = urlsplit(value).hostname or value.split("/", 1)[0].split(":", 1)[0]
                if host and host.lower() not in allowed:
                    return False
        return True

    def _refuse(self) -> None:
        self.send_response(403)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Server", "lab-waf")
        self.send_header("Content-Length", str(len(REFUSAL)))
        self.end_headers()
        self.wfile.write(REFUSAL)

    def _forward(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None

        request = urllib.request.Request(UPSTREAM + self.path, data=body, method=method)
        for name, value in self.headers.items():
            if name.lower() in ("host", "connection", "content-length"):
                continue
            request.add_header(name, value)

        try:
            with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
                payload = response.read()
                self.send_response(response.status)
                for name, value in response.headers.items():
                    if name.lower() in ("connection", "transfer-encoding", "content-length"):
                        continue
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except urllib.error.HTTPError as error:
            payload = error.read()
            self.send_response(error.code)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception as error:  # noqa: BLE001
            message = f"waf upstream error: {error}".encode()
            self.send_response(502)
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            self.wfile.write(message)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


def main() -> int:
    profile = "a"
    port = 8081
    args = sys.argv[1:]
    for index, value in enumerate(args):
        if value == "--profile" and index + 1 < len(args):
            profile = args[index + 1]
        elif value.isdigit():
            port = int(value)
    if profile not in PROFILES:
        print(f"unknown profile {profile!r}; choose from {', '.join(PROFILES)}", file=sys.stderr)
        return 2

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.profile = PROFILES[profile]  # type: ignore[attr-defined]
    spec = PROFILES[profile]
    kind = spec["type"]
    count = len(spec.get("patterns") or spec.get("signatures") or spec.get("allowed") or ())
    if kind == "semantic":
        count = 2  # every address spelling, and the dangerous schemes
    print(f"lab-waf (profile {profile}: {kind}, {count} rules) on :{port} -> {UPSTREAM}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
