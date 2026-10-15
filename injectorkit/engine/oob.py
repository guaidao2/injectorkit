"""Out-of-band interactions: proof that arrives on another connection.

A blind SSRF, a blind command injection, a blind XXE leaves no error, no change
in the page and no delay. The only evidence is a connection the *target* makes
to an address we chose. So the engine plants a unique callback name in the
payload and treats the call home as proof.

The listener is optional on purpose. Where a target cannot reach back, the
out-of-band actions skip themselves rather than plant a payload that can never
report. The token is what ties a callback to the exact action that planted it.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


@dataclass
class Interaction:
    """One callback that reached the listener."""

    token: str
    label: str
    protocol: str
    remote_addr: str
    detail: str
    at: float = field(default_factory=time.time)
    # The whole record, when the backend gives one. Attribution needs it: a
    # callback name lives in the Host header of an HTTP request, not in the
    # request line that a reader cares about.
    raw: str = ""

    def describe(self) -> str:
        return f"{self.protocol} from {self.remote_addr}: {self.detail} (token {self.token}, {self.label})"


class OOBListener:
    """An HTTP callback listener that hands out unique names."""

    def __init__(
        self,
        bind: str = "0.0.0.0",
        port: int = 8081,
        public_host: str | None = None,
        timeout: float = 6.0,
    ) -> None:
        self.bind = bind
        self.port = port
        self.public_host = public_host or bind
        self.timeout = timeout
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._issued: dict[str, str] = {}
        self._seen: dict[str, list[Interaction]] = {}
        # Tokens that answer with a redirect instead of a 200. What an
        # application follows is chosen by whoever answered the first hop, and
        # this is where the listener becomes that whoever.
        self._redirects: dict[str, str] = {}

    # ---------------------------------------------------------------- control

    def start(self) -> "OOBListener":
        if self._server is not None:
            return self
        server = ThreadingHTTPServer((self.bind, self.port), _Handler)
        server.registry = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> "OOBListener":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def running(self) -> bool:
        return self._server is not None

    # ----------------------------------------------------------------- tokens

    def new_url(self, label: str) -> tuple[str, str]:
        """Mint a callback URL and the token that identifies it."""
        token = secrets.token_hex(4)
        with self._lock:
            self._issued[token] = label
        return f"http://{self.public_host}:{self.port}/{token}", token

    def issue(self, token: str, label: str) -> None:
        with self._lock:
            self._issued[token] = label

    def new_redirect(self, target: str, label: str = "") -> tuple[str, str]:
        """A URL here that answers 302 to `target`.

        This is the first hop of a chain the target walks itself: it asks us for
        a page, we name the destination, and the request that matters is the one
        the target makes after the redirect - which it makes from its own
        network, to somewhere the caller could not name directly.
        """
        token = secrets.token_hex(4)
        with self._lock:
            self._redirects[token] = target
            self._issued[token] = label or "redirect"
        return f"http://{self.public_host}:{self.port}/redirect/{token}", token

    def redirect_target(self, token: str) -> str | None:
        with self._lock:
            return self._redirects.get(token)

    def labels(self) -> dict[str, str]:
        with self._lock:
            return dict(self._issued)

    # ------------------------------------------------------------- recording

    def record(self, token: str, protocol: str, remote_addr: str, detail: str) -> None:
        interaction = Interaction(
            token=token,
            label=self.labels().get(token, "unknown"),
            protocol=protocol,
            remote_addr=remote_addr,
            detail=detail,
        )
        with self._lock:
            self._seen.setdefault(token, []).append(interaction)

    def poll(self, token: str) -> list[Interaction]:
        """Take the interactions for a token; polling clears them."""
        with self._lock:
            return self._seen.pop(token, [])

    def interactions(self) -> list[Interaction]:
        with self._lock:
            return [item for items in self._seen.values() for item in items]

    def wait(self, token: str, timeout: float | None = None, interval: float = 0.25) -> list[Interaction]:
        """Poll until the token is interacted with or the budget runs out."""
        deadline = time.time() + (timeout if timeout is not None else self.timeout)
        while time.time() < deadline:
            found = self.poll(token)
            if found:
                return found
            time.sleep(interval)
        return self.poll(token)


class _Handler(BaseHTTPRequestHandler):
    """Records every request and answers 200, whatever it asked for."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        self._record()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(min(length, 1 << 16))
        self._record()

    def do_HEAD(self) -> None:  # noqa: N802
        self._record()

    def _record(self) -> None:
        listener: OOBListener = self.server.registry  # type: ignore[attr-defined]
        path = urlsplit(self.path).path

        # A redirect first: the caller asked for a page, and the page says where
        # to go next. What comes after is the request that proves the target
        # walks the chain on its own.
        if path.startswith("/redirect/"):
            token = path.rsplit("/", 1)[-1]
            target = listener.redirect_target(token)
            if target:
                listener.record(token, "http", self.client_address[0], f"302 -> {target}")
                self.send_response(302)
                self.send_header("Location", target)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

        token = _match_token(listener.labels(), self.path, self.headers.get("Host", ""))
        detail = f"{self.command} {self.path}"
        if token:
            listener.record(token, "http", self.client_address[0], detail)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Silence: callbacks are reported through the engine, not stderr."""


def _match_token(issued: dict[str, str], path: str, host: str) -> str:
    """Find which callback name this request carries.

    A target may put the planted URL in the path, in a query parameter, or let
    the name resolve as a subdomain - all three are checked, because an SSRF
    that tucks the callback into a parameter is exactly the normal case.
    """
    if not issued:
        return ""
    parts = urlsplit(path)
    candidates = [segment for segment in parts.path.split("/") if segment]
    candidates.extend(host.split(":")[0].split("."))
    for values in parse_qs(parts.query).values():
        candidates.extend(values)
    candidates.append(parts.query)
    for candidate in candidates:
        if candidate in issued:
            return candidate
    for candidate in candidates:
        for token in issued:
            if token and token in candidate:
                return token
    return ""
