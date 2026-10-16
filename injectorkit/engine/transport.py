"""Sending requests, and measuring what came back.

Deliberately thin: one place that turns a Request into a Response plus a
measured duration, so every action in every module is observed the same way and
the blackboard can account for all of the traffic the run produced.
"""

from __future__ import annotations

import email.utils
import random
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Sequence

from ..core.httpmsg import Headers, Request, Response


def _retry_after(headers: Headers) -> float | None:
    """Seconds the target asked to be left alone, in either spelling.

    The header is either a number of seconds or an HTTP date. Both are in the
    wild, and a scan that understands only one of them ignores half the targets
    that bothered to say anything at all.
    """
    raw = (headers.get("Retry-After") or "").strip()
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    return max(0.0, when.timestamp() - time.time())


# What a real browser announces, as parts that have to agree with each other: a
# Firefox token with a Chrome version is not a browser anyone has ever shipped,
# and a target's statistics can tell.
_UA_PLATFORMS = (
    "Windows NT 10.0; Win64; x64",
    "Windows NT 10.0; WOW64",
    "X11; Linux x86_64",
    "Macintosh; Intel Mac OS X 10_15_7",
)
_UA_FAMILIES = (
    (
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36",
        ("120.0.0.0", "124.0.0.0", "126.0.0.0", "128.0.0.0"),
    ),
    (
        "Gecko/20100101 Firefox/{version}",
        ("115.0", "121.0", "125.0", "128.0"),
    ),
    (
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15",
        ("16.6", "17.0", "17.5"),
    ),
)


@dataclass
class TransportOptions:
    """Everything that shapes how a request goes out."""

    timeout: float = 15.0
    insecure: bool = True
    proxy: str | None = None
    follow_redirects: bool = False
    headers: Sequence[tuple[str, str]] = ()
    # What the target sees the tool calling itself. The default is honest: a
    # scan that announces itself leaves a trace its owner can find.
    user_agent: str = "InjectorKit"
    random_user_agent: bool = False
    max_body: int = 4 << 20
    delay: float = 0.0
    # How many times to try again after a connection drops. Only connections: an
    # HTTP status is the server answering, and asking the same question again
    # will not change it. A dropped connection, on the other hand, is not an
    # answer at all, and a scan that treats it as one reports a target as quiet
    # when its network merely hiccuped.
    retries: int = 0


@dataclass
class Transport:
    """A client with no opinion about why a request is being sent."""

    options: TransportOptions = field(default_factory=TransportOptions)

    # Raised when the target asks for it, never lowered. A target that answers
    # 429 is telling the scan to slow down, and a scan that keeps the same pace
    # gets its answers from the limiter rather than from the application - which
    # then reads exactly like a target with nothing to find.
    _pace: float = 0.0

    # How far the pace may be raised before it is worth giving up on the run.
    MAX_PACE = 60.0
    PACE_STEP = 0.5

    def __post_init__(self) -> None:
        handlers: list[urllib.request.BaseHandler] = []
        if not self.options.follow_redirects:
            handlers.append(_NoRedirect())
        if self.options.insecure:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=context))
        if self.options.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.options.proxy, "https": self.options.proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    def send(self, request: Request) -> Response:
        headers = Headers()
        for name, value in request.headers:
            # `add`, not `set`, so that a request which carries the same header
            # twice keeps both here. Note that this is not enough to get the
            # duplication onto the wire: `urllib` holds headers in a dict and
            # `add_header` replaces by name, so the last value wins by the time
            # the request leaves. Duplication needs a transport that writes the
            # message itself, which is why `Where.HEADER` refuses to pollute.
            headers.add(name, value)

        # The configured identity goes on top, with two rules that matter. A
        # cookie is merged rather than replaced: a request may carry its own -
        # a CSRF token, a consent flag - and dropping them would end the very
        # session this exists to keep. Every other header only fills a gap,
        # because a request that already names an identity is more specific
        # than a command-line default, and overriding it would be the one thing
        # that must never happen to an authenticated request.
        for name, value in self.options.headers:
            if not name or not value:
                # A stray empty argument - an unset shell variable, a typo -
                # should not turn into a header on the wire.
                continue
            if name.lower() == "cookie":
                existing = headers.get("Cookie") or ""
                headers.set("Cookie", f"{existing}; {value}" if existing else value)
            elif not headers.get(name):
                headers.set(name, value)

        headers.set("User-Agent", self._user_agent(headers))
        headers.set("Accept", "*/*")
        headers.set("Connection", "close")

        outgoing = urllib.request.Request(
            url=request.url,
            data=request.body or None,
            method=request.method,
        )
        for name, value in headers:
            outgoing.add_header(name, value)
        if request.body:
            outgoing.add_header("Content-Length", str(len(request.body)))

        timeout = request.timeout or self.options.timeout
        # Only a dropped connection is retried. An HTTP status is the server
        # answering, and asking the same question again does not change it; a
        # connection that never opened is not an answer at all, and treating it
        # as one reports a target as quiet when its network merely hiccuped.
        last: Response | None = None
        for attempt in range(self.options.retries + 1):
            if attempt:
                # Room for a dropped connection or a limiter to clear, growing
                # so that a target which is genuinely down is not hammered.
                time.sleep(min(0.25 * 2 ** attempt, 2.0))
            if self.options.delay or self._pace:
                time.sleep(self.options.delay + self._pace)

            started = time.perf_counter()
            try:
                with self._opener.open(outgoing, timeout=timeout) as handle:
                    body = handle.read(self.options.max_body)
                    response = Response(
                        status=handle.status,
                        reason=handle.reason or "",
                        headers=Headers(list(handle.headers.items())),
                        body=body,
                        elapsed=time.perf_counter() - started,
                    )
            except urllib.error.HTTPError as error:
                body = error.read(self.options.max_body) if error.fp else b""
                response = Response(
                    status=error.code,
                    reason=str(error.reason),
                    headers=Headers(list(error.headers.items()) if error.headers else []),
                    body=body,
                    elapsed=time.perf_counter() - started,
                )
            except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError, ValueError, OSError) as error:
                last = Response(
                    error=_short_error(error),
                    elapsed=time.perf_counter() - started,
                )
                continue

            wait = self._asked_to_wait(response)
            if wait is not None and attempt < self.options.retries:
                self._pace = min(self.MAX_PACE, self._pace + self.PACE_STEP)
                time.sleep(min(wait, self.MAX_PACE))
                continue
            return response
        return last or Response(error="the request was never attempted")

    @staticmethod
    def _asked_to_wait(response: Response) -> float | None:
        """How long the target asked to be left alone, if it did.

        429 always counts, and 503 counts when it names a wait: a 503 without one
        is an ordinary server error and retrying it would be guessing. The header
        carries either a number of seconds or an HTTP date, and both spellings
        are in the wild.
        """
        if response.status == 429:
            return _retry_after(response.headers) or 1.0
        if response.status == 503:
            return _retry_after(response.headers)
        return None

    def _user_agent(self, headers: Headers) -> str:
        """What to claim to be.

        A User-Agent the request itself carries wins - that is what `-H` and a
        pasted capture mean. Otherwise `--random-ua` composes a fresh plausible
        one per request, and failing that the configured name is used.
        """
        explicit = headers.get("User-Agent")
        if explicit:
            return explicit
        if self.options.random_user_agent:
            return self._compose_user_agent()
        return self.options.user_agent

    @staticmethod
    def _compose_user_agent() -> str:
        """Build one from parts rather than pick from a list.

        A short fixed list is itself a fingerprint, and it goes stale; the parts
        a real browser announces are what a target's statistics actually see.
        """
        template, versions = random.choice(_UA_FAMILIES)
        platform = random.choice(_UA_PLATFORMS)
        return f"Mozilla/5.0 ({platform}) " + template.format(version=random.choice(versions))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is a response worth reading, not something to follow blindly."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _short_error(error: BaseException) -> str:
    text = str(error)
    if isinstance(error, urllib.error.URLError) and getattr(error, "reason", None):
        text = str(error.reason)
    return text[:200]
