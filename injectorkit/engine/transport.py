"""Sending requests, and measuring what came back.

Deliberately thin: one place that turns a Request into a Response plus a
measured duration, so every action in every module is observed the same way and
the blackboard can account for all of the traffic the run produced.
"""

from __future__ import annotations

import random
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Sequence

from ..core.httpmsg import Headers, Request, Response

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


@dataclass
class Transport:
    """A client with no opinion about why a request is being sent."""

    options: TransportOptions = field(default_factory=TransportOptions)

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
        headers = Headers(self.options.headers)
        for name, value in request.headers:
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

        if self.options.delay:
            time.sleep(self.options.delay)

        timeout = request.timeout or self.options.timeout
        started = time.perf_counter()
        try:
            with self._opener.open(outgoing, timeout=timeout) as handle:
                body = handle.read(self.options.max_body)
                return Response(
                    status=handle.status,
                    reason=handle.reason or "",
                    headers=Headers(list(handle.headers.items())),
                    body=body,
                    elapsed=time.perf_counter() - started,
                )
        except urllib.error.HTTPError as error:
            body = error.read(self.options.max_body) if error.fp else b""
            return Response(
                status=error.code,
                reason=str(error.reason),
                headers=Headers(list(error.headers.items()) if error.headers else []),
                body=body,
                elapsed=time.perf_counter() - started,
            )
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError, ValueError, OSError) as error:
            return Response(
                error=_short_error(error),
                elapsed=time.perf_counter() - started,
            )

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
