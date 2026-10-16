"""A gadget's side effect, read back over HTTP.

Running a gadget and being unable to tell whether it ran is the same as not
running it. The strongest proof available is a side effect the target will serve
back: a gadget that writes a file into the web root has left something the next
request can fetch, and the answer to that request is not a guess.

This is what makes the phar chain verifiable rather than theoretical. The archive
is inert, the deserialization is invisible, and the only thing that says any of
it happened is a file that was not there before - carrying a string this run
invented and nothing on the target could have produced by accident.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from ..core.httpmsg import Request


@dataclass
class SideEffect:
    """A file a gadget was asked to leave, and whether it turned up."""

    marker: str
    path: str
    url: str = ""
    found: str = ""

    @property
    def proved(self) -> bool:
        return bool(self.found)

    def describe(self) -> str:
        if self.proved:
            return (
                f"the gadget ran: {self.url} serves a file that was not there before, "
                f"carrying {self.marker}"
            )
        return f"nothing was served from {self.url or self.path}"


def make_marker() -> str:
    """Something the target could not have produced on its own."""
    return "ik" + secrets.token_hex(8)


def probe_side_effect(ctx, url: str, marker: str, attempts: int = 3) -> SideEffect:
    """Ask the target for the file the gadget was told to write.

    Retried a little: the write happens on the request that triggered the gadget,
    and a web server answering the next request while still finishing the last
    one is ordinary. Giving up on the first read would report a working chain as
    broken, which is the same mistake the log-poisoning check made.

    `attempts` is deliberately small. A gadget that has not written by the third
    look has not written.
    """
    effect = SideEffect(marker=marker, path="", url=url)
    for attempt in range(max(1, attempts)):
        exchange = ctx.send(Request.from_url(url), action="exploit.phar.verify")
        body = exchange.response.text
        if marker in body:
            effect.found = body[:400]
            return effect
        if attempt + 1 < attempts:
            time.sleep(0.5)
    return effect


def was_there_before(ctx, url: str) -> bool:
    """Whether the target already serves something at that path.

    Asked before the gadget runs, because a file that was already there is not
    evidence of anything. Cheap, and the difference between "the write happened"
    and "this path was always going to answer".
    """
    exchange = ctx.send(Request.from_url(url), action="exploit.phar.before")
    return exchange.response.status == 200
