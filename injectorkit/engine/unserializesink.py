"""Finding the parameter that reaches `unserialize()`.

A serialized blob is not a file and does not go through a loader: the value
itself is handed to `unserialize()`, which instantiates whatever the string says.
That call is the entire sink, and finding it is finding a call site - the same
question the phar chain asks, answered a different way.

PHP answers it plainly. Give `unserialize()` a string that is not a serialized
value and it says so, naming itself:

    unserialize(): Error at offset 8 of 9 bytes

Like `Cannot create phar`, that sentence is proof the value reached the function
rather than a symptom of something nearby. A parameter that merely gets echoed
back, or looked up, or stored, says nothing of the kind.

Two shapes are tried, because a value can reach the call in either: one that is
plainly not serialized, and one that starts like a serialized value and is
truncated. The second is worth sending even when the first gets a plain page,
because an application that validates the prefix before calling will refuse the
first and hand the second straight through.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

# PHP's own words when the value is not a serialized blob. Case is folded before
# matching because the message's spelling has changed across versions.
UNSERIALIZE_ERRORS = (
    "unserialize()",
    "error at offset",
    "unserialize(): error",
    "unserialization",
)

# Plainly not serialized, then shaped like one and cut off. The second is what
# gets past a length or prefix check that rejects obvious rubbish.
PROBES: tuple[str, ...] = (
    "ik-probe-not-serialized",
    'a:1:{i:0;s:4:"ik";',
    'O:8:"stdClass":1:{s:1:"a";s:1:"b";',
)


@dataclass
class UnserializeSink:
    """A parameter whose value is handed to `unserialize()`."""

    param: str = ""
    payload: str = ""
    evidence: str = ""
    confirmed: bool = False

    def describe(self) -> str:
        if not self.confirmed:
            return ""
        return (
            f"{self.param} is handed to unserialize(): sending a value that is not a "
            f"serialized blob makes PHP say so ({self.evidence})"
        )


def looks_like_unserialize_error(body: str) -> str:
    """PHP's complaint about a value that reached `unserialize()`."""
    if not body:
        return ""
    lowered = body.lower()
    if "unserialize" not in lowered:
        return ""
    for marker in UNSERIALIZE_ERRORS:
        if marker in lowered:
            index = lowered.find(marker)
            line = body[max(0, index - 40) : index + 120].strip().splitlines()[0]
            return line.strip()
    return ""


def junk_survived(body: str, marker: str, junk: str) -> bool:
    """Whether the application handed the value back untouched.

    `unserialize` consumes what the length prefix declares and returns that,
    leaving anything after it unread - so `s:8:"ik-probe";JUNKJUNK` comes back as
    `ik-probe`, with the junk gone. An application that merely echoes the
    parameter back returns the junk along with it.

    The marker alone proves nothing, since the raw value contains it too. It is
    the *absence* of the trailing junk, next to the presence of the marker, that
    cannot happen without the value having been through the function.
    """
    if not body:
        return False
    return marker in body and junk not in body


def probe_unserialize_sink(ctx, param) -> UnserializeSink:
    """Find out whether this parameter reaches `unserialize()`.

    Two independent answers, because neither is always available. PHP's own
    error is the plainest evidence there is, and it is what a development or CTF
    deployment gives you - but a production one sets `display_errors` off and
    then the error is generated and thrown away. The reflection test needs no
    error at all and works whenever the application shows the value back, which
    is most of the time it shows anything.
    """
    from .inject import inject

    # The error first: it is one request and says the most.
    for payload in PROBES:
        _, exchange = inject(ctx, param, payload, "probe.unserialize-sink")
        if exchange.response.error:
            continue
        evidence = looks_like_unserialize_error(exchange.response.text)
        if evidence:
            return UnserializeSink(
                param=param.key(), payload=payload, evidence=evidence[:200], confirmed=True
            )

    # Then reflection: a valid value with junk after it, which the function
    # drops. The marker is random so the raw value cannot contain it twice, and
    # the junk is random so nothing on the page can match it by accident.
    marker = "ik" + secrets.token_hex(6)
    junk = "IKTAIL" + secrets.token_hex(6)
    payload = f's:{len(marker)}:"{marker}";{junk}'
    _, exchange = inject(ctx, param, payload, "probe.unserialize-sink")
    if exchange.response.error:
        return UnserializeSink()
    body = exchange.response.text
    if junk_survived(body, marker, junk):
        return UnserializeSink(
            param=param.key(),
            payload=payload,
            evidence=(
                f"the value came back as {marker} with the trailing {junk} dropped, "
                "which only the function's own parsing does"
            ),
            confirmed=True,
        )
    return UnserializeSink()
