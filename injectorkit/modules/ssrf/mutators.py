"""What a destination can be called.

These are the mutators that belong to the SSRF problem rather than to payload
generation in general: how an address can be spelled, and which names resolve to
an address that a filter was trying to keep out of reach. They live here, next
to the probes that use them, rather than in the core - so the core stays a
framework, and a second module does not have to read this one's tricks to
understand its own.

Registered at import time; the module's `__init__` imports this file.
"""

from __future__ import annotations

import ipaddress
import re

from ...core.mutate import Kind, Mutator, register


def _with_host(rewrite):
    """Apply a rewrite to the host part of a URL, leaving scheme and path alone."""

    pattern = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*://)([^/?#]*)(.*)$", re.S)

    def apply(value: str) -> str:
        match = pattern.match(value)
        if not match:
            return value
        scheme, authority, rest = match.groups()
        userinfo, at, hostport = authority.rpartition("@")
        prefix = f"{userinfo}@" if at else ""
        host, colon, port = hostport.partition(":")
        try:
            address = ipaddress.IPv4Address(host)
        except ValueError:
            return value
        return f"{scheme}{prefix}{rewrite(address)}{colon}{port}{rest}"

    return apply


def _octal(address: ipaddress.IPv4Address) -> str:
    """127.0.0.1 as 0177.0.0.1 - the same address, spelled the way inet_aton reads it."""
    return ".".join(f"0{oct(part)[2:]}" for part in address.packed)


def _short_form(address: str) -> str:
    """127.0.0.1 as 127.1 - one number standing for the lower two octets."""
    parts = address.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{int(parts[2]) << 8 | int(parts[3])}"
    return address


SSRF_MUTATORS: tuple[Mutator, ...] = (
    # -- spelling of an address. A filter that blocks the dotted form has blocked
    #    a spelling, not an address. These are mutually exclusive: two spellings
    #    of the same address cannot be combined into a third that means anything.
    Mutator("host-decimal", _with_host(lambda a: str(int(a))), (Kind.SSRF,), family="host", weight=10),
    Mutator("host-octal", _with_host(_octal), (Kind.SSRF,), family="host", weight=11),
    Mutator("host-hex", _with_host(lambda a: "0x" + a.packed.hex()), (Kind.SSRF,), family="host", weight=12),
    Mutator("host-short", _with_host(lambda a: _short_form(str(a))), (Kind.SSRF,), family="host", weight=13),
    Mutator("host-ipv6-mapped", _with_host(lambda a: f"[::ffff:{a}]"), (Kind.SSRF,), family="host", weight=14),
    Mutator("host-trailing-dot", _with_host(lambda a: f"{a}."), (Kind.SSRF,), family="host", weight=15),
    # -- a name that resolves to the address. A filter that judges the string,
    #    or even one that parses it, sees a domain; the resolver sees the
    #    address inside. This is the spelling a semantic rule set cannot reach
    #    without doing the resolution itself.
    Mutator("host-nipio", _with_host(lambda a: f"{a}.nip.io"), (Kind.SSRF,), family="host-alias", weight=16),
    Mutator("host-sslipio", _with_host(lambda a: f"{a}.sslip.io"), (Kind.SSRF,), family="host-alias", weight=17),
    Mutator("host-nipio-dashed", _with_host(lambda a: f"{str(a).replace('.', '-')}.nip.io"), (Kind.SSRF,), family="host-alias", weight=18),
    # -- authority confusion. What the client connects to and what a filter reads
    #    as the destination are decided by different parts of the string.
    Mutator("authority-at", lambda v: v.replace("://", "://x@", 1), (Kind.SSRF,), family="authority", weight=22),
    Mutator("authority-real-then-at", lambda v: v.replace("://", "://example.com@", 1), (Kind.SSRF,), family="authority", weight=23),
    Mutator("host-whitespace", lambda v: v.replace("://", "://%09", 1), (Kind.SSRF,), family="authority", weight=24),
)

register(*SSRF_MUTATORS)
