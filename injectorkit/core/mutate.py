"""Action generation: a payload is derived, never stored.

The problem this solves: a tool that ships fixed strings is refused by the first
signature that knows them, and its coverage against a filtering target is close
to zero. So a payload is a *seed* - a small expression that is semantically
correct - plus a set of *mutators* that keep its meaning while changing its
bytes.

Variants are ordered by generation: generation 0 is the seed as written,
generation 1 applies one mutator, generation 2 two, and so on. Mutators in the
same family are never combined (three ways of hiding a space produce a payload
that is none of them). A mutator whose output is already in transport form is
not encoded again.

In a scanner this ladder is climbed when a response looks like a refusal. Here
the engine climbs it when the filter profile says the value was rewritten or
dropped, and remembers the generation that passes so the next action starts
there.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable
from urllib.parse import quote


class Kind(str, Enum):
    """A class of vulnerability, which decides which mutators apply."""

    SSRF = "ssrf"
    PROTOCOL = "protocol"
    TRAVERSAL = "traversal"
    COMMAND = "command"
    DESERIALIZATION = "deserialization"
    GENERIC = "generic"


@dataclass(frozen=True)
class Mutator:
    """A meaning-preserving rewrite of a payload string."""

    name: str
    apply: Callable[[str], str]
    kinds: tuple[Kind, ...] = ()
    excludes: tuple[Kind, ...] = ()
    family: str = ""
    weight: int = 0
    produces_encoded: bool = False

    def matches(self, kind: Kind) -> bool:
        if kind in self.excludes:
            return False
        if not self.kinds:
            return True
        return kind in self.kinds


@dataclass(frozen=True)
class Variant:
    """One spelling of a seed, and what produced it."""

    value: str
    generation: int
    mutators: tuple[str, ...] = ()
    encoded: bool = False

    def describe(self) -> str:
        if not self.mutators:
            return f"gen0 ({self.value})"
        return f"gen{self.generation} {'+'.join(self.mutators)}"


# ---------------------------------------------------------------- mutator set


def _map_chars(replacements: dict[str, str]):
    def apply(value: str) -> str:
        return "".join(replacements.get(char, char) for char in value)

    return apply


def _replace_all(old: str, new: str):
    def apply(value: str) -> str:
        return value.replace(old, new)

    return apply


def _alternate_case(value: str) -> str:
    out, upper = [], True
    for char in value:
        if char.isalpha():
            out.append(char.upper() if upper else char.lower())
            upper = not upper
        else:
            out.append(char)
    return "".join(out)


def _uppercase_scheme(value: str) -> str:
    """HTTP reads the scheme case-insensitively; a filter may not."""
    pattern = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://")

    def replace(match: re.Match) -> str:
        return match.group(1).upper() + "://"

    return pattern.sub(replace, value, count=1)


BUILTIN_MUTATORS: tuple[Mutator, ...] = (
    # -- scheme and case confusion. Every URL-ish value is read case-insensitively
    #    by the client and possibly case-sensitively by a filter.
    Mutator("case-swap", _alternate_case, (Kind.SSRF, Kind.PROTOCOL), family="case", weight=20),
    Mutator("scheme-uppercase", _uppercase_scheme, (Kind.SSRF, Kind.PROTOCOL), family="case", weight=21),
    # -- encoding. Only applied once: a mutator that already emitted transport
    #    form must not be encoded again.
    Mutator("urlencode", lambda v: quote(v, safe=""), (Kind.SSRF, Kind.PROTOCOL, Kind.TRAVERSAL), family="encoding", weight=30, produces_encoded=True),
    Mutator(
        "urlencode-specials",
        _map_chars({
            ":": "%3a", "/": "%2f", "\\": "%5c", "@": "%40", "?": "%3f",
            "=": "%3d", "&": "%26", "#": "%23", " ": "%20", "\r": "%0d", "\n": "%0a",
        }),
        (Kind.SSRF, Kind.PROTOCOL),
        family="encoding",
        weight=31,
        produces_encoded=True,
    ),
    Mutator("double-urlencode", lambda v: quote(quote(v, safe=""), safe=""), (Kind.SSRF, Kind.PROTOCOL), family="encoding", weight=32, produces_encoded=True),
    Mutator("crlf-encode", _replace_all("\r\n", "%0d%0a"), (Kind.PROTOCOL, Kind.SSRF), family="crlf", weight=33, produces_encoded=True),
    Mutator("crlf-lf-only", _replace_all("\r\n", "%0a"), (Kind.PROTOCOL,), family="crlf", weight=34, produces_encoded=True),
    Mutator("null-byte", lambda v: v + "%00", (Kind.TRAVERSAL, Kind.PROTOCOL), weight=35, produces_encoded=True),
    # -- path handling. Implementations disagree about what these resolve to.
    Mutator("double-slash", lambda v: v.replace("/", "//", 1), (Kind.TRAVERSAL, Kind.PROTOCOL), family="path", weight=40),
    Mutator("dot-slash", lambda v: v.replace("/", "/./", 1), (Kind.TRAVERSAL, Kind.PROTOCOL), family="path", weight=41),
    Mutator("dotdot-encoded", lambda v: v.replace("../", "%2e%2e%2f"), (Kind.TRAVERSAL,), family="encoding", weight=42, produces_encoded=True),
    Mutator("dotdot-overlong", lambda v: v.replace("../", "....//"), (Kind.TRAVERSAL,), family="path", weight=43),
)

# What the modules contribute. The framework and the transformations that belong
# to no particular vulnerability live here; everything that is knowledge about
# one problem - how an address can be spelled, what a target service expects -
# is registered by the module that owns that problem, so the core does not
# accumulate a pile of one domain's tricks.
_registered: list[Mutator] = []


def register(*mutators: Mutator) -> None:
    """Add mutators contributed by a module.

    Idempotent by name. A module registers when it is imported and a test that
    imports it may register again, so the same rewrite can arrive twice - and a
    catalogue holding two entries with one name is a rewrite that gets sent
    twice, which is worse than it sounds once generations multiply it.
    """
    known = {item.name for item in all_mutators()}
    fresh = [item for item in mutators if item.name not in known]
    for item in fresh:
        known.add(item.name)
    _registered.extend(fresh)


def all_mutators() -> tuple[Mutator, ...]:
    return BUILTIN_MUTATORS + tuple(_registered)


def mutator(name: str) -> Mutator:
    for candidate in all_mutators():
        if candidate.name == name:
            return candidate
    raise KeyError(name)


# ------------------------------------------------------------ variant ladder


def applicable(kind: Kind, exclude_families: frozenset[str] = frozenset()) -> list[Mutator]:
    """Mutators usable for a kind, ordered so cheap ones run first."""
    return sorted(
        (
            mutator
            for mutator in all_mutators()
            if mutator.matches(kind) and mutator.family not in exclude_families
        ),
        key=lambda m: (m.weight, m.name),
    )


def generations(
    seed: str,
    kind: Kind = Kind.GENERIC,
    max_generation: int = 2,
    limit: int = 24,
    exclude_families: frozenset[str] = frozenset(),
) -> list[Variant]:
    """Expand a seed into its variant ladder, deduplicated and bounded.

    Generation 0 is the seed itself, so an unprotected target costs one request
    per seed and never sees a mutation.

    `exclude_families` drops whole families before anything is built - for
    rewrites that the thing being targeted cannot run at all, where sending them
    would be requests spent proving nothing rather than a bypass that failed.
    """
    out: list[Variant] = [Variant(value=seed, generation=0)]
    seen: set[str] = {seed}
    frontier: list[tuple[str, int, tuple[str, ...], frozenset[str], bool]] = [
        (seed, 0, (), frozenset(), False)
    ]

    while frontier:
        value, generation, used, families, encoded = frontier.pop(0)
        if generation >= max_generation:
            continue
        for mutator in applicable(kind, families | exclude_families):
            # A variant already in transport form is sent as it stands; encoding
            # it again would make the target receive a literal percent sequence.
            if encoded and mutator.produces_encoded:
                continue
            produced = mutator.apply(value)
            if produced == value:
                continue
            next_generation = generation + 1
            if produced in seen:
                continue
            seen.add(produced)
            out.append(
                Variant(
                    value=produced,
                    generation=next_generation,
                    mutators=used + (mutator.name,),
                    encoded=mutator.produces_encoded,
                )
            )
            if len(out) >= limit:
                return out
            frontier.append(
                (
                    produced,
                    next_generation,
                    used + (mutator.name,),
                    families | ({mutator.family} if mutator.family else frozenset()),
                    mutator.produces_encoded,
                )
            )
    return out


@dataclass
class SeedSet:
    """A named group of seeds, which is what a module actually hands the engine."""

    name: str
    kind: Kind
    seeds: tuple[str, ...]
    max_generation: int = 1
    limit: int = 24
    note: str = ""
    extras: dict = field(default_factory=dict)

    def expand(self) -> list[Variant]:
        out: list[Variant] = []
        for seed in self.seeds:
            out.extend(
                generations(
                    seed,
                    kind=self.kind,
                    max_generation=self.max_generation,
                    limit=self.limit,
                )
            )
        return out
