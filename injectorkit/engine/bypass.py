"""The bypass subsystem: how a value gets past a filter, and what is remembered.

Two jobs, both engine-level so no module has to think about them.

The first is to keep a filter profile per target: which spellings were refused,
which were rewritten, and at which generation a value started to reach the
parser. Detection is deliberately conservative, because a false positive is
expensive - every later action would climb generations for nothing.

The second is to make escalation affordable. Once generation 2 is known to pass
for a target, the next action starts there instead of rediscovering the fact,
which is what turns a ladder into a budget.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from .blackboard import Blackboard, Confidence
from .evidence import refused as looks_refused
from ..core.httpmsg import Response


@dataclass
class FilterProfile:
    """What one host does with input it does not like."""

    host: str
    vendor: str = ""
    refusals: int = 0
    rewrites: int = 0
    observed: bool = False
    # Per action family, the generation known to get through.
    floors: dict[str, int] = field(default_factory=dict)
    refused_values: list[str] = field(default_factory=list)

    @property
    def protected(self) -> bool:
        return bool(self.vendor) or self.refusals >= 2

    def floor(self, action: str) -> int:
        return self.floors.get(action, 0)

    def raise_floor(self, action: str, generation: int) -> None:
        """Only ever upwards: one pass is evidence the spelling works, a later
        refusal is not evidence it stopped working."""
        if generation > self.floors.get(action, 0):
            self.floors[action] = generation

    def describe(self) -> str:
        state = "protected" if self.protected else "open"
        vendor = f" ({self.vendor})" if self.vendor else ""
        floors = ", ".join(f"{key}=gen{value}" for key, value in sorted(self.floors.items()))
        return f"{self.host}: {state}{vendor}, refusals={self.refusals}, floors=[{floors}]"


class Bypass:
    """Owns filter profiles and decides when to escalate."""

    def __init__(self, blackboard: Blackboard, max_generation: int = 3, enabled: bool = True) -> None:
        self.blackboard = blackboard
        self.max_generation = max_generation
        self.enabled = enabled
        self.profiles: dict[str, FilterProfile] = {}
        # Per host and action, the mutators already proven to be refused. A
        # filter that is case-insensitive defeats case-swap once; there is no
        # reason for the next payload to pay for that discovery again.
        self.dead_mutators: dict[str, set[str]] = {}

    # ------------------------------------------------------------ persistence

    def to_json(self) -> str:
        """What this run learned about how hosts treat input they dislike.

        Worth keeping between runs because all of it is bought with refused
        requests: the refusal count, the refused spellings and the generation
        floor are earned one rejection at a time, and re-earning them costs
        exactly what they cost the first time. The board facts derived from them
        are not enough - the thresholds behind those facts are the part that has
        to survive.
        """
        return json.dumps(
            {
                "profiles": {host: asdict(profile) for host, profile in self.profiles.items()},
                "dead_mutators": {key: sorted(names) for key, names in self.dead_mutators.items()},
            },
            indent=2,
        )

    def load_json(self, text: str) -> int:
        """Merge remembered profiles in. Returns how many hosts were loaded."""
        try:
            raw = json.loads(text)
        except ValueError:
            return 0
        if not isinstance(raw, dict):
            return 0

        loaded = 0
        profiles = raw.get("profiles")
        if isinstance(profiles, dict):
            for host, data in profiles.items():
                if not isinstance(data, dict):
                    continue
                self.profiles[host] = FilterProfile(
                    host=host,
                    vendor=str(data.get("vendor", "")),
                    refusals=int(data.get("refusals", 0)),
                    rewrites=int(data.get("rewrites", 0)),
                    observed=bool(data.get("observed", False)),
                    floors={str(k): int(v) for k, v in (data.get("floors") or {}).items()},
                    refused_values=[str(value) for value in (data.get("refused_values") or [])],
                )
                loaded += 1

        dead = raw.get("dead_mutators")
        if isinstance(dead, dict):
            for key, names in dead.items():
                if isinstance(names, list):
                    self.dead_mutators.setdefault(key, set()).update(str(name) for name in names)
        return loaded

    # ---------------------------------------------------------------- profile

    def profile(self, host: str) -> FilterProfile:
        if host not in self.profiles:
            self.profiles[host] = FilterProfile(host=host)
        return self.profiles[host]

    def floor(self, host: str, action: str) -> int:
        return self.profile(host).floor(action) if self.enabled else 0

    def raise_floor(self, host: str, action: str, generation: int) -> None:
        if not self.enabled or generation <= 0:
            return
        profile = self.profile(host)
        profile.raise_floor(action, generation)
        self.blackboard.set(
            f"bypass.floor.{host}.{action}",
            generation,
            evidence=f"generation {generation} reached the target",
            confidence=Confidence.LIKELY,
        )

    # ------------------------------------------------------------- observing

    def mutator_dead(self, host: str, action: str, name: str, scope: str = "") -> bool:
        return name in self.dead_mutators.get(self._dead_key(host, action, scope), ())

    def mark_mutator_dead(self, host: str, action: str, name: str, scope: str = "") -> None:
        """Remember a rewrite this target refuses, so nothing spells it again.

        The scope narrows the claim. A rewrite that failed on a `gopher://`
        payload says nothing about the same rewrite on an `http://` one: the
        filter caught a literal that only one of them carries.
        """
        if not self.enabled or not name:
            return
        key = self._dead_key(host, action, scope)
        self.dead_mutators.setdefault(key, set()).add(name)
        self.blackboard.set(
            f"bypass.dead.{host}.{action}{('.' + scope) if scope else ''}",
            sorted(self.dead_mutators[key]),
            evidence=f"{name} was refused by the filter",
            confidence=Confidence.LIKELY,
        )

    @staticmethod
    def _dead_key(host: str, action: str, scope: str) -> str:
        return f"{host}|{action}|{scope}" if scope else f"{host}|{action}"

    def observe(self, host: str, action: str, response: Response, request_label: str = "") -> bool:
        """Record what a response says about the filter. Returns True on refusal."""
        profile = self.profile(host)
        profile.observed = True
        if _refused(response):
            profile.refusals += 1
            if request_label:
                # Bounded: a long run must not grow this without limit.
                if len(profile.refused_values) < 100:
                    profile.refused_values.append(request_label)
            self.blackboard.set(
                f"filter.refused.{host}",
                profile.refusals,
                evidence=f"{request_label or 'probe'} was refused with status {response.status}",
                confidence=Confidence.LIKELY,
            )
            return True
        return False

    def summarise(self) -> str:
        if not self.profiles:
            return "no target observed"
        return "; ".join(profile.describe() for profile in self.profiles.values())

    def refusals(self) -> int:
        """How many requests the target refused outright."""
        return sum(profile.refusals for profile in self.profiles.values())

    def blocked_families(self) -> dict[str, int]:
        """Which payload families are closed, and how many rewrites proved it.

        This is the difference between "nothing here" and "everything here is
        filtered": a run that found nothing because every spelling was refused
        has to say so, or its silence reads as a clean target.
        """
        out: dict[str, int] = {}
        for key, names in self.dead_mutators.items():
            parts = key.split("|")
            scope = parts[2] if len(parts) > 2 and parts[2] else "any"
            out[scope] = out.get(scope, 0) + len(names)
        return out


def _refused(response: Response) -> bool:
    """Whether a response looks like something refused the request.

    Delegated rather than reimplemented. This is the copy the ladder actually
    reads - every time a response comes back - while the judge's is only reached
    when a module asks. While they were separate, a fix applied to the judge's
    looked like a fix and changed nothing on the path that matters.
    """
    return looks_refused(response)
