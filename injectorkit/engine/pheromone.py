"""Pheromone: a weighted memory of which rewrites actually work.

The bypass layer answers a narrow question - which rewrites this target has
refused - and its answer is per target, immediate and binary. That is the right
shape for a single engagement, and the wrong shape for the next one: it cannot
say "address rewrites tend to work, comment insertion tends not to", and it
never forgets.

This table answers the wider question. Every rewrite that reaches a parser
deposits weight; every one that is refused takes it away; and weight evaporates
with time, so a conclusion that was true of one target does not silently rule
forever. Keys are a payload family and the rewrite that produced the value, not
a host: that is what makes one engagement's discovery worth something to the
next.

The table is a prior, not a search. Ordering variants by it changes which
spelling is tried first; it never decides that a spelling is impossible. The
deterministic ladder still runs, so a payload that was misjudged once can still
be tried again.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field

# Where an unknown rewrite sits, and where an evaporated one drifts back to.
NEUTRAL = 0.5

# A rewrite that only stopped being refused stays below this, however often it
# clears a filter: it proved the filter let it past, not that anything on the
# other side acted on it. A confirmed hit lifts the ceiling.
UNVERIFIED_CEILING = 0.7

DEFAULT_PATH = os.path.join(".injectorkit", "pheromone.json")
DEFAULT_HALF_LIFE = 6 * 3600.0


@dataclass
class Trail:
    """What is known about one family of rewrites."""

    weight: float = NEUTRAL
    uses: int = 0
    hits: int = 0
    misses: int = 0
    # True once a rewrite in this trail produced actual evidence.
    verified: bool = False
    updated: float = field(default_factory=time.time)

    def describe(self) -> str:
        mark = "verified" if self.verified else "unverified"
        return f"w={self.weight:.2f} used={self.uses} hit={self.hits} miss={self.misses} {mark}"


class PheromoneTable:
    """Cross-target memory of which rewrites get through."""

    def __init__(
        self,
        path: str = DEFAULT_PATH,
        half_life: float = DEFAULT_HALF_LIFE,
        deposit: float = 0.4,
        penalty: float = 0.25,
        enabled: bool = True,
    ) -> None:
        self.path = path
        self.half_life = max(1.0, half_life)
        self.deposit = deposit
        self.penalty = penalty
        self.enabled = enabled
        self.trails: dict[str, Trail] = {}
        self.dirty = False

    # ------------------------------------------------------------- addressing

    @staticmethod
    def key(family: str, mutators: tuple[str, ...]) -> str:
        return f"{family or 'any'}|{'+'.join(mutators)}" if mutators else ""

    # ----------------------------------------------------------------- weight

    def weight(self, family: str, mutators: tuple[str, ...]) -> float:
        """Current weight, after evaporating whatever time has passed.

        Evaporation is time-based rather than round-based: a conclusion reached
        this morning should not weigh the same tonight, and a scan that runs
        once a week should not keep carrying a verdict forever.
        """
        if not mutators:
            return NEUTRAL
        trail = self.trails.get(self.key(family, mutators))
        if trail is None:
            return NEUTRAL
        age = max(0.0, time.time() - trail.updated)
        return NEUTRAL + (trail.weight - NEUTRAL) * (0.5 ** (age / self.half_life))

    def reward(self, family: str, mutators: tuple[str, ...], amount: float = 1.0) -> None:
        """Lay down weight for a rewrite that worked.

        The amount matters. Clearing a filter is not the same as reaching a
        parser: a payload that stopped being refused but produced no evidence
        has proved only that the filter let it past, and scoring that the same
        as a confirmed hit teaches the table to prefer rewrites that get
        nowhere quietly.
        """
        if not self.enabled or not mutators:
            return
        self._update(family, mutators, success=True, amount=amount)

    def punish(self, family: str, mutators: tuple[str, ...], amount: float = 1.0) -> None:
        """A rewrite was refused: take weight away."""
        if not self.enabled or not mutators:
            return
        self._update(family, mutators, success=False, amount=amount)

    def _update(self, family: str, mutators: tuple[str, ...], success: bool, amount: float = 1.0) -> None:
        key = self.key(family, mutators)
        current = self.weight(family, mutators)
        trail = self.trails.setdefault(key, Trail(weight=current))
        current = NEUTRAL + (trail.weight - NEUTRAL) * 0.5 ** (
            max(0.0, time.time() - trail.updated) / self.half_life
        )
        if success:
            updated = current + (1.0 - current) * self.deposit * max(0.0, amount)
            trail.hits += 1
            if amount >= 1.0:
                trail.verified = True
        else:
            updated = current * (1.0 - self.penalty * max(0.0, amount))
            trail.misses += 1
        ceiling = 1.0 if trail.verified else UNVERIFIED_CEILING
        trail.weight = min(ceiling, max(0.0, updated))
        trail.uses += 1
        trail.updated = time.time()
        self.dirty = True

    def recalibrate(self, strength: float = 1.0) -> int:
        """Pull every trail back toward neutral, because the food ran out.

        Evaporation here is driven by time, and time is the wrong trigger for the
        case that matters. When a target yields nothing at all, the conclusion
        that "this rewrite gets through" is not old, it is wrong - and a table
        that only forgets with age keeps steering the next attempt by it. That is
        the opposite of what a colony does: with no food found it stops walking
        the old trail and spreads out again.

        So a run that found nothing calls this with the strength of its failure.
        Weight moves toward neutral in both directions, which means a trail that
        looked good stops leading and one that looked bad gets another hearing.
        Nothing here deletes: the counts and the verified flag stay, and a trail
        that keeps earning will climb back.

        Returns how many trails moved.
        """
        if not self.enabled or strength <= 0:
            return 0
        pull = min(1.0, strength)
        moved = 0
        for trail in self.trails.values():
            target = NEUTRAL
            updated = trail.weight + (target - trail.weight) * pull
            if abs(updated - trail.weight) > 1e-9:
                trail.weight = max(0.0, min(1.0, updated))
                trail.updated = time.time()
                moved += 1
        if moved:
            self.dirty = True
        return moved

    def rank(self, family: str, variants) -> list:
        """Order variants by what is most likely to get through.

        Generation 0 keeps its place at the front whatever the table says: it
        costs one request and it is the only spelling that needs no justification
        - an unprotected target should never be sent a mutation.

        Below that, an untried rewrite is not ranked by a weight it does not have,
        and it is not put last either. It slots in at neutral: behind a rewrite
        this target has already been seen to accept, ahead of one that has been
        tried and did not work. Ranking the unknown last is how a table that has
        learned a lot about a target stops finding out about the rewrites it never
        reached - the frontier is where the next thing is, and it has to stay
        reachable.
        """
        if not self.enabled:
            return list(variants)

        def sort_key(variant):
            if not variant.mutators:
                return (0, 0.0, variant.generation)
            trail = self.trails.get(self.key(family, variant.mutators))
            ranking = NEUTRAL if trail is None else self.weight(family, variant.mutators)
            return (1, -ranking, variant.generation)

        return sorted(variants, key=sort_key)

    # ------------------------------------------------------------ persistence

    def load(self) -> "PheromoneTable":
        if not self.enabled or not self.path or not os.path.exists(self.path):
            return self
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError):
            # A damaged table is not worth failing a run over; start over.
            return self
        for key, raw in (payload.get("trails") or {}).items():
            try:
                self.trails[key] = Trail(
                    weight=float(raw.get("weight", NEUTRAL)),
                    uses=int(raw.get("uses", 0)),
                    hits=int(raw.get("hits", 0)),
                    misses=int(raw.get("misses", 0)),
                    verified=bool(raw.get("verified", False)),
                    updated=float(raw.get("updated", time.time())),
                )
            except (TypeError, ValueError):
                continue
        return self

    def save(self) -> None:
        if not self.enabled or not self.dirty or not self.path:
            return
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        payload = {
            "version": 1,
            "half_life": self.half_life,
            "trails": {key: asdict(trail) for key, trail in self.trails.items()},
        }
        try:
            with open(self.path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
        except OSError:
            pass

    # ----------------------------------------------------------------- report

    def summary(self) -> str:
        """One line per family that has learned something, most used first."""
        if not self.trails:
            return "no prior experience"
        rows = []
        for key, trail in sorted(self.trails.items(), key=lambda item: -item[1].uses):
            family, _, mutators = key.partition("|")
            rows.append(f"{family}: {mutators or '(none)'} {trail.describe()}")
        return "\n".join(rows)
