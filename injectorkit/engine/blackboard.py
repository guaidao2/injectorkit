"""The blackboard: what the engine has learned about a target.

Modules do not keep state. They read facts from here and write conclusions back,
each with the evidence that produced it, so a later reader can audit why the
engine believed something. Because the facts are shared, a discovery made while
probing one scheme is available to every other module and to the next action of
the same run.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from ..core.httpmsg import Exchange


class Confidence(str, Enum):
    """How firmly a conclusion is held."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Fact:
    """One thing learned about a target."""

    key: str
    value: Any
    evidence: str = ""
    confidence: Confidence = Confidence.INCONCLUSIVE
    at: float = field(default_factory=time.time)

    def describe(self) -> str:
        """One line for the board, with the value kept to a readable width.

        A finding carries the whole request that produced it. That is worth
        having in the session file and unreadable on a terminal, so the board
        says what was proved and on what evidence, and leaves the full value to
        whoever goes looking for it. A list of findings is summarised by name,
        which is the part a reader is scanning for.
        """
        value = self.value
        text = repr(value)
        if len(text) > 120 and isinstance(value, (list, tuple)):
            names = [
                str(item.get("name"))
                for item in value
                if isinstance(item, dict) and item.get("name")
            ]
            text = f"[{', '.join(names)}]" if names else f"[{len(value)} items]"
        if len(text) > 120:
            text = text[:117] + "..."
        return f"{self.key} = {text} [{self.confidence.value}] {self.evidence}".strip()


@dataclass
class Blackboard:
    """Shared facts, dead ends and the traffic that produced them."""

    target: str = ""
    facts: dict[str, Fact] = field(default_factory=dict)
    dead_ends: dict[str, str] = field(default_factory=dict)
    # Paths that were never tried, and what they would need. Kept apart from the
    # dead ends: one is a result, the other is an open question.
    not_covered: dict[str, str] = field(default_factory=dict)
    exchanges: list[Exchange] = field(default_factory=list)
    # Requests the engine did not send itself: the baseline, the page fetched for
    # --forms. Real traffic, and traffic the operator's budget has to include -
    # otherwise a run exceeds what was asked for before its first probe fires.
    # Not persisted: it counts this run, not every run.
    direct_requests: int = 0

    # --------------------------------------------------------------- writing

    def set(
        self,
        key: str,
        value: Any,
        evidence: str = "",
        confidence: Confidence = Confidence.INCONCLUSIVE,
    ) -> Fact:
        fact = Fact(key=key, value=value, evidence=evidence, confidence=confidence)
        self.facts[key] = fact
        return fact

    def get(self, key: str, default: Any = None) -> Any:
        fact = self.facts.get(key)
        return fact.value if fact else default

    def fact(self, key: str) -> Fact | None:
        return self.facts.get(key)

    def has(self, key: str) -> bool:
        return key in self.facts

    def add(self, key: str, value: Any, **kwargs: Any) -> Fact:
        """Collect values under one key without losing what was already there."""
        existing = self.get(key)
        if existing is None:
            return self.set(key, [value], **kwargs)
        if isinstance(existing, list) and value not in existing:
            existing.append(value)
            return self.set(key, existing, **kwargs)
        return self.facts[key]

    # --------------------------------------------------------------- pruning

    def mark_dead_end(self, key: str, reason: str) -> None:
        """Record that a path was tried and ruled out, so nothing retries it."""
        self.dead_ends[key] = reason

    def mark_not_covered(self, key: str, reason: str) -> None:
        """Record a path that was never tried, and what it would take.

        Not the same as a dead end, and the difference is the point: "we tested
        it and it refused" and "we never tested it because there was no listener,
        no upload path, no credential" look identical in a summary that lumps
        them together - and one of them is a hole. Reported separately, the
        second is a to-do list for the next run.
        """
        self.not_covered[key] = reason

    def is_dead(self, key: str) -> bool:
        """Whether a path is settled, either way."""
        return key in self.dead_ends or key in self.not_covered

    # --------------------------------------------------------------- traffic

    def note(self, exchange: Exchange) -> Exchange:
        self.exchanges.append(exchange)
        return exchange

    def count_request(self, count: int = 1) -> None:
        """Record a request that did not go through the engine's own send."""
        self.direct_requests += count

    def requests_sent(self) -> int:
        return len(self.exchanges) + self.direct_requests

    # ------------------------------------------------------------ persistence

    def to_json(self) -> str:
        return json.dumps(
            {
                "target": self.target,
                "facts": {key: asdict(fact) for key, fact in self.facts.items()},
                "dead_ends": self.dead_ends,
                "not_covered": self.not_covered,
            },
            indent=2,
            default=str,
        )

    @classmethod
    def from_json(cls, data: str) -> "Blackboard":
        parsed = json.loads(data)
        board = cls(target=parsed.get("target", ""))
        for key, raw in parsed.get("facts", {}).items():
            board.facts[key] = Fact(
                key=key,
                value=raw.get("value"),
                evidence=raw.get("evidence", ""),
                confidence=Confidence(raw.get("confidence", "inconclusive")),
                at=raw.get("at", time.time()),
            )
        board.dead_ends = dict(parsed.get("dead_ends", {}))
        board.not_covered = dict(parsed.get("not_covered", {}))
        return board

    def save(self, path: str) -> None:
        """Write what was learned, so the next run starts from it.

        Only facts and closed paths are kept: the exchanges are the run, not the
        result, and a session file that grows with every request is not one
        anyone will keep.
        """
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.to_json())

    @classmethod
    def load(cls, path: str) -> "Blackboard":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_json(handle.read())

    def findings(self) -> list[dict]:
        """Every finding on the board, across keys, in the order recorded."""
        out: list[dict] = []
        for key in sorted(self.facts):
            if not key.endswith("findings"):
                continue
            value = self.facts[key].value
            if isinstance(value, list):
                out.extend(item for item in value if isinstance(item, dict))
        return out

    def render_findings(self) -> str:
        """The injection points as a block, the way a report is read.

        One block per finding: what was injected, where, and with what. A
        summary that names a technique but withholds the payload cannot be
        reproduced by hand, and reproducing it by hand is the only thing anyone
        does with a finding.
        """
        found = self.findings()
        if not found:
            return ""
        lines = ["---"]
        for item in found:
            lines.append(f"Parameter: {item.get('param', '?')}")
            if item.get("name"):
                lines.append(f"    Test:     {item['name']}")
            if item.get("family"):
                lines.append(f"    Family:   {item['family']}")
            if item.get("payload"):
                lines.append(f"    Payload:  {item['payload']}")
            if item.get("evidence"):
                lines.append(f"    Evidence: {item['evidence']}")
            lines.append("")
        lines.append("---")
        return "\n".join(lines)

    def render(self) -> str:
        """Human-readable summary, printed at the end of a run.

        Every line says what kind of line it is, the way the rest of the output
        does: `[+]` what was proved, `[-]` what was tried and ruled out, `[?]`
        what was never tried. Those last two are different answers, and a board
        that renders them the same way is not reporting.
        """
        lines = [f"[*] target: {self.target}"]
        if not self.facts:
            lines.append("    (nothing was proved)")
        for key in sorted(self.facts):
            lines.append(f"[+] {self.facts[key].describe()}")
        if self.dead_ends:
            lines.append("[-] closed paths:")
            for key in sorted(self.dead_ends):
                lines.append(f"[-] {key}: {self.dead_ends[key]}")
        if self.not_covered:
            lines.append("[?] not covered:")
            for key in sorted(self.not_covered):
                lines.append(f"[?] {key}: {self.not_covered[key]}")
        lines.append(f"[*] requests sent: {self.requests_sent()}")
        return "\n".join(lines)
