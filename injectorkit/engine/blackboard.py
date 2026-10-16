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


# Facts whose key starts with this hold a file a run read, and the value is what
# came back. A read is a result rather than bookkeeping, so it is rendered with
# the findings and at the end - the operator named a file, and the file is the
# answer. The prefix is the contract between a module that reads and the summary
# that shows: the module decides what is worth reading, the board decides how a
# result is presented.
READ_FACT_PREFIX = "read.file."

# How much of a file to print. A read that fills the screen tells the reader
# nothing they can act on, and the whole of it is in the session file.
READ_LINES = 40

# Facts whose key is a command and whose value is what it printed. Same reasoning
# as a file that was read: the operator asked for a command to run and the output
# is the answer, so it belongs with the results and not among the progress lines
# it happened to scroll past. Keyed by the command, so running the same one twice
# shows it once.
RUN_FACT_PREFIX = "run.command."

# How much of a command's output to print.
RUN_LINES = 40

# The word for a value that came out of the session rather than out of this run,
# for the result block. One phrase, reused: the project already says it on the
# line that announces a read, and a second wording for one fact is how two
# spellings of the same thing end up disagreeing.
RESUMED = "  (resumed from an earlier run)"

# What the target said, as opposed to what the run worked out about it. These are
# readings of a moment and are never written to the session: the file may have
# changed, and a stale reading presented as a result is worse than no reading at
# all. The path that reached them is written, so asking again is cheap.
CONTENT_PREFIXES = (READ_FACT_PREFIX, RUN_FACT_PREFIX)


@dataclass
class Fact:
    """One thing learned about a target."""

    key: str
    value: Any
    evidence: str = ""
    confidence: Confidence = Confidence.INCONCLUSIVE
    at: float = field(default_factory=time.time)
    # Whether this came out of the session file rather than out of this run.
    #
    # Set on load and never cleared, because a fact that a run re-derives is
    # written again by `set`, which builds a new Fact. It is deliberately not
    # tracked per element: `add` merges into a list, and a list holding one
    # answer from this run and three from the last one is neither carried nor
    # this run's. The content sections below are single-valued facts, which is
    # where this can be said without lying; a list is covered by the run-level
    # line instead.
    carried: bool = False

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

    def forget_not_covered(self, key: str) -> None:
        """Drop a "never tried" entry, for when it stops being true.

        Every one of these is about a condition - no listener, no switch, no
        upload path - and a condition can be supplied on the next run. The entry
        is persisted with the session, so without this the summary reports the
        previous run's excuse beside work that just happened: with `--exploit`
        given and the chain run, `not requested; pass --exploit` was still
        printed, because nothing ever took the line back.
        """
        self.not_covered.pop(key, None)

    def is_ruled_out(self, key: str) -> bool:
        """Whether a path was tried and closed.

        Only the dead ends. A `not_covered` entry is a to-do, not a verdict: the
        operator can pass the listener or the switch next time, and pruning on it
        would mean the action never gets to notice that they did - so
        `probe.remote` would be skipped forever after one run without a listener.
        """
        return key in self.dead_ends

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
        """Everything learned about the target's shape - and none of its content.

        Two kinds of fact, and they age differently. What a run worked out about
        the target's *shape* - which parameter takes a wrapper, which delivery
        reaches a shell, where files live - is the path it found, and that is what
        the next run should start from. What the target *said* - the bytes of a
        file, the output of a command - is a reading of a moment: the file may
        have changed since, and an answer served from a session file is a claim
        about a run that is not this one.

        So the content facts are not written. They are re-fetched when the
        operator asks again, and the path that is written is what makes asking
        again cheap - the wrapper that worked is tried first instead of searched
        for. Measured: a warm `--read` run costs a handful of requests instead of
        the whole ladder, because the ladder's outcome is the part that survived.
        """
        keep = {
            key: asdict(fact)
            for key, fact in self.facts.items()
            if not key.startswith(CONTENT_PREFIXES)
        }
        return json.dumps(
            {
                "target": self.target,
                "facts": keep,
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
                # Everything here came off disk. Whatever the run does next
                # writes its own Fact, so this is the whole of the marking.
                carried=True,
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

    # How wide a payload may be before the block stops printing it whole.
    # A short payload is worth copying by hand - that is what a finding is for.
    # A generated filter chain is twelve thousand characters of iconv names, and
    # nobody has ever retyped one: it is rebuilt, not transcribed, so the block
    # says what it was and how long, and leaves the bytes to the session file.
    PAYLOAD_WIDTH = 200

    def render_findings(self) -> str:
        """The injection points as a block, the way a report is read.

        One block per finding: what was injected, where, and with what. A
        summary that names a technique but withholds the payload cannot be
        reproduced by hand, and reproducing it by hand is the only thing anyone
        does with a finding - but that holds for payloads a person can read. One
        that is twelve thousand characters long is reproduced by asking the tool
        for it again, so printing it whole costs a screen and tells the reader
        nothing they can use.
        """
        found = self.findings()
        reads = self.reads()
        runs = self.runs()
        if not found and not reads and not runs:
            return ""
        lines = ["---"]
        for item in found:
            lines.append(f"Parameter: {item.get('param', '?')}")
            if item.get("name"):
                lines.append(f"    Test:     {item['name']}")
            if item.get("family"):
                lines.append(f"    Family:   {item['family']}")
            payload = str(item.get("payload") or "")
            if payload:
                lines.append(f"    Payload:  {self._readable_payload(payload)}")
            if item.get("evidence"):
                lines.append(f"    Evidence: {item['evidence']}")
            lines.append("")
        lines.append("---")
        if reads:
            lines.append("")
            lines.append("Files read:")
            for path, content, carried in reads:
                lines.append(f"    {path}{RESUMED if carried else ''}")
                body = content.splitlines()
                if not body:
                    lines.append("      (the file is empty)")
                    continue
                for line in body[:READ_LINES]:
                    lines.append(f"      {line}")
                extra = len(body) - READ_LINES
                if extra > 0:
                    lines.append(f"      ... {extra} more line(s)")
        if runs:
            lines.append("")
            lines.append("Commands run:")
            for command, output, carried in runs:
                lines.append(f"    {command}{RESUMED if carried else ''}")
                body = output.splitlines()
                if not body:
                    lines.append("      (no output)")
                    continue
                for line in body[:RUN_LINES]:
                    lines.append(f"      {line}")
                extra = len(body) - RUN_LINES
                if extra > 0:
                    lines.append(f"      ... {extra} more line(s)")
        return "\n".join(lines)

    def reads(self) -> list[tuple[str, str]]:
        """The files a run actually read, in the order they were first read.

        A file that was read is a result, not bookkeeping: the operator named it,
        and the content is the whole answer. It is shown once, at the end, even
        when several wrappers turned out to reach it - which one worked is in the
        findings above, and saying the same file four times buries the one thing
        that was asked for.

        A file with nothing in it is still shown. "I read it and it is empty" is
        an answer to what was asked; dropping it here is how the operator gets
        silence and cannot tell it from a read that never happened.

        The third element says whether the answer came out of the session. It is
        the `Fact`'s own note, which used to be thrown away by returning a pair -
        and an answer with no note is how a run that read nothing printed a file
        under a heading that says the run read it.
        """
        out: list[tuple[str, str, bool]] = []
        for key, fact in self.facts.items():
            if not key.startswith(READ_FACT_PREFIX):
                continue
            path = key[len(READ_FACT_PREFIX) :]
            if isinstance(fact.value, str):
                out.append((path, fact.value, fact.carried))
        return sorted(out)

    def runs(self) -> list[tuple[str, str, bool]]:
        """The commands a run executed, and what each printed. See `reads`."""
        out: list[tuple[str, str, bool]] = []
        for key, fact in self.facts.items():
            if not key.startswith(RUN_FACT_PREFIX):
                continue
            command = key[len(RUN_FACT_PREFIX) :]
            output = fact.value if isinstance(fact.value, str) else ""
            out.append((command, output, fact.carried))
        return sorted(out)

    def remember_run(self, command: str, output: str) -> None:
        """Keep what a command printed, so the summary can show it."""
        if not command:
            return
        self.set(
            RUN_FACT_PREFIX + command,
            output,
            evidence="the output of a command run through the target",
            confidence=Confidence.CONFIRMED,
        )

    def _readable_payload(self, payload: str) -> str:
        """The payload if it can be read, and a description of it if it cannot."""
        if len(payload) <= self.PAYLOAD_WIDTH:
            return payload
        head = payload[: self.PAYLOAD_WIDTH].rstrip()
        return (
            f"{head}\n"
            f"              ... {len(payload)} characters in all, generated at run time. "
            "The full value is in the session file"
        )

    # Facts that record what the run did rather than what it found. "This page
    # has been tried" is what saves the next run the work, and it belongs in the
    # session file - not in the summary, where it reads as a result and buries
    # the one line that is one.
    #
    # The filter and bypass facts are here for the same reason: `bypass.floor.…`
    # and `filter.refused.…` are counts about the tool's own state, and on a
    # filtered target there are more of them than findings - printed as `[+]`,
    # directly above the finding somebody is looking for.
    BOOKKEEPING = ("ran.", "bypass.", "filter.")

    # Facts that are results, but are shown somewhere better. A file that was
    # read has a section of its own at the end; in the fact list it would appear
    # as a Python literal of the whole file, directly above the line saying it
    # was read.
    SHOWN_ELSEWHERE = (READ_FACT_PREFIX, RUN_FACT_PREFIX)

    def is_bookkeeping(self, key: str) -> bool:
        return key.startswith(self.BOOKKEEPING + self.SHOWN_ELSEWHERE)

    def render(self) -> str:
        """Human-readable summary, printed at the end of a run.

        Every line says what kind of line it is, the way the rest of the output
        does: `[+]` what was proved, `[-]` what was tried and ruled out, `[?]`
        what was never tried. Those last two are different answers, and a board
        that renders them the same way is not reporting.

        What the run *did* stays out of it. A dozen `ran.<action> = True` lines
        are a record for the next run, and printing them beside the findings
        makes the findings harder to find - which is the opposite of what a
        summary is for. `-v` prints them for anyone who wants them.
        """
        lines = [f"[*] target: {self.target}"]
        results = [key for key in sorted(self.facts) if not self.is_bookkeeping(key)]
        if not results:
            lines.append("    (nothing was proved)")
        for key in results:
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

    def render_bookkeeping(self) -> str:
        """What the run did, for -v: which actions were tried on this page."""
        keys = [key for key in sorted(self.facts) if self.is_bookkeeping(key)]
        if not keys:
            return ""
        lines = ["[*] actions tried on this page:"]
        for key in keys:
            lines.append(f"    {self._without_prefix(key)}")
        return "\n".join(lines)

    def _without_prefix(self, key: str) -> str:
        """The key with its standing prefix removed, and only if it has one.

        Three prefixes end up in this renderer now - `ran.` for actions and
        `bypass.` / `filter.` for what the filter subsystem worked out - so
        slicing a fixed four characters off every key turned `bypass.floor...`
        into `ss.floor...` and `run.command.id` into `command.id`. A mangled name
        is worse than a long one: it cannot be searched for.
        """
        for prefix in self.BOOKKEEPING:
            if key.startswith(prefix):
                return key[len(prefix) :]
        return key
