"""The state machine: probe, observe, decide, advance.

A module does not run a list of payloads. It contributes a graph of states, each
with the actions worth trying there and the transitions that fire on evidence.
The engine walks it, records everything on the blackboard, and moves on when the
target answers a question - including the answer "this path is closed", which is
recorded as a dead end so nothing retries it.

The same engine runs every vulnerability class, because every class is the same
shape of work over a different graph.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

from .blackboard import Blackboard
from .bypass import Bypass
from .evidence import Judge
from .transport import Transport
from ..core.httpmsg import Exchange, Request


@dataclass
class Action:
    """One thing worth doing in a state."""

    id: str
    description: str
    run: Callable[["RunContext"], None]
    # Generation ladder this action uses, if any. Recorded so a bypassed target
    # can resume at the generation that already worked.
    ladder: str = ""

    def __post_init__(self) -> None:
        if not self.ladder:
            self.ladder = self.id


@dataclass
class Transition:
    """A move to another state, taken when the evidence says so."""

    to: str
    when: Callable[["RunContext"], bool]
    description: str = ""


@dataclass
class State:
    """A phase of the run."""

    name: str
    description: str
    actions: list[Action] = field(default_factory=list)
    transitions: list[Transition] = field(default_factory=list)
    on_exhausted: str | None = None


@dataclass
class StateGraph:
    """A module's contribution: the states and how they connect."""

    name: str
    start: str
    states: dict[str, State] = field(default_factory=dict)

    def add(self, state: State) -> State:
        self.states[state.name] = state
        return state

    def state(self, name: str) -> State:
        if name not in self.states:
            raise KeyError(f"state graph has no state named {name!r}")
        return self.states[name]


class RunContext:
    """Everything an action may touch.

    An action never imports a module or reaches for a global. It sends through
    the context, which means its traffic is counted, its filter behaviour is
    recorded, and its findings land on the blackboard for every other module.
    """

    def __init__(
        self,
        graph: StateGraph,
        transport: Transport,
        blackboard: Blackboard | None = None,
        judge: Judge | None = None,
        bypass: Bypass | None = None,
        oob: Any = None,
        pheromone: Any = None,
        config: dict[str, Any] | None = None,
        log: Callable[[str], None] | None = None,
        emit: Callable[[str], None] | None = None,
        info: Callable[[str], None] | None = None,
        max_requests: int = 400,
    ) -> None:
        self.graph = graph
        self.transport = transport
        self.blackboard = blackboard or Blackboard()
        self.judge = judge or Judge()
        self.bypass = bypass or Bypass(self.blackboard)
        self.oob = oob
        # Cross-target priors on which rewrites work. Ordering only: it decides
        # what is tried first, never what is possible.
        self.pheromone = pheromone
        self.config = config or {}
        self.log = log or (lambda message: None)
        # Results the user asked for, and progress they did not.
        self.emit = emit or self.log
        self.info = info or self.log
        self.max_requests = max_requests
        self._stopped = False
        self.state = graph.start
        # Set by an action that has concluded the current state early.
        self.advance_to: str | None = None
        # Whether the last response looked like a refusal, which is the signal
        # to climb the mutation ladder rather than repeat a spelling.
        self.last_refused = False

    # ---------------------------------------------------------------- control

    def stop(self, reason: str = "") -> None:
        if not self._stopped and reason:
            self.log(f"stopping: {reason}")
        self._stopped = True

    @property
    def stopped(self) -> bool:
        if self.blackboard.requests_sent() >= self.max_requests:
            self._stopped = True
            self.log(f"request budget of {self.max_requests} reached")
        return self._stopped

    # --------------------------------------------------------------- traffic

    def send(self, request: Request, action: str = "") -> Exchange:
        """Send one request and record it. Every action goes through here."""
        response = self.transport.send(request)
        exchange = Exchange(request=request, response=response, action=action)
        self.blackboard.note(exchange)
        self.log(exchange.render())

        host = request.host()
        self.last_refused = False
        if host and self.bypass.enabled:
            refused = self.bypass.observe(host, action, response, request_label=request.label)
            self.last_refused = refused
            if refused:
                self.log(f"  refused by {host}; raising filter pressure")
        return exchange

    def variants(self, seed: str, generation: int = 0, kind: Any = None, limit: int = 12) -> list[Any]:
        """Expand a seed into variants at or past a generation."""
        from ..core.mutate import Kind, generations

        start = max(0, generation)
        ladder = generations(seed, kind=kind or Kind.SSRF, max_generation=start + 3, limit=limit)
        return [variant for variant in ladder if variant.generation >= start]


class Engine:
    """Walks a state graph until it has an answer or runs out of moves."""

    def __init__(self, graph: StateGraph, context: RunContext) -> None:
        self.graph = graph
        self.ctx = context
        self.visited: list[str] = []

    def run(self) -> Blackboard:
        current = self.graph.start
        guard = 0
        while current and not self.ctx.stopped:
            guard += 1
            if guard > 64:
                self.ctx.log("state machine stopped: too many state changes")
                break
            state = self.graph.state(current)
            self.visited.append(state.name)
            self.ctx.state = state.name
            # What the run is about to do, in the words the operator would use.
            # This is the line that makes a scan readable while it runs, so it
            # belongs with the progress output rather than behind -v.
            self.ctx.info(state.description)

            advanced = False
            for action in state.actions:
                if self.ctx.stopped:
                    break
                if self.ctx.blackboard.is_dead(action.id):
                    self.ctx.log(f"   already ruled out: {action.description}")
                    continue
                self.ctx.info(f"testing {action.description}")
                try:
                    action.run(self.ctx)
                except Exception as error:  # a broken action must not end the run
                    self.ctx.log(f"   action {action.id} failed: {error}")
                    self.ctx.blackboard.mark_dead_end(action.id, f"raised {type(error).__name__}: {error}")
                    if self.ctx.config.get("traceback"):
                        self.ctx.log(traceback.format_exc())

                # An action may decide the state is finished with, which is how a
                # conclusive early answer skips the rest of a state's work.
                if self.ctx.advance_to:
                    current, self.ctx.advance_to = self.ctx.advance_to, None
                    self.ctx.log(f"   -> {current} (action {action.id} concluded the state)")
                    advanced = True
                    break

            if advanced:
                continue

            # Transitions are evaluated once the state's work is done, so an
            # early answer in one action cannot silently cancel the others.
            target, reason = self._transition(state)
            if target:
                self.ctx.log(f"   -> {target} ({reason})")
                current = target
                continue
            if state.on_exhausted:
                current = state.on_exhausted
                continue
            break
        return self.ctx.blackboard

    def _transition(self, state: State) -> tuple[str | None, str]:
        """First transition whose condition holds, evaluated exactly once."""
        for transition in state.transitions:
            try:
                if transition.when(self.ctx):
                    return transition.to, transition.description or "evidence matched"
            except Exception as error:
                self.ctx.log(f"   transition to {transition.to} raised: {error}")
        return None, ""
