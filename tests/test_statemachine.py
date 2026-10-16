"""The state graph: what to do, and what each answer means.

The engine's shape lives here. A module declares its actions and the conditions
that move between them, and that is what makes a run reproducible rather than
improvised.
"""

from __future__ import annotations

import unittest

from injectorkit.engine.blackboard import Blackboard
from injectorkit.engine.pheromone import PheromoneTable
from injectorkit.engine.statemachine import Action, State, StateGraph, Transition


def noop(ctx) -> None:
    return None


def action(name: str) -> Action:
    return Action(id=name, description=f"{name} action", run=noop)


class GraphShape(unittest.TestCase):
    def test_a_state_can_be_added_and_found(self):
        graph = StateGraph(name="test", start="start")
        graph.add(State(name="start", description="", actions=[action("a")]))
        self.assertEqual(graph.state("start").name, "start")

    def test_states_keep_the_order_they_were_added_in(self):
        graph = StateGraph(name="test", start="one")
        for name in ("one", "two", "three"):
            graph.add(State(name=name, description="", actions=[action(name)]))
        self.assertEqual(list(graph.states), ["one", "two", "three"])

    def test_the_start_state_is_recorded(self):
        self.assertEqual(StateGraph(name="test", start="first").start, "first")

    def test_an_action_carries_its_id_and_callable(self):
        item = Action(id="probe", description="look", run=noop)
        self.assertEqual(item.id, "probe")
        self.assertTrue(callable(item.run))

    def test_a_state_records_where_it_goes_when_nothing_matches(self):
        state = State(name="probe", description="", actions=[action("probe")], on_exhausted="finish")
        self.assertEqual(state.on_exhausted, "finish")


class WhatTheOperatorAskedFor(unittest.TestCase):
    """A cached verdict is not an answer to a request made by hand.

    The session remembers that an action was tried on a page, which is the right
    thing to skip. But "a file was read here once" is not an answer to "-read
    that file": a run that skips it because it once succeeded has the payload to
    show and nothing else - measured on a live target, where `--read /etc/passwd`
    against a warm session printed the wrapper it would have used and none of
    the file.
    """

    def test_an_action_with_no_request_attached_is_never_forced(self):
        self.assertFalse(action("probe").is_wanted({}))
        self.assertFalse(action("probe").is_wanted({"read": ["/flag"]}))

    def test_a_named_request_forces_the_action(self):
        item = Action(id="probe.read", description="read a file", run=noop, wanted="read")
        self.assertTrue(item.is_wanted({"read": ["/etc/passwd"]}))

    def test_the_request_has_to_actually_be_there(self):
        item = Action(id="probe.read", description="read a file", run=noop, wanted="read")
        self.assertFalse(item.is_wanted({}))
        self.assertFalse(item.is_wanted({"read": []}))
        self.assertFalse(item.is_wanted({"read": None}))

    def test_an_exploit_request_forces_the_action_that_runs_it(self):
        item = Action(id="exploit", description="run code", run=noop, wanted="exploit")
        self.assertTrue(item.is_wanted({"exploit": True}))
        self.assertFalse(item.is_wanted({"exploit": False}))


class WhatAResumedRunOwesTheOperator(unittest.TestCase):
    """The account belongs to this run, not to the one that wrote the session.

    A `not_covered` entry says a condition was missing - no listener, no switch -
    and it is saved with the session. Nothing used to take it back, so a later
    run that supplied the condition printed the earlier run's excuse beside the
    work it had just done: measured, `proto --exploit --os-cmd 'id'` ran the
    chain, printed its output, and still reported "not requested; pass
    --exploit to run code on the target".

    The entry also doubled as a prune, because the state machine skipped on
    "settled either way" - so `probe.remote` was skipped forever after one run
    without a listener, and an action pruned that way never gets to notice that
    the operator has since supplied what it asked for.
    """

    def graph_that_runs(self, ran, wanted=None):
        def body(ctx) -> None:
            ran.append(ctx.config.get("exploit"))

        graph = StateGraph(name="t", start="s")
        graph.add(
            State(
                name="s",
                description="the exploit state",
                actions=[
                    Action(
                        id="exploit.chain",
                        description="run the chain",
                        run=body,
                        wanted=wanted,
                    )
                ],
            )
        )
        return graph

    def run_it(self, board, ran, config=None, wanted=None):
        from injectorkit.engine.statemachine import Engine, RunContext

        graph = self.graph_that_runs(ran, wanted)
        ctx = RunContext(
            graph=graph,
            transport=None,
            blackboard=board,
            pheromone=PheromoneTable(path="", enabled=False),
            config=config or {},
            max_requests=10,
        )
        Engine(graph, ctx).run()
        return ctx

    def board_with_a_stale_entry(self):
        board = Blackboard(target="t")
        board.mark_not_covered("exploit.chain", "not requested; pass --exploit")
        return board

    def test_an_entry_about_a_missing_condition_does_not_prune_the_action(self):
        board = self.board_with_a_stale_entry()
        ran: list = []
        self.run_it(board, ran, config={"exploit": True})
        self.assertEqual(ran, [True], "the action has to get to re-check the condition")

    def test_running_the_action_takes_the_entry_back(self):
        board = self.board_with_a_stale_entry()
        ctx = self.run_it(board, [], config={"exploit": True})
        self.assertNotIn("exploit.chain", ctx.blackboard.not_covered)

    def test_the_action_puts_it_back_when_the_condition_is_still_missing(self):
        board = self.board_with_a_stale_entry()

        def body(ctx) -> None:
            ctx.blackboard.mark_not_covered("exploit.chain", "not requested; pass --exploit")

        graph = StateGraph(name="t", start="s")
        graph.add(State(name="s", description="", actions=[Action("exploit.chain", "run", body)]))
        from injectorkit.engine.statemachine import Engine, RunContext

        ctx = RunContext(
            graph=graph,
            transport=None,
            blackboard=board,
            pheromone=PheromoneTable(path="", enabled=False),
            max_requests=10,
        )
        Engine(graph, ctx).run()
        self.assertEqual(
            ctx.blackboard.not_covered.get("exploit.chain"), "not requested; pass --exploit"
        )

    def test_a_dead_end_still_prunes(self):
        board = Blackboard(target="t")
        board.mark_dead_end("exploit.chain", "the target refused it")
        ran: list = []
        self.run_it(board, ran, config={"exploit": True})
        self.assertEqual(ran, [], "a path that was tried and closed is still closed")


class Transitions(unittest.TestCase):
    def test_a_transition_names_where_it_leads(self):
        self.assertEqual(Transition(to="next", when=lambda ctx: True).to, "next")

    def test_a_state_can_hold_several_transitions(self):
        state = State(
            name="probe",
            description="",
            actions=[action("probe")],
            transitions=[
                Transition(to="exploit", when=lambda ctx: True),
                Transition(to="finish", when=lambda ctx: True),
            ],
        )
        self.assertEqual([item.to for item in state.transitions], ["exploit", "finish"])

    def test_a_transition_can_describe_itself(self):
        transition = Transition(to="next", when=lambda ctx: True, description="a wrapper answered")
        self.assertEqual(transition.description, "a wrapper answered")


class Guards(unittest.TestCase):
    def test_a_guard_is_asked_with_the_run_context(self):
        seen = []

        def when(ctx):
            seen.append(ctx)
            return True

        state = State(name="probe", description="", actions=[action("probe")], transitions=[Transition(to="a", when=when)])
        state.transitions[0].when("CONTEXT")
        self.assertEqual(seen, ["CONTEXT"])

    def test_the_first_matching_branch_wins(self):
        # Order matters: a state lists its most specific condition first and its
        # fallback last.
        state = State(
            name="probe",
            description="",
            actions=[action("probe")],
            transitions=[
                Transition(to="first", when=lambda ctx: True),
                Transition(to="second", when=lambda ctx: True),
            ],
        )
        chosen = next((item.to for item in state.transitions if item.when(None)), None)
        self.assertEqual(chosen, "first")

    def test_a_guard_that_declines_lets_the_next_one_be_asked(self):
        state = State(
            name="probe",
            description="",
            actions=[action("probe")],
            transitions=[
                Transition(to="first", when=lambda ctx: False),
                Transition(to="second", when=lambda ctx: True),
            ],
        )
        chosen = next((item.to for item in state.transitions if item.when(None)), None)
        self.assertEqual(chosen, "second")


if __name__ == "__main__":
    unittest.main()
