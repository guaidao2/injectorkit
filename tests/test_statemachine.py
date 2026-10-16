"""The state graph: what to do, and what each answer means.

The engine's shape lives here. A module declares its actions and the conditions
that move between them, and that is what makes a run reproducible rather than
improvised.
"""

from __future__ import annotations

import unittest

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
