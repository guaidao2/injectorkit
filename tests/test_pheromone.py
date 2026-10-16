"""What the colony does when there is no food.

The table exists to make the next run cheaper, which only works while what it
remembers is still true. Evaporation here is measured in time, and time is the
wrong trigger for the case that matters: a target that yields nothing does not
hold a stale belief about rewrites, it holds a wrong one, and a table that only
forgets with age keeps steering the next attempt by it.

What a colony does instead is stop walking the old trail: with nothing found, the
preference is pulled back toward the middle and the untried rewrites get their
turn. These tests are about that, and about the ordering that makes it possible.
"""

from __future__ import annotations

import os
import unittest
from types import SimpleNamespace

from injectorkit.engine.blackboard import Blackboard
from injectorkit.engine.pheromone import NEUTRAL, PheromoneTable

SCRATCH = os.path.join(os.getcwd(), ".tmp", "pheromone-test")


class Trail:
    """A variant to rank: mutators plus a generation."""

    def __init__(self, mutators=(), generation: int = 0):
        self.mutators = tuple(mutators)
        self.generation = generation


def table() -> PheromoneTable:
    return PheromoneTable(path="")


class Recalibration(unittest.TestCase):
    def test_a_preference_is_pulled_toward_the_middle(self):
        table_ = table()
        table_.reward("probe", ("upper",), amount=1.0)
        high = table_.weight("probe", ("upper",))
        self.assertGreater(high, NEUTRAL)

        table_.recalibrate(1.0)
        self.assertAlmostEqual(table_.weight("probe", ("upper",)), NEUTRAL, places=6)

    def test_it_works_in_both_directions(self):
        # A trail that looked bad is as suspect as one that looked good; a target
        # that found nothing has no grounds for either belief.
        table_ = table()
        table_.punish("probe", ("null-byte",), amount=1.0)
        self.assertLess(table_.weight("probe", ("null-byte",)), NEUTRAL)

        table_.recalibrate(1.0)
        self.assertAlmostEqual(table_.weight("probe", ("null-byte",)), NEUTRAL, places=6)

    def test_a_partial_pull_leaves_something_behind(self):
        table_ = table()
        table_.reward("probe", ("upper",), amount=1.0)
        before = table_.weight("probe", ("upper",))
        table_.recalibrate(0.5)
        after = table_.weight("probe", ("upper",))
        self.assertLess(after, before)
        self.assertGreater(after, NEUTRAL)

    def test_nothing_is_deleted(self):
        # The counts and the verified flag are the record of what was observed.
        # Recalibration is about what will be believed next, not about erasing
        # what happened.
        table_ = table()
        table_.reward("probe", ("upper",), amount=1.0)
        trail = table_.trails[PheromoneTable.key("probe", ("upper",))]
        table_.recalibrate(1.0)
        self.assertEqual(trail.hits, 1)
        self.assertEqual(trail.uses, 1)
        self.assertTrue(trail.verified)

    def test_a_trail_that_keeps_earning_climbs_back(self):
        table_ = table()
        table_.reward("probe", ("upper",), amount=1.0)
        table_.recalibrate(1.0)
        middle = table_.weight("probe", ("upper",))
        table_.reward("probe", ("upper",), amount=1.0)
        self.assertGreater(table_.weight("probe", ("upper",)), middle)

    def test_it_reports_how_many_moved(self):
        table_ = table()
        table_.reward("probe", ("upper",))
        table_.reward("probe", ("lower",))
        self.assertEqual(table_.recalibrate(1.0), 2)

    def test_a_zero_strength_does_nothing(self):
        table_ = table()
        table_.reward("probe", ("upper",))
        self.assertEqual(table_.recalibrate(0.0), 0)

    def test_a_disabled_table_is_left_alone(self):
        table_ = PheromoneTable(path="", enabled=False)
        table_.reward("probe", ("upper",))
        self.assertEqual(table_.recalibrate(1.0), 0)
        self.assertEqual(table_.weight("probe", ("upper",)), NEUTRAL)


class TheFrontierStaysReachable(unittest.TestCase):
    """A rewrite nothing has tried is ranked at neutral, not last.

    Ranking the unknown last is how a table that has learned a lot stops finding
    out about the rewrites it never reached.
    """

    def test_an_untried_rewrite_beats_one_that_was_refused(self):
        table_ = table()
        table_.punish("probe", ("null-byte",), amount=1.0)
        ordered = table_.rank("probe", [Trail(("null-byte",), 1), Trail(("octal",), 1)])
        self.assertEqual(ordered[0].mutators, ("octal",))

    def test_a_rewrite_seen_to_work_still_leads_an_untried_one(self):
        # The frontier is not more valuable than something already proved. It is
        # only more valuable than something already ruled out.
        table_ = table()
        table_.reward("probe", ("upper",), amount=1.0)
        ordered = table_.rank("probe", [Trail(("upper",), 1), Trail(("octal",), 1)])
        self.assertEqual(ordered[0].mutators, ("upper",))

    def test_generation_zero_still_leads_everything(self):
        table_ = table()
        table_.reward("probe", ("upper",), amount=1.0)
        plain = Trail((), generation=0)
        ordered = table_.rank("probe", [Trail(("upper",), 1), plain, Trail(("octal",), 1)])
        self.assertEqual(ordered[0].mutators, ())

    def test_among_tried_rewrites_weight_still_decides(self):
        table_ = table()
        table_.reward("probe", ("upper",), amount=1.0)
        table_.punish("probe", ("rots13",), amount=1.0)
        ordered = table_.rank("probe", [Trail(("rots13",), 1), Trail(("upper",), 1)])
        self.assertEqual(ordered[0].mutators, ("upper",))

    def test_a_disabled_table_keeps_the_order_it_was_given(self):
        table_ = PheromoneTable(path="", enabled=False)
        items = [Trail(("upper",), 1), Trail(("octal",), 1)]
        self.assertEqual(
            [v.mutators for v in table_.rank("probe", items)], [("upper",), ("octal",)]
        )


class WhatTheEngineDoesWithIt(unittest.TestCase):
    """The run that found nothing is the one that calls for recalibration."""

    def engine(self, table_, board, said=None):
        from injectorkit.engine.statemachine import Engine, RunContext

        ctx = RunContext(
            graph=SimpleNamespace(start="s"),
            transport=None,
            blackboard=board,
            pheromone=table_,
            info=(said.append if said is not None else None),
            max_requests=400,
        )
        return Engine(SimpleNamespace(start="s"), ctx)

    def test_a_finding_cancels_it(self):
        table_ = table()
        table_.reward("probe", ("upper",), amount=1.0)
        before = table_.weight("probe", ("upper",))

        board = Blackboard(target="t")
        board.add("proven", True, evidence="something worked")
        for _ in range(200):
            board.count_request()

        self.engine(table_, board)._recalibrate_if_barren()
        # Not exact: reading a weight evaporates it by however much time passed.
        self.assertAlmostEqual(table_.weight("probe", ("upper",)), before, places=5)

    def test_a_short_run_says_nothing(self):
        table_ = table()
        table_.reward("probe", ("upper",), amount=1.0)
        before = table_.weight("probe", ("upper",))
        board = Blackboard(target="t")
        board.count_request()

        self.engine(table_, board)._recalibrate_if_barren()
        self.assertAlmostEqual(table_.weight("probe", ("upper",)), before, places=5)

    def test_a_long_barren_run_moves_the_table(self):
        table_ = table()
        table_.reward("probe", ("upper",), amount=1.0)
        before = table_.weight("probe", ("upper",))
        board = Blackboard(target="t")
        for _ in range(200):
            board.count_request()

        said: list[str] = []
        self.engine(table_, board, said)._recalibrate_if_barren()
        self.assertLess(table_.weight("probe", ("upper",)), before)
        self.assertTrue(any("recalibrating" in line for line in said))


if __name__ == "__main__":
    unittest.main()
