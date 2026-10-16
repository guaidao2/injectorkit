"""Cross-target priors: they reorder attempts, they never filter them.

The rules that keep this from doing harm are the ones worth testing. A prior
that drops a variant is a prior that hides a finding, and a prior that rewards
"the request was not refused" teaches the table to prefer a quiet failure.
"""

from __future__ import annotations

import time
import unittest

from injectorkit.core.mutate import Variant
from injectorkit.engine.pheromone import NEUTRAL, PheromoneTable


def table(**kwargs) -> PheromoneTable:
    options = {"path": "", "enabled": True, "half_life": 3600.0}
    options.update(kwargs)
    return PheromoneTable(**options)


class Weight(unittest.TestCase):
    def test_an_unknown_rewrite_is_neutral(self):
        self.assertEqual(table().weight("http:ip", ("host-decimal",)), NEUTRAL)

    def test_an_empty_rewrite_list_is_neutral(self):
        self.assertEqual(table().weight("http:ip", ()), NEUTRAL)

    def test_a_reward_raises_the_weight(self):
        board = table()
        board.reward("http:ip", ("host-decimal",))
        self.assertGreater(board.weight("http:ip", ("host-decimal",)), NEUTRAL)

    def test_a_penalty_lowers_the_weight(self):
        board = table()
        board.punish("http:ip", ("host-decimal",))
        self.assertLess(board.weight("http:ip", ("host-decimal",)), NEUTRAL)

    def test_trails_are_scoped_to_their_family(self):
        board = table()
        board.reward("http:ip", ("host-decimal",))
        self.assertEqual(board.weight("gopher:ip", ("host-decimal",)), NEUTRAL)

    def test_trails_are_scoped_to_their_rewrite(self):
        board = table()
        board.reward("http:ip", ("host-decimal",))
        self.assertEqual(board.weight("http:ip", ("host-octal",)), NEUTRAL)


class Evaporation(unittest.TestCase):
    def test_a_verdict_fades_back_towards_neutral(self):
        board = table(half_life=10.0)
        board.reward("http:ip", ("host-decimal",))
        raised = board.weight("http:ip", ("host-decimal",))
        board.trails["http:ip|host-decimal"].updated = time.time() - 10.0
        faded = board.weight("http:ip", ("host-decimal",))
        self.assertLess(faded, raised)
        self.assertGreater(faded, NEUTRAL)

    def test_enough_time_returns_it_to_neutral(self):
        board = table(half_life=1.0)
        board.reward("http:ip", ("host-decimal",))
        board.trails["http:ip|host-decimal"].updated = time.time() - 3600.0
        self.assertAlmostEqual(board.weight("http:ip", ("host-decimal",)), NEUTRAL, places=3)

    def test_a_penalty_fades_out_the_same_way(self):
        board = table(half_life=1.0)
        board.punish("http:ip", ("host-decimal",))
        board.trails["http:ip|host-decimal"].updated = time.time() - 3600.0
        self.assertAlmostEqual(board.weight("http:ip", ("host-decimal",)), NEUTRAL, places=3)


class Ranking(unittest.TestCase):
    def test_a_known_good_rewrite_comes_before_a_known_bad_one(self):
        board = table()
        board.reward("http:ip", ("host-decimal",))
        board.punish("http:ip", ("host-octal",))
        good = Variant(value="good", generation=0, mutators=("host-decimal",))
        bad = Variant(value="bad", generation=0, mutators=("host-octal",))
        self.assertEqual(board.rank("http:ip", [bad, good])[0].mutators, ("host-decimal",))

    def test_the_unmodified_variant_keeps_the_front_place(self):
        # Generation 0 is the original value. An unprotected target must never be
        # sent a mutation first, whatever the table learned somewhere else.
        board = table()
        board.reward("http:ip", ("host-decimal",))
        plain = Variant(value="plain", generation=0)
        decimal = Variant(value="decimal", generation=0, mutators=("host-decimal",))
        self.assertEqual(board.rank("http:ip", [decimal, plain])[0].mutators, ())

    def test_everything_is_still_returned(self):
        # Ordering is the whole job: nothing may be dropped.
        board = table()
        board.punish("http:ip", ("host-decimal",))
        variants = [
            Variant(value="a", generation=0),
            Variant(value="b", generation=0, mutators=("host-decimal",)),
            Variant(value="c", generation=0, mutators=("host-octal",)),
        ]
        self.assertEqual(len(board.rank("http:ip", variants)), len(variants))

    def test_order_is_unchanged_when_nothing_is_known_yet(self):
        board = table()
        variants = [Variant(value="a", generation=0), Variant(value="b", generation=0)]
        self.assertEqual([item.value for item in board.rank("http:ip", variants)], ["a", "b"])


class Disabled(unittest.TestCase):
    def test_a_disabled_table_changes_nothing(self):
        board = table(enabled=False)
        board.reward("http:ip", ("host-decimal",))
        self.assertEqual(board.weight("http:ip", ("host-decimal",)), NEUTRAL)


class Keys(unittest.TestCase):
    def test_the_key_names_the_family_and_the_rewrites(self):
        self.assertEqual(PheromoneTable.key("http:ip", ("a", "b")), "http:ip|a+b")

    def test_an_empty_rewrite_list_has_no_key(self):
        self.assertEqual(PheromoneTable.key("http:ip", ()), "")


if __name__ == "__main__":
    unittest.main()
