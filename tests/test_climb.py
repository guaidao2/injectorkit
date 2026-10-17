"""Which generations the ladder climbs, and in what order.

The floor is the one piece of remembered state that could quietly remove work: it
was where the climb started, and while it was the loop's lower bound, every
generation below it went unsent. Measured against a filter that compared its
blocklist without folding case - reachable with `PHP://`, which is generation 1 -
a floor of 2 from an earlier run meant generation 1 was never sent: 164 requests,
86 refused, the read reported as not done.

Reordering the climb was not enough. The climb stops at the first generation where
a rewrite was not refused, so putting the floor's generations first only helps
while they are all refused. The order is now the plain ascent, and nothing bounds
it.
"""

from __future__ import annotations

import ast
import pathlib
import unittest

from injectorkit.engine.inject import climb_order

INJECT = pathlib.Path(__file__).resolve().parent.parent / "injectorkit" / "engine" / "inject.py"


class TheWholeLadderIsClimbed(unittest.TestCase):
    def test_generation_zero_comes_first(self):
        self.assertEqual(climb_order(3)[0], 0)

    def test_every_generation_is_in_the_order(self):
        self.assertEqual(climb_order(3), [0, 1, 2, 3])

    def test_the_generation_that_holds_the_case_rewrite_is_reachable(self):
        # `scheme-uppercase` is generation 1. Whatever else changes, a climb that
        # starts above it is the defect this file exists for.
        self.assertIn(1, climb_order(3))

    def test_nothing_is_tried_twice(self):
        order = climb_order(4)
        self.assertEqual(order, sorted(set(order)))

    def test_one_generation_still_works(self):
        self.assertEqual(climb_order(0), [0])


class NothingBoundsTheClimbFromRememberedState(unittest.TestCase):
    """A prior may order the work; it may not decide the work is unnecessary.

    The pure function above cannot catch this on its own: reverting the loop to
    `range(start, ...)` with `start = ctx.bypass.floor(...)` would leave every
    assertion about `climb_order` passing, because the bound lived in the caller.
    So the caller is checked too - the engine's own ladder must not read the floor.
    """

    def test_the_ladder_does_not_read_the_floor(self):
        tree = ast.parse(INJECT.read_text(encoding="utf-8"))
        reads = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr == "floor"
        ]
        self.assertEqual(
            reads,
            [],
            "engine/inject.py reads `floor` again; if it is used to bound the climb, "
            "a generation below it will never be sent",
        )


if __name__ == "__main__":
    unittest.main()
