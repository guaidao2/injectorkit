"""What the filter did, kept apart from what the target did.

The distinction the engine turns on is between "the target answered" and "the
request never arrived". Both look like a failure from the outside, and only one
of them is a statement about the target.
"""

from __future__ import annotations

import unittest

from injectorkit.core.httpmsg import Headers, Response
from injectorkit.engine.blackboard import Blackboard
from injectorkit.engine.bypass import Bypass, FilterProfile

REFUSAL = b"Request blocked: the parameter you supplied is not allowed (lab-waf)"


def refused(status: int = 403, body: bytes = REFUSAL, headers: Headers | None = None) -> Response:
    return Response(status=status, headers=headers or Headers(), body=body)


def answered(body: bytes = b"ok") -> Response:
    return Response(status=200, headers=Headers(), body=body)


class Profile(unittest.TestCase):
    def test_a_fresh_profile_is_not_protected(self):
        self.assertFalse(FilterProfile(host="t").protected)

    def test_two_refusals_mark_it_protected(self):
        # One refusal can be an accident; two is a filter deciding, and the
        # threshold is deliberate - a single rejected probe should not be read
        # as "this target is protected".
        board = Bypass(Blackboard())
        board.observe("t", "probe.metadata", refused())
        self.assertFalse(board.profile("t").protected)
        board.observe("t", "probe.metadata", refused())
        self.assertTrue(board.profile("t").protected)

    def test_a_named_vendor_is_enough_on_its_own(self):
        board = Bypass(Blackboard())
        board.profile("t").vendor = "lab-waf"
        self.assertTrue(board.profile("t").protected)

    def test_the_floor_starts_at_zero_and_rises(self):
        board = Bypass(Blackboard())
        self.assertEqual(board.floor("t", "probe.metadata"), 0)
        board.raise_floor("t", "probe.metadata", 2)
        self.assertEqual(board.floor("t", "probe.metadata"), 2)

    def test_the_floor_is_per_action(self):
        board = Bypass(Blackboard())
        board.raise_floor("t", "probe.metadata", 2)
        self.assertEqual(board.floor("t", "probe.file"), 0)


class Refusals(unittest.TestCase):
    def test_a_block_page_counts_as_a_refusal(self):
        board = Bypass(Blackboard())
        self.assertTrue(board.observe("t", "probe.metadata", refused()))

    def test_a_normal_answer_does_not(self):
        board = Bypass(Blackboard())
        self.assertFalse(board.observe("t", "probe.metadata", answered()))

    def test_refusals_are_counted(self):
        board = Bypass(Blackboard())
        board.observe("t", "probe.metadata", refused())
        board.observe("t", "probe.file", refused())
        self.assertEqual(board.refusals(), 2)

    def test_an_origin_error_is_not_a_refusal(self):
        # A 500 is the application breaking, not a filter deciding.
        board = Bypass(Blackboard())
        self.assertFalse(board.observe("t", "probe.metadata", refused(status=500, body=b"boom")))

    def test_a_connection_error_is_not_a_refusal(self):
        board = Bypass(Blackboard())
        self.assertFalse(board.observe("t", "probe.metadata", Response(status=0, error="connection refused")))

    def test_blocked_families_report_the_scopes_seen(self):
        # A family is called closed when rewrites in it have been marked dead,
        # not merely when something was refused.
        board = Bypass(Blackboard())
        board.mark_mutator_dead("t", "probe.metadata", "host-decimal", scope="gopher:ip")
        board.mark_mutator_dead("t", "probe.metadata", "host-octal", scope="gopher:ip")
        board.mark_mutator_dead("t", "probe.metadata", "upper-scheme", scope="http:name")
        families = board.blocked_families()
        self.assertEqual(families.get("gopher:ip"), 2)
        self.assertEqual(families.get("http:name"), 1)


class FailedRewrites(unittest.TestCase):
    def test_a_rewrite_marked_dead_stays_dead(self):
        board = Bypass(Blackboard())
        self.assertFalse(board.mutator_dead("t", "probe.metadata", "host-decimal"))
        board.mark_mutator_dead("t", "probe.metadata", "host-decimal")
        self.assertTrue(board.mutator_dead("t", "probe.metadata", "host-decimal"))

    def test_dead_markers_are_scoped(self):
        # A blocklist matches literals, so a rewrite that failed for one payload
        # family says nothing about another. Sharing the marker wipes out whole
        # families of probes after a single refusal.
        board = Bypass(Blackboard())
        board.mark_mutator_dead("t", "probe.metadata", "host-decimal", scope="gopher:ip")
        self.assertTrue(board.mutator_dead("t", "probe.metadata", "host-decimal", scope="gopher:ip"))
        self.assertFalse(board.mutator_dead("t", "probe.metadata", "host-decimal", scope="http:name"))


class Disabled(unittest.TestCase):
    def test_a_disabled_tracker_never_raises_the_floor(self):
        # --no-bypass means the run does not climb the ladder, not that it stops
        # looking: the refusals are still worth reporting.
        board = Bypass(Blackboard(), enabled=False)
        board.observe("t", "probe.metadata", refused())
        board.raise_floor("t", "probe.metadata", 3)
        self.assertEqual(board.floor("t", "probe.metadata"), 0)


class Summary(unittest.TestCase):
    def test_the_summary_mentions_the_count(self):
        board = Bypass(Blackboard())
        board.observe("t", "probe.metadata", refused())
        board.observe("t", "probe.file", refused())
        self.assertIn("2", board.summarise())


if __name__ == "__main__":
    unittest.main()
