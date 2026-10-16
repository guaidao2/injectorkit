"""The board: what was proved, what was ruled out, and what was never tried.

The last two are kept apart on purpose. "The request was refused" and "there was
no listener, so we never sent it" look the same in a summary that lumps them
together, and only one of them is a result.
"""

from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from injectorkit.core.httpmsg import Exchange, Headers, Request, Response
from injectorkit.engine.blackboard import Blackboard, Confidence

TMP = Path(__file__).resolve().parent / "_tmp"


class Facts(unittest.TestCase):
    def test_set_and_get(self):
        board = Blackboard(target="t")
        board.set("ssrf.runtime", "php", evidence="a wrapper worked", confidence=Confidence.CONFIRMED)
        self.assertEqual(board.get("ssrf.runtime"), "php")
        self.assertTrue(board.has("ssrf.runtime"))
        self.assertEqual(board.fact("ssrf.runtime").confidence, Confidence.CONFIRMED)

    def test_a_missing_key_returns_the_default(self):
        self.assertIsNone(Blackboard().get("nothing"))
        self.assertEqual(Blackboard().get("nothing", "fallback"), "fallback")

    def test_add_collects_without_losing_what_was_there(self):
        board = Blackboard()
        board.add("found", "a")
        board.add("found", "b")
        board.add("found", "a")
        self.assertEqual(board.get("found"), ["a", "b"])

    def test_describe_carries_the_confidence(self):
        board = Blackboard()
        board.set("k", "v", evidence="why", confidence=Confidence.LIKELY)
        self.assertIn("[likely]", board.fact("k").describe())


class SettledDoesNotMeanRuledOut(unittest.TestCase):
    def test_a_dead_end_is_reported_as_a_closed_path(self):
        board = Blackboard(target="t")
        board.mark_dead_end("probe.metadata", "request was refused")
        self.assertIn("closed paths:", board.render())
        self.assertIn("request was refused", board.render())
        self.assertNotIn("not covered:", board.render())

    def test_an_untried_path_is_reported_separately(self):
        board = Blackboard(target="t")
        board.mark_not_covered("probe.remote", "no listener was given")
        rendered = board.render()
        self.assertIn("not covered:", rendered)
        self.assertNotIn("closed paths:", rendered)

    def test_both_lists_appear_together(self):
        board = Blackboard(target="t")
        board.mark_dead_end("probe.metadata", "request was refused")
        board.mark_not_covered("probe.remote", "no listener was given")
        rendered = board.render()
        self.assertIn("closed paths:", rendered)
        self.assertIn("not covered:", rendered)

    def test_both_kinds_stop_a_retry(self):
        board = Blackboard()
        board.mark_dead_end("a", "refused")
        board.mark_not_covered("b", "no listener")
        self.assertTrue(board.is_dead("a"))
        self.assertTrue(board.is_dead("b"))
        self.assertFalse(board.is_dead("c"))


class Persistence(unittest.TestCase):
    def setUp(self):
        TMP.mkdir(exist_ok=True)
        self.path = str(TMP / "board.json")

    def tearDown(self):
        shutil.rmtree(TMP, ignore_errors=True)

    def test_facts_survive_a_round_trip(self):
        board = Blackboard(target="t")
        board.set("ssrf.channel", "out-of-band", evidence="callback", confidence=Confidence.LIKELY)
        board.save(self.path)
        again = Blackboard.load(self.path)
        self.assertEqual(again.target, "t")
        self.assertEqual(again.get("ssrf.channel"), "out-of-band")
        self.assertEqual(again.fact("ssrf.channel").confidence, Confidence.LIKELY)

    def test_dead_ends_survive_and_stay_distinct_from_untried_paths(self):
        board = Blackboard(target="t")
        board.mark_dead_end("probe.metadata", "request was refused")
        board.mark_not_covered("probe.remote", "no listener was given")
        board.save(self.path)
        again = Blackboard.load(self.path)
        self.assertIn("probe.metadata", again.dead_ends)
        self.assertIn("probe.remote", again.not_covered)
        self.assertNotIn("probe.remote", again.dead_ends)

    def test_the_file_is_json(self):
        import json

        board = Blackboard(target="t")
        board.set("k", 1)
        board.save(self.path)
        with open(self.path, encoding="utf-8") as handle:
            parsed = json.load(handle)
        self.assertEqual(parsed["target"], "t")
        self.assertIn("not_covered", parsed)


class TrafficCount(unittest.TestCase):
    def test_every_exchange_is_counted(self):
        board = Blackboard()
        exchange = Exchange(
            request=Request.from_url("http://t/"),
            response=Response(status=200, headers=Headers(), body=b""),
        )
        board.note(exchange)
        self.assertEqual(board.requests_sent(), 1)


class WhatTheSummaryShows(unittest.TestCase):
    """A summary is for reading, and a run produces two kinds of line.

    A finding is a result. "This action has been tried" is bookkeeping - it
    exists so the next run can skip this page, and printing it beside the
    findings is how a report becomes unreadable.
    """

    def board_with(self, finding_payload: str) -> Blackboard:
        board = Blackboard(target="t")
        # One dict: `add` collects values under a key, so it wraps what it is
        # given. Handing it a list would nest one inside the other and the
        # finding would not be found - which is how this test first failed.
        board.add(
            "proto.findings",
            {
                "name": "plain-system",
                "param": "body:file",
                "family": "read",
                "payload": finding_payload,
                "evidence": "signature present",
            },
            evidence="a finding",
        )
        board.add("ran.probe.read", True, evidence="tried on this page", confidence=Confidence.LIKELY)
        board.add("ran.classify", True, evidence="tried on this page", confidence=Confidence.LIKELY)
        return board

    def test_bookkeeping_stays_out_of_the_summary(self):
        rendered = self.board_with("/etc/passwd").render()
        self.assertNotIn("ran.probe.read", rendered)
        self.assertNotIn("ran.classify", rendered)
        self.assertNotIn("tried on this page", rendered)

    def test_the_finding_is_still_there(self):
        rendered = self.board_with("/etc/passwd").render()
        self.assertIn("proto.findings", rendered)

    def test_bookkeeping_can_be_asked_for(self):
        tried = self.board_with("/etc/passwd").render_bookkeeping()
        self.assertIn("probe.read", tried)
        self.assertIn("classify", tried)

    def test_a_short_payload_is_printed_in_full(self):
        # A payload somebody can retype by hand is the point of a finding.
        block = self.board_with("id=1 AND 2290=2290").render_findings()
        self.assertIn("id=1 AND 2290=2290", block)

    def test_a_generated_payload_is_summarised(self):
        # A twelve-thousand-character filter chain is rebuilt, not transcribed.
        # Printing it whole costs a screen and gives the reader nothing.
        long_payload = "php://filter/" + "convert.iconv.A.B|" * 500
        block = self.board_with(long_payload).render_findings()
        self.assertNotIn(long_payload, block)
        self.assertIn("characters in all", block)

    def test_the_summary_still_says_it_was_generated(self):
        long_payload = "php://filter/" + "convert.iconv.A.B|" * 500
        block = self.board_with(long_payload).render_findings()
        self.assertIn("php://filter/convert.iconv", block)


if __name__ == "__main__":
    unittest.main()
