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


if __name__ == "__main__":
    unittest.main()
