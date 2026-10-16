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


class AFileThatWasRead(unittest.TestCase):
    """A read is the answer, so it is shown as one - at the end, and once.

    `--read FILE` is the whole point of a run: the operator named a file and the
    content is what they asked for. It belongs with the results, not in the
    middle of the progress lines, and not once for every wrapper that turned out
    to reach it.
    """

    def board(self) -> Blackboard:
        from injectorkit.engine.blackboard import READ_FACT_PREFIX

        board = Blackboard(target="t")
        board.set(
            READ_FACT_PREFIX + "/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\n",
            evidence="kept so a later run need not ask again",
            confidence=Confidence.CONFIRMED,
        )
        return board

    def test_the_file_is_shown_with_the_results(self):
        block = self.board().render_findings()
        self.assertIn("Files read:", block)
        self.assertIn("root:x:0:0:root:/root:/bin/bash", block)

    def test_the_file_is_not_also_a_python_literal_in_the_summary(self):
        rendered = self.board().render()
        self.assertNotIn("read.file.", rendered)
        self.assertNotIn("root:x:0:0", rendered)

    def test_a_file_is_listed_once_however_it_was_reached(self):
        self.assertEqual(len(self.board().reads()), 1)

    def test_an_empty_file_is_still_a_result(self):
        # "I read it and there is nothing in it" is an answer to what was asked.
        # Dropping it is how the operator gets silence and cannot tell it from a
        # read that never happened.
        board = Blackboard(target="t")
        board.set("read.file./empty", "", evidence="read", confidence=Confidence.CONFIRMED)
        self.assertEqual(board.reads(), [("/empty", "")])
        block = board.render_findings()
        self.assertIn("Files read:", block)
        self.assertIn("(the file is empty)", block)

    def test_a_file_is_still_listed_after_a_session_is_reloaded(self):
        board = Blackboard.from_json(self.board().to_json())
        self.assertIn("Files read:", board.render_findings())
        self.assertIn("root:x:0:0", board.render_findings())

    def test_only_the_first_lines_are_printed(self):
        from injectorkit.engine.blackboard import READ_LINES, READ_FACT_PREFIX

        board = Blackboard(target="t")
        body = "\n".join(f"line {number}" for number in range(READ_LINES + 12))
        board.set(READ_FACT_PREFIX + "/big", body, evidence="long", confidence=Confidence.CONFIRMED)
        block = board.render_findings()
        self.assertIn("line 0", block)
        self.assertIn("12 more line(s)", block)

    def test_a_board_with_neither_findings_nor_reads_renders_nothing(self):
        self.assertEqual(Blackboard(target="t").render_findings(), "")


class ACommandThatWasRun(unittest.TestCase):
    """The output of a command is a result, and results go at the end, once.

    `--os-cmd` and `--os-shell` exist to run something on the target and show
    what came back. Printing it among the progress lines scatters the answer up
    the screen; printing it here puts it where the findings are, which is where
    somebody looks when the run stops.
    """

    def test_the_output_is_shown_with_the_results(self):
        board = Blackboard(target="t")
        board.remember_run("id", "uid=33(www-data) gid=33(www-data)\n")
        block = board.render_findings()
        self.assertIn("Commands run:", block)
        self.assertIn("id", block)
        self.assertIn("uid=33(www-data)", block)

    def test_it_is_not_also_a_python_literal_in_the_summary(self):
        board = Blackboard(target="t")
        board.remember_run("id", "uid=33(www-data)\n")
        self.assertNotIn("run.command.", board.render())

    def test_running_the_same_command_twice_shows_it_once(self):
        board = Blackboard(target="t")
        board.remember_run("id", "first\n")
        board.remember_run("id", "second\n")
        self.assertEqual(len(board.runs()), 1)
        self.assertIn("second", board.render_findings())

    def test_a_command_with_no_output_says_so(self):
        board = Blackboard(target="t")
        board.remember_run("true", "")
        self.assertIn("(no output)", board.render_findings())

    def test_it_survives_a_session_reload(self):
        board = Blackboard(target="t")
        board.remember_run("id", "uid=33(www-data)\n")
        reloaded = Blackboard.from_json(board.to_json())
        self.assertIn("uid=33(www-data)", reloaded.render_findings())

    def test_a_commandless_board_renders_nothing(self):
        self.assertEqual(Blackboard(target="t").render_findings(), "")


class WhatIsSettledAndWhatIsATodo(unittest.TestCase):
    """A dead end is a verdict; "not covered" is a question that can be reopened.

    Both stop a retry, but they are not the same thing: "the target refused it"
    stays true, and "there was no listener when it ran" stops being true the
    moment the operator passes one. Conflating them is how an action gets pruned
    forever by a reason the next invocation has already answered.
    """

    def test_a_dead_end_is_ruled_out(self):
        board = Blackboard(target="t")
        board.mark_dead_end("probe.remote", "the target refused it")
        self.assertTrue(board.is_ruled_out("probe.remote"))
        self.assertTrue(board.is_dead("probe.remote"))

    def test_a_missing_condition_is_not_ruled_out(self):
        board = Blackboard(target="t")
        board.mark_not_covered("probe.remote", "no listener was given")
        self.assertFalse(board.is_ruled_out("probe.remote"))
        self.assertTrue(board.is_dead("probe.remote"), "it is still an open question")

    def test_a_todo_can_be_taken_back(self):
        board = Blackboard(target="t")
        board.mark_not_covered("probe.remote", "no listener was given")
        board.forget_not_covered("probe.remote")
        self.assertNotIn("probe.remote", board.not_covered)
        self.assertFalse(board.is_dead("probe.remote"))

    def test_taking_back_something_that_was_never_there_is_harmless(self):
        board = Blackboard(target="t")
        board.forget_not_covered("never.recorded")
        self.assertEqual(board.not_covered, {})

    def test_a_dead_end_is_not_taken_back_by_forgetting_a_todo(self):
        board = Blackboard(target="t")
        board.mark_dead_end("probe.remote", "the target refused it")
        board.forget_not_covered("probe.remote")
        self.assertTrue(board.is_ruled_out("probe.remote"))


if __name__ == "__main__":
    unittest.main()
