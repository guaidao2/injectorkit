"""Colour, and the rule that keeps it out of a pipe.

The output of a scan is data first and presentation second: a run that pipes into
grep must not have escape sequences in it, and a run a person is watching should
be readable. Both halves are checked here, along with the indentation trap that
made every finding come out grey the first time.
"""

from __future__ import annotations

import io
import os
import unittest
from unittest import mock

from injectorkit.engine import style


class TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


ESC = "\x1b"


class Enabled(unittest.TestCase):
    def test_never_is_off(self):
        self.assertFalse(style.enabled("never", TTY()))

    def test_always_is_on(self):
        self.assertTrue(style.enabled("always", io.StringIO()))

    @mock.patch.dict(os.environ)
    def test_auto_follows_the_stream(self):
        # The environment this suite runs in may itself set NO_COLOR, so the
        # variable is cleared for the duration rather than assumed absent.
        os.environ.pop("NO_COLOR", None)
        self.assertTrue(style.enabled("auto", TTY()))
        self.assertFalse(style.enabled("auto", io.StringIO()))

    def test_a_stream_without_isatty_is_treated_as_not_a_terminal(self):
        class Odd:
            pass

        self.assertFalse(style.enabled("auto", Odd()))

    def test_an_explicit_request_beats_the_environment(self):
        # NO_COLOR is a default for sessions that cannot use colour; a person
        # typing --color always is saying something more specific.
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertTrue(style.enabled("always", io.StringIO()))

    def test_no_color_is_honoured_in_the_automatic_case(self):
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(style.enabled("auto", TTY()))


class Painting(unittest.TestCase):
    def test_painting_wraps_and_resets(self):
        self.assertEqual(style.paint("x", "finding", True), f"{ESC}[32mx{ESC}[0m")

    def test_painting_is_a_no_op_when_disabled(self):
        self.assertEqual(style.paint("x", "finding", False), "x")

    def test_an_unknown_style_is_left_alone(self):
        self.assertEqual(style.paint("x", "nonsense", True), "x")


class LineStyling(unittest.TestCase):
    def test_a_finding_is_coloured(self):
        self.assertIn(ESC, style.style_line("  [!] something was proved", True))

    def test_an_indented_line_is_recognised(self):
        # Findings are printed with two leading spaces. Matching the prefix
        # against the raw line instead of the stripped one sends every finding
        # down the fallback path, where it is coloured as board detail.
        coloured = style.style_line("  [!] something was proved", True)
        self.assertIn(style.STYLES["finding"], coloured)

    def test_an_execution_is_emphasised_over_a_finding(self):
        finding = style.style_line("[!] a", True)
        execution = style.style_line("[+] b", True)
        self.assertIn(style.STYLES["execute"], execution)
        self.assertNotEqual(finding, execution)

    def test_a_refusal_is_coloured_differently_from_a_result(self):
        self.assertIn(style.STYLES["filter"], style.style_line("  filter: 3 requests were refused", True))

    def test_a_confidence_marker_is_picked_out_of_a_board_line(self):
        coloured = style.style_line("  ssrf.channel = 'oob' [likely]", True)
        self.assertIn(ESC, coloured)
        self.assertIn("ssrf.channel", coloured.replace(ESC, ""))

    def test_the_two_closing_headings_are_styled(self):
        self.assertIn(ESC, style.style_line("closed paths:", True))
        self.assertIn(ESC, style.style_line("not covered:", True))

    def test_nothing_is_added_when_disabled(self):
        line = "  [!] something was proved"
        self.assertEqual(style.style_line(line, False), line)

    def test_plain_text_passes_through_untouched(self):
        line = "  probe.remote: no listener was given"
        self.assertEqual(style.style_line(line, True), line)


class StrippedOutputIsIdentical(unittest.TestCase):
    def test_removing_the_escapes_gives_the_original_line(self):
        line = "  [!] aws-iam via query:url: signature present"
        coloured = style.style_line(line, True)
        self.assertEqual(coloured.replace(ESC, "").replace("[32m", "").replace("[0m", "").replace("[2m", ""), line)


if __name__ == "__main__":
    unittest.main()
