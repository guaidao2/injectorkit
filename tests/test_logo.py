"""The banner: it has to fit.

An ASCII banner wider than the terminal wraps and turns into noise, and one with
trailing whitespace fills a file with spaces. Both are checked, along with the
things it is there to say.
"""

from __future__ import annotations

import unittest

from injectorkit import logo

# A terminal is eighty columns unless someone says otherwise.
TERMINAL_WIDTH = 80


class Shape(unittest.TestCase):
    def test_the_art_fits_a_terminal(self):
        self.assertLessEqual(logo.width(), TERMINAL_WIDTH)

    def test_no_row_has_trailing_whitespace(self):
        # figlet output arrives padded to a rectangle; the padding is noise.
        for row in logo.rows():
            self.assertEqual(row, row.rstrip(), repr(row))

    def test_the_art_is_plain_ascii(self):
        for row in logo.rows():
            row.encode("ascii")

    def test_there_is_more_than_one_row(self):
        self.assertGreater(len(logo.rows()), 3)


class Content(unittest.TestCase):
    def banner(self) -> str:
        return logo.banner("v1.2.3")

    def test_the_version_is_shown(self):
        self.assertIn("v1.2.3", self.banner())

    def test_the_tagline_is_shown(self):
        self.assertIn(logo.TAGLINE, self.banner())

    def test_the_project_url_is_shown(self):
        self.assertIn(logo.PROJECT, self.banner())

    def test_the_authors_are_shown_in_order(self):
        # coolmoon first, guaidao2 second, as the project credits say - checked
        # within the author part of the line, since the URL to its left already
        # names guaidao2.
        authors_line = next(line for line in self.banner().split("\n") if "coolmoon" in line)
        authors_part = authors_line[authors_line.index("coolmoon"):]
        self.assertIn("guaidao2", authors_part)

    def test_the_widest_line_still_fits(self):
        widest = max(len(line) for line in self.banner().split("\n"))
        self.assertLessEqual(widest, TERMINAL_WIDTH)

    def test_no_line_of_the_banner_is_padded(self):
        for line in self.banner().split("\n"):
            self.assertEqual(line, line.rstrip())


class Colouring(unittest.TestCase):
    def test_a_paint_function_is_used_when_given(self):
        seen = []

        def paint(text, name):
            seen.append(name)
            return f"<{name}>{text}"

        rendered = logo.banner("v1", paint)
        self.assertIn("<title>", rendered)
        self.assertIn("title", seen)

    def test_without_one_the_banner_is_plain_text(self):
        self.assertNotIn("\x1b", logo.banner("v1"))


if __name__ == "__main__":
    unittest.main()
