"""Where the web root is, worked out instead of asked for.

Asking an operator to type a path turns a tool into a form, and the path is
usually already known: any file the run read says where something is, and a
directory holding a file the application serves is a directory it can probably
write to.

The distinction these tests are mostly about is evidence against hypothesis. A
path derived from a file that was actually read is not a guess about where the
web root is - it is what that file says about it. A path from the stock list is a
guess, and a wrong one writes a file somewhere the operator will never look while
reporting success.
"""

from __future__ import annotations

import unittest

from injectorkit.engine.webroot import (
    LINUX_ROOTS,
    WINDOWS_ROOTS,
    guess_roots,
    roots_from_file,
    roots_from_marker,
)


class WalkingUpFromAFile(unittest.TestCase):
    def test_every_directory_above_the_file_is_offered(self):
        self.assertEqual(
            roots_from_file("/var/www/html/index.php"),
            ["/var/www/html", "/var/www", "/var"],
        )

    def test_the_deepest_comes_first(self):
        # A file that was read is more likely to be near what the application
        # serves than near the filesystem root.
        self.assertEqual(roots_from_file("/srv/app/public/index.php")[0], "/srv/app/public")

    def test_a_relative_path_yields_nothing(self):
        # `index.php` says nothing about where it is.
        self.assertEqual(roots_from_file("index.php"), [])

    def test_a_file_at_the_root_yields_nothing(self):
        self.assertEqual(roots_from_file("/index.php"), [])

    def test_windows_paths_keep_their_drive(self):
        self.assertEqual(
            roots_from_file("C:/xampp/htdocs/app/index.php"),
            ["C:/xampp/htdocs/app", "C:/xampp/htdocs", "C:/xampp"],
        )

    def test_backslashes_are_normalised(self):
        self.assertEqual(roots_from_file("C:\\inetpub\\wwwroot\\iisstart.htm")[0], "C:/inetpub/wwwroot")


class SplittingOnARootName(unittest.TestCase):
    """The rule sqlmap uses: a directory named `html` is where a root begins."""

    def test_html_marks_the_root(self):
        self.assertEqual(roots_from_marker("/var/www/html/config.php"), ["/var/www/html"])

    def test_htdocs_marks_the_root(self):
        self.assertEqual(roots_from_marker("/usr/local/apache2/htdocs/index.php"), ["/usr/local/apache2/htdocs"])

    def test_wwwroot_marks_the_root(self):
        self.assertEqual(roots_from_marker("C:/Inetpub/wwwroot/default.aspx"), ["C:/Inetpub/wwwroot"])

    def test_a_path_with_no_marker_yields_nothing(self):
        self.assertEqual(roots_from_marker("/etc/passwd"), [])


class ChoosingBetweenSources(unittest.TestCase):
    def test_a_file_that_was_read_beats_the_stock_list(self):
        roots = guess_roots(seen_paths=["/var/www/html/flag.php"])
        best = roots.best()
        self.assertEqual(best.path, "/var/www/html")
        self.assertTrue(best.observed)

    def test_what_the_operator_said_wins_outright(self):
        roots = guess_roots(seen_paths=["/var/www/html/flag.php"], operator_said="/srv/app/public")
        self.assertEqual(roots.best().path, "/srv/app/public")
        self.assertTrue(roots.best().observed)

    def test_the_stock_list_is_marked_as_a_guess(self):
        roots = guess_roots()
        self.assertFalse(roots.best().observed)
        self.assertIn("common location", roots.describe())

    def test_a_guess_is_replaced_by_evidence_for_the_same_path(self):
        roots = guess_roots(seen_paths=["/var/www/html/index.php"])
        matching = [g for g in roots.guesses if g.path == "/var/www/html"]
        self.assertEqual(len(matching), 1, "one path, one entry")
        self.assertTrue(matching[0].observed)

    def test_nothing_seen_still_offers_the_stock_locations(self):
        paths = guess_roots().paths()
        self.assertTrue(set(LINUX_ROOTS) <= set(paths))

    def test_windows_gets_the_windows_list(self):
        paths = guess_roots(windows=True).paths()
        self.assertTrue(set(WINDOWS_ROOTS) <= set(paths))
        self.assertNotIn("/var/www/html", paths)

    def test_the_report_says_which_kind_of_answer_it_is(self):
        observed = guess_roots(seen_paths=["/var/www/html/index.php"]).describe()
        guessed = guess_roots().describe()
        self.assertIn("was read from", observed)
        self.assertIn("common location", guessed)

    def test_nothing_at_all_says_so(self):
        # A wrong path is worse than no path: it reports success and puts the
        # file where nobody will find it.
        roots = guess_roots()
        roots.guesses.clear()
        self.assertIn("not established", roots.describe())


class WhatACommandSaid(unittest.TestCase):
    def test_a_directory_in_a_listing_is_picked_up(self):
        from injectorkit.engine.webroot import command_roots

        found = command_roots("drwxr-xr-x 2 www-data www-data 4096 /var/www/html/uploads")
        self.assertIn("/var/www/html/uploads", found)

    def test_an_environment_variable_is_picked_up(self):
        from injectorkit.engine.webroot import command_roots

        found = command_roots("DOCUMENT_ROOT=/var/www/html\nPATH=/usr/bin")
        self.assertIn("/var/www/html", found)

    def test_paths_that_are_not_a_web_root_are_left_alone(self):
        from injectorkit.engine.webroot import command_roots

        self.assertEqual(command_roots("PATH=/usr/bin:/bin\nHOME=/root"), [])

    def test_nothing_to_read(self):
        from injectorkit.engine.webroot import command_roots

        self.assertEqual(command_roots(""), [])


if __name__ == "__main__":
    unittest.main()
