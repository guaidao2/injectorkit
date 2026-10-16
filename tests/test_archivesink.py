"""Finding the call that opens an archive, by the error it makes.

An uploaded phar is inert on PHP 8 unless the application asks for its metadata,
so the chain needs a call site that opens an archive it was pointed at. That call
site announces itself: give it a file that is not an archive and PHP says
`Cannot create phar`, which can only come from a value reaching `new Phar(...)`.

The distinction these tests exist for is between that and an ordinary not-found.
A parameter that just gets read says the file is missing, which is not a call
site, and treating it as one aims the whole chain at the wrong place.
"""

from __future__ import annotations

import unittest

from injectorkit.engine.archivesink import (
    ArchiveSink,
    looks_like_archive_sink,
    looks_like_missing,
)

REAL_ERROR = (
    "could not load /etc/passwd: Cannot create phar '/etc/passwd', file extension "
    "(or combination) not recognised or the directory does not exist"
)


class WhatAPharConstructorSays(unittest.TestCase):
    def test_the_live_message_is_recognised(self):
        self.assertTrue(looks_like_archive_sink(REAL_ERROR))

    def test_it_does_not_have_to_match_case(self):
        self.assertTrue(looks_like_archive_sink("cannot create PHAR '/x'"))

    def test_the_reason_keeps_the_message_it_was_given(self):
        evidence = looks_like_archive_sink(REAL_ERROR)
        self.assertIn("Cannot create phar", evidence)
        self.assertLess(len(evidence), 400)

    def test_another_phar_error_is_recognised(self):
        self.assertTrue(looks_like_archive_sink("Phar Error: unable to open phar archive"))

    def test_an_ordinary_page_says_nothing(self):
        self.assertEqual(looks_like_archive_sink("<html>welcome</html>"), "")

    def test_a_missing_file_is_not_a_constructor(self):
        self.assertEqual(looks_like_archive_sink("no such config: /tmp/x.phar"), "")


class TellingTheTwoFailuresApart(unittest.TestCase):
    def test_a_not_found_is_not_a_call_site(self):
        self.assertTrue(looks_like_missing("Warning: include(/nope): failed to open stream"))
        self.assertFalse(looks_like_archive_sink("Warning: include(/nope): failed to open stream"))

    def test_the_constructor_error_is_not_read_as_a_not_found(self):
        # Both contain the word "exist"; only one is a call site, and a check
        # that matched the shared word would call every read a constructor.
        self.assertFalse(looks_like_missing(REAL_ERROR))

    def test_a_plain_page_is_neither(self):
        self.assertFalse(looks_like_missing("<html>fine</html>"))

    def test_something_that_does_not_exist_is_not_a_call_site(self):
        self.assertFalse(looks_like_archive_sink("Phar::__construct(): phar error"))


class WhatTheFindingSays(unittest.TestCase):
    def test_it_names_the_parameter(self):
        sink = ArchiveSink(param="query:config", evidence="Cannot create phar", confirmed=True)
        self.assertIn("query:config", sink.describe())
        self.assertIn("opens archives", sink.describe())

    def test_an_unconfirmed_sink_says_nothing(self):
        # Nothing to report is not the same as a finding that reads as empty.
        self.assertEqual(ArchiveSink().describe(), "")

    def test_the_evidence_is_carried_into_the_report(self):
        sink = ArchiveSink(param="q", evidence="Cannot create phar '/etc/passwd'", confirmed=True)
        self.assertIn("Cannot create phar", sink.describe())


if __name__ == "__main__":
    unittest.main()
