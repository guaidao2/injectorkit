"""Where a run's progress is kept, and what it takes to forget it.

The point of the store is that a second scan of the same page costs less than
the first. These tests check the two things that make that true - a path derived
from the target rather than named by hand, and a way to throw it away - and the
one thing that makes it safe, which is that a store belonging to another host is
never read.
"""

from __future__ import annotations

import os
import shutil
import unittest
from urllib.parse import urlsplit

from injectorkit.engine import session

HERE = os.getcwd()
SCRATCH = os.path.join(HERE, ".tmp", "session-test")


class SessionLayout(unittest.TestCase):
    def setUp(self):
        self.saved = session.ROOT
        shutil.rmtree(SCRATCH, ignore_errors=True)
        session.ROOT = SCRATCH

    def tearDown(self):
        session.ROOT = self.saved
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def test_the_host_names_the_directory(self):
        directory = session.target_dir("https://example.test/a?b=1")
        self.assertTrue(directory.endswith("example.test"), directory)

    def test_the_path_names_the_file(self):
        path = session.session_path("https://example.test/a/b.php?x=1")
        self.assertTrue(path.endswith("a_b.php.json"), path)

    def test_a_root_path_gets_a_readable_name(self):
        self.assertTrue(session.session_path("https://example.test/").endswith("index.json"))

    def test_the_query_string_does_not_split_the_file(self):
        # Two runs against the same page with different parameters are the same
        # page; keying on the query would make every run a cold one.
        one = session.session_path("https://example.test/x?a=1")
        two = session.session_path("https://example.test/x?a=2")
        self.assertEqual(one, two)

    def test_two_hosts_never_share_a_file(self):
        one = session.session_path("https://a.test/x")
        two = session.session_path("https://b.test/x")
        self.assertNotEqual(one, two)

    def test_everything_lands_under_the_session_root(self):
        path = session.session_path("https://example.test/deep/path")
        self.assertTrue(path.startswith(SCRATCH), path)


class RoundTrip(unittest.TestCase):
    def setUp(self):
        self.saved = session.ROOT
        shutil.rmtree(SCRATCH, ignore_errors=True)
        session.ROOT = SCRATCH

    def tearDown(self):
        session.ROOT = self.saved
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def test_nothing_is_loaded_before_anything_is_saved(self):
        self.assertIsNone(session.load("https://example.test/"))

    def test_what_was_saved_comes_back(self):
        session.save("https://example.test/", '{"target": "example.test"}')
        self.assertIn("example.test", session.load("https://example.test/") or "")

    def test_saving_creates_the_directories_it_needs(self):
        self.assertTrue(session.save("https://new.test/a/b", "{}"))
        self.assertTrue(os.path.exists(session.session_path("https://new.test/a/b")))

    def test_flushing_removes_the_whole_host(self):
        session.save("https://example.test/one", "{}")
        session.save("https://example.test/two", "{}")
        self.assertTrue(session.flush("https://example.test/"))
        self.assertIsNone(session.load("https://example.test/one"))
        self.assertIsNone(session.load("https://example.test/two"))

    def test_flushing_one_host_leaves_another_alone(self):
        session.save("https://a.test/", "{}")
        session.save("https://b.test/", "{}")
        session.flush("https://a.test/")
        self.assertIsNotNone(session.load("https://b.test/"))

    def test_flushing_something_never_saved_is_not_an_error(self):
        self.assertFalse(session.flush("https://never.test/"))

    def test_a_query_string_does_not_make_a_second_store(self):
        session.save("https://example.test/x?a=1", "{}")
        self.assertIsNotNone(session.load("https://example.test/x?a=2"))


class SafeNames(unittest.TestCase):
    def test_a_host_keeps_its_dots(self):
        self.assertEqual(session._safe("example.test:8443"), "example.test_8443")

    def test_traversal_cannot_escape_the_root(self):
        for hostile in ("../../etc", "..", "/etc/passwd"):
            path = session.session_path(f"https://example.test/{hostile}")
            root = session.target_dir("https://example.test/")
            self.assertTrue(path.startswith(root), path)
            self.assertNotIn("..", path)

    def test_an_empty_path_is_named_rather_than_dropped(self):
        self.assertEqual(session._safe(""), "index")
        self.assertEqual(session._safe("/"), "index")


class WhatTheTargetsFiltersLookLike(unittest.TestCase):
    """The filter profile is bought with refused requests, so it is kept."""

    def setUp(self):
        self.saved = session.ROOT
        shutil.rmtree(SCRATCH, ignore_errors=True)
        session.ROOT = SCRATCH

    def tearDown(self):
        session.ROOT = self.saved
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def test_nothing_is_loaded_before_anything_is_saved(self):
        self.assertIsNone(session.load_filters("https://example.test/"))

    def test_what_was_saved_comes_back(self):
        session.save_filters("https://example.test/", '{"profiles": {}}')
        self.assertIn("profiles", session.load_filters("https://example.test/") or "")

    def test_it_lives_beside_the_progress_not_inside_it(self):
        # Flushing one must not take the other with it, and the page-level store
        # cannot hold something that belongs to the host.
        self.assertNotEqual(
            session.filter_path("https://example.test/"),
            session.session_path("https://example.test/"),
        )


class BypassProfileRoundTrip(unittest.TestCase):
    def bypass(self):
        from injectorkit.engine.blackboard import Blackboard
        from injectorkit.engine.bypass import Bypass

        return Bypass(Blackboard(target="example.test"))

    def test_a_profile_survives_a_round_trip(self):
        first = self.bypass()
        profile = first.profile("example.test")
        profile.refusals = 3
        profile.vendor = "somevendor"
        profile.raise_floor("probe.code", 2)
        profile.refused_values.append("gopher://127.0.0.1")

        second = self.bypass()
        self.assertEqual(second.load_json(first.to_json()), 1)

        restored = second.profile("example.test")
        self.assertEqual(restored.refusals, 3)
        self.assertEqual(restored.vendor, "somevendor")
        self.assertEqual(restored.floor("probe.code"), 2)
        self.assertIn("gopher://127.0.0.1", restored.refused_values)

    def test_a_resumed_profile_is_protected_without_earning_it_again(self):
        # Two refusals is the threshold; a run that starts from a remembered
        # profile should not have to be refused twice more to count as protected.
        first = self.bypass()
        first.profile("example.test").refusals = 2
        self.assertTrue(first.profile("example.test").protected)

        second = self.bypass()
        second.load_json(first.to_json())
        self.assertTrue(second.profile("example.test").protected)

    def test_dead_mutators_survive_too(self):
        first = self.bypass()
        first.dead_mutators["example.test|probe.code"] = {"upper"}
        second = self.bypass()
        second.load_json(first.to_json())
        self.assertIn("upper", second.dead_mutators.get("example.test|probe.code", set()))

    def test_rubbish_is_ignored_rather_than_fatal(self):
        self.assertEqual(self.bypass().load_json("not json at all"), 0)
        self.assertEqual(self.bypass().load_json("[1, 2, 3]"), 0)
        self.assertEqual(self.bypass().load_json('{"profiles": "nonsense"}'), 0)


if __name__ == "__main__":
    unittest.main()
