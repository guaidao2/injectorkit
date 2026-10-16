"""Pieces the deserialization chains are built out of.

Each of these is a judgement that was wrong at least once while the chains were
being written, and they are the kind of wrong that looks right: a cookie merged
twice, a candidate list ordered so the working directory comes last, a gadget's
side effect credited to the wrong evidence.
"""

from __future__ import annotations

import unittest

from injectorkit.engine.sessionsink import (
    candidates as session_candidates,
    looks_like_session_data,
    looks_missing,
    progress_request,
    session_from_response,
    session_id_from_cookie,
)
from injectorkit.engine.transport import merge_cookies
from injectorkit.engine.unserializesink import (
    looks_like_unserialize_error,
    junk_survived,
)
from injectorkit.engine.webroot import RootGuess, Roots, webroot_from_config
from injectorkit.modules.proto.deserialize import (
    Gadget,
    directory_of,
    served_at,
    write_targets,
)


class TheCookiesThatGoOnTheWire(unittest.TestCase):
    """The operator's session joins the request's own without displacing it."""

    def test_a_request_with_no_cookie_takes_the_operators(self):
        self.assertEqual(merge_cookies("", "prefs=x"), "prefs=x")

    def test_a_request_cookie_is_kept(self):
        merged = merge_cookies("csrf=abc", "prefs=x")
        self.assertIn("csrf=abc", merged)
        self.assertIn("prefs=x", merged)

    def test_a_name_already_present_is_not_added_again(self):
        # The target request now carries the operator's cookie so that it can be
        # injected into; appending it a second time puts it on the wire twice and
        # leaves which one wins to the server.
        self.assertEqual(merge_cookies("prefs=x", "prefs=x"), "prefs=x")

    def test_the_requests_own_value_wins(self):
        # The injected value lives in the request. A command-line default must
        # not overwrite it, or the payload never reaches the target.
        self.assertEqual(merge_cookies("prefs=INJECTED", "prefs=default"), "prefs=INJECTED")

    def test_names_are_compared_without_case(self):
        self.assertEqual(merge_cookies("Prefs=x", "prefs=y"), "Prefs=x")

    def test_the_new_cookie_is_still_added_when_one_name_exists(self):
        merged = merge_cookies("prefs=x", "csrftoken=abc")
        self.assertIn("prefs=x", merged)
        self.assertIn("csrftoken=abc", merged)

    def test_an_empty_addition_changes_nothing(self):
        self.assertEqual(merge_cookies("prefs=x", ""), "prefs=x")


class TellingAnUnserializedValueFromAnEchoedOne(unittest.TestCase):
    """The junk test, which needs no error display to work."""

    def test_the_junk_going_missing_is_the_signal(self):
        body = "preferences loaded\nikabc123\n"
        self.assertTrue(junk_survived(body, "ikabc123", "IKTAIL999"))

    def test_the_junk_still_there_means_it_was_only_echoed(self):
        body = 's:8:"ikabc123";IKTAIL999'
        self.assertFalse(junk_survived(body, "ikabc123", "IKTAIL999"))

    def test_a_marker_that_never_came_back_says_nothing(self):
        self.assertFalse(junk_survived("a page", "ikabc123", "IKTAIL999"))

    def test_an_empty_body_says_nothing(self):
        self.assertFalse(junk_survived("", "ikabc123", "IKTAIL999"))


class PhpsOwnComplaint(unittest.TestCase):
    def test_the_live_message_is_read(self):
        found = looks_like_unserialize_error(
            "Warning: unserialize(): Error at offset 18 of 18 bytes in /var/www/index.php"
        )
        self.assertIn("unserialize", found.lower())

    def test_a_page_that_merely_mentions_the_word_is_not_evidence(self):
        # An article about unserialize is not a call to it.
        self.assertEqual(looks_like_unserialize_error("a blog post about unserialize"), "")

    def test_an_unrelated_error_is_not_evidence(self):
        self.assertEqual(looks_like_unserialize_error("Warning: include(): failed"), "")


class WhereTheGadgetIsAskedToWrite(unittest.TestCase):
    def test_the_upload_directory_comes_before_the_root(self):
        roots = [RootGuess(path="/var/www/html", source="seen", observed=True)]
        targets = write_targets(roots, upload_dir="uploads")
        self.assertEqual(targets[0], "/var/www/html/uploads/")

    def test_the_root_is_tried_when_no_upload_directory_is_known(self):
        roots = [RootGuess(path="/var/www/html", source="stock", observed=False)]
        self.assertIn("/var/www/html/", write_targets(roots))

    def test_a_directory_the_server_named_comes_first(self):
        roots = Roots()
        roots.add("/var/www/html", "stock")
        roots.add("/opt/app/www", "configuration", observed=True, first=True)
        self.assertEqual(roots.best().path, "/opt/app/www")

    def test_every_root_contributes(self):
        roots = [
            RootGuess(path="/var/www/html", source="stock"),
            RootGuess(path="/srv/www", source="stock"),
        ]
        targets = write_targets(roots, upload_dir="uploads")
        self.assertIn("/var/www/html/uploads/", targets)
        self.assertIn("/srv/www/uploads/", targets)

    def test_the_url_drops_the_web_root(self):
        self.assertEqual(served_at("/var/www/html/uploads/", "/var/www/html", "x.txt"), "/uploads/x.txt")

    def test_a_file_in_the_root_is_served_at_its_name(self):
        self.assertEqual(served_at("/var/www/html/", "/var/www/html", "x.txt"), "/x.txt")

    def test_the_directory_an_upload_named_is_readable(self):
        self.assertEqual(directory_of("uploads/abc.phar"), "uploads")

    def test_an_absolute_path_names_no_relative_directory(self):
        self.assertEqual(directory_of("/var/www/html/uploads/abc.phar"), "")


class WhatTheServerSaysItServes(unittest.TestCase):
    def test_an_apache_vhost_is_read(self):
        found = webroot_from_config("    DocumentRoot /opt/injectorkit-lab/www\n")
        self.assertEqual(found, ["/opt/injectorkit-lab/www"])

    def test_an_nginx_root_directive_is_read(self):
        found = webroot_from_config("server {\n    root /var/www/html;\n}\n")
        self.assertEqual(found, ["/var/www/html"])

    def test_a_comment_is_not_a_directive(self):
        # `# root /var/www` is somebody's note, not the server's configuration.
        found = webroot_from_config("# DocumentRoot /nope\n")
        self.assertEqual(found, [])

    def test_a_page_with_no_directive_says_nothing(self):
        self.assertEqual(webroot_from_config("<html>hello</html>"), [])

    def test_only_the_path_is_taken_and_not_the_punctuation(self):
        found = webroot_from_config("    root /srv/site;\n")
        self.assertEqual(found, ["/srv/site"])


class TheGadgetItself(unittest.TestCase):
    def test_a_gadget_needs_a_class(self):
        self.assertFalse(Gadget().usable)

    def test_a_gadget_with_a_class_is_usable(self):
        self.assertTrue(Gadget(class_name="Cache").usable)

    def test_properties_start_empty_rather_than_missing(self):
        self.assertEqual(Gadget(class_name="Cache").properties, {})


class TheSessionCookie(unittest.TestCase):
    """Which cookie is the session, read from what the target says."""

    def _response(self, header: str):
        class Response:
            headers = type("H", (), {"get": staticmethod(lambda name: header)})()

        return Response()

    def test_the_session_cookie_is_read(self):
        found = session_from_response(self._response("PHPSESSID=abc123; path=/; HttpOnly"))
        self.assertEqual(found, ("PHPSESSID", "abc123"))

    def test_a_cookie_that_is_not_a_session_is_skipped(self):
        self.assertEqual(session_from_response(self._response("csrf=abc123; path=/")), ("", ""))

    def test_a_value_that_cannot_be_a_filename_is_refused(self):
        # Naming a file after this would produce a path that names nothing.
        found = session_from_response(self._response("PHPSESSID=a/b../c; path=/"))
        self.assertEqual(found, ("", ""))

    def test_the_operators_own_cookie_is_read(self):
        self.assertEqual(session_id_from_cookie("csrf=1; PHPSESSID=deadbeef"), ("PHPSESSID", "deadbeef"))

    def test_a_cookie_header_with_no_session_gives_nothing(self):
        self.assertEqual(session_id_from_cookie("csrf=1; theme=dark"), ("", ""))

    def test_the_file_is_named_for_the_id(self):
        self.assertEqual(
            session_candidates(["/var/lib/php/sessions"], "abc123"),
            ["/var/lib/php/sessions/sess_abc123"],
        )


class TellingASessionFileFromAPage(unittest.TestCase):
    def test_a_php_handler_entry_is_recognised(self):
        self.assertTrue(looks_like_session_data("seen|i:3;prefs|s:4:\"dark\";"))

    def test_a_page_with_a_pipe_in_it_is_not_a_session_file(self):
        self.assertFalse(looks_like_session_data("<html>a | b</html>"))

    def test_an_empty_body_is_not_evidence(self):
        self.assertFalse(looks_like_session_data(""))

    def test_phis_own_wording_says_the_file_was_not_there(self):
        # An empty session file and a missing one both answer with little; only
        # one of them comes with PHP saying it could not open it.
        body = "Warning: include(/var/lib/php/sessions/sess_x): failed to open stream"
        self.assertTrue(looks_missing(body))

    def test_an_empty_answer_is_not_a_missing_file(self):
        self.assertFalse(looks_missing(""))


class TheProgressRequest(unittest.TestCase):
    """The request the standard session delivery sends."""

    def _request(self):
        return progress_request(
            "http://target/prefs.php", "abc123", "PHPSESSID", '|O:8:"stdClass":0:{}', size=32
        )

    def test_it_names_the_field_php_looks_for(self):
        self.assertIn("PHP_SESSION_UPLOAD_PROGRESS", self._request().body.decode("latin-1"))

    def test_it_carries_a_file_so_the_upload_is_tracked(self):
        self.assertIn('filename="ik.bin"', self._request().body.decode("latin-1"))

    def test_it_names_the_session_the_operator_chose(self):
        self.assertEqual(self._request().headers.get("Cookie"), "PHPSESSID=abc123")

    def test_it_is_a_post_with_a_multipart_boundary(self):
        request = self._request()
        self.assertEqual(request.method, "POST")
        self.assertIn("multipart/form-data", request.headers.get("Content-Type") or "")

    def test_the_payload_is_in_the_body(self):
        self.assertIn('|O:8:"stdClass":0:{}', self._request().body.decode("latin-1"))


if __name__ == "__main__":
    unittest.main()
