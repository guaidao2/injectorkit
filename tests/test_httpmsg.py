"""Parsing rules the rest of the tool is built on.

Most of these exist because getting them wrong was expensive: the body has to
survive byte for byte, and a header written as one string has to become a pair.
"""

from __future__ import annotations

import unittest

from injectorkit.core.httpmsg import Headers, Request, Response, parse_headers


class ParseHeaderLines(unittest.TestCase):
    def test_splits_name_from_value(self):
        self.assertEqual(parse_headers(["Host: example.com"]), [("Host", "example.com")])

    def test_keeps_repeated_names(self):
        self.assertEqual(parse_headers(["X-A: 1", "X-A: 2"]), [("X-A", "1"), ("X-A", "2")])

    def test_keeps_a_colon_inside_the_value(self):
        self.assertEqual(parse_headers(["Referer: http://t/x"]), [("Referer", "http://t/x")])

    def test_drops_a_line_with_no_colon(self):
        self.assertEqual(parse_headers(["garbage"]), [])

    def test_trims_surrounding_space(self):
        self.assertEqual(parse_headers(["A:   spaced   "]), [("A", "spaced")])


class HeaderLookup(unittest.TestCase):
    def test_lookup_ignores_case(self):
        self.assertEqual(Headers([("Content-Type", "text/plain")]).get("content-type"), "text/plain")

    def test_get_all_returns_every_occurrence(self):
        self.assertEqual(Headers([("X-A", "1"), ("X-A", "2")]).get_all("x-a"), ["1", "2"])

    def test_set_replaces_where_add_appends(self):
        headers = Headers([("X-A", "1")])
        headers.set("X-A", "9")
        headers.add("X-A", "2")
        self.assertEqual(headers.get_all("X-A"), ["9", "2"])

    def test_delete_removes_every_occurrence(self):
        headers = Headers([("X-A", "1"), ("X-A", "2"), ("X-B", "3")])
        headers.delete("x-a")
        self.assertEqual(headers.names(), ["X-B"])


class RequestParsing(unittest.TestCase):
    def test_head_is_normalised_and_the_target_kept(self):
        request = Request.parse(b"GET /x?a=1 HTTP/1.1\nHost: t\n\n")
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.url, "/x?a=1")
        self.assertEqual(request.headers.get("host"), "t")

    def test_body_survives_byte_for_byte(self):
        # A multipart body is separated by CRLF. Normalising line endings across
        # the whole message destroys the boundaries, which is why only the head
        # is allowed to be rewritten.
        body = b'--b\r\nContent-Disposition: form-data; name="f"\r\n\r\nv\r\n--b--\r\n'
        raw = (
            b"POST /x HTTP/1.1\r\nHost: t\r\n"
            b"Content-Type: multipart/form-data; boundary=b\r\n\r\n" + body
        )
        self.assertEqual(Request.parse(raw).body, body)

    def test_lone_line_feeds_inside_the_body_are_left_alone(self):
        body = b"a\nb\r\nc"
        raw = b"POST /x HTTP/1.1\r\nHost: t\r\n\r\n" + body
        self.assertEqual(Request.parse(raw).body, body)

    def test_absolute_target_is_kept_as_written(self):
        request = Request.parse(b"GET http://t/x HTTP/1.1\r\nHost: t\r\n\r\n")
        self.assertEqual(request.url, "http://t/x")

    def test_from_url_carries_the_host(self):
        request = Request.from_url("http://target.example/x?y=1")
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.host(), "target.example")

    def test_clone_does_not_share_state(self):
        original = Request.parse(b"POST /x HTTP/1.1\r\nHost: t\r\n\r\nbody")
        copy = original.clone()
        copy.headers.set("X-New", "1")
        self.assertFalse(original.headers.__contains__("X-New"))
        self.assertEqual(copy.body, b"body")

    def test_to_bytes_round_trips(self):
        original = Request.parse(b"POST /x HTTP/1.1\r\nHost: t\r\n\r\nbody")
        again = Request.parse(original.to_bytes())
        self.assertEqual(again.body, b"body")
        self.assertEqual(again.url, "/x")


class ResponseBehaviour(unittest.TestCase):
    def test_text_decodes_without_losing_bytes(self):
        body = bytes(range(256))
        self.assertEqual(Response(status=200, body=body).text.encode("latin-1"), body)

    def test_a_redirect_counts_as_a_response(self):
        # ok means "the server answered", not "it answered with success".
        self.assertTrue(Response(status=302, headers=Headers(), body=b"").ok)

    def test_an_error_is_not_ok(self):
        self.assertFalse(Response(status=0, error="connection refused").ok)

    def test_header_lookup_is_case_insensitive(self):
        response = Response(status=200, headers=Headers([("Server", "lab")]))
        self.assertEqual(response.header("server"), "lab")


if __name__ == "__main__":
    unittest.main()
