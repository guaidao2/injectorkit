"""Carrying an identity: cookies and headers on every request.

The rules here come from what goes wrong with an authenticated scan. A cookie
that replaces the request's own ends the session it was meant to keep, and a
configured header that overrides the request's own is the one thing that must
never happen to a request that already names an identity.

The first class sends real traffic to a local server and reads back what arrived,
because the interesting question is what reaches the wire - not what the code
believes it set.
"""

from __future__ import annotations

import argparse
import base64
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from injectorkit.core.httpmsg import Headers, Request
from injectorkit.engine.transport import Transport, TransportOptions
from injectorkit.runtime import credentials


class _Echo(BaseHTTPRequestHandler):
    """Answers with the headers it was sent, so a test can read them back."""

    seen: list[dict] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).seen.append({name.lower(): value for name, value in self.headers.items()})
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # noqa: A002
        pass


class WhatReachesTheWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _Echo.seen = []

    def target(self, headers=None) -> Request:
        return Request(method="GET", url=f"http://127.0.0.1:{self.port}/", headers=Headers(headers or []))

    def send(self, request, configured) -> dict:
        transport = Transport(TransportOptions(headers=tuple(configured), timeout=5))
        response = transport.send(request)
        self.assertEqual(response.status, 200)
        return _Echo.seen[-1]

    def test_a_configured_cookie_is_sent(self):
        self.assertEqual(self.send(self.target(), [("Cookie", "sess=abc")])["cookie"], "sess=abc")

    def test_a_configured_cookie_is_merged_not_replaced(self):
        # The request may already carry a CSRF token. Replacing the header would
        # end the very session this exists to keep.
        seen = self.send(self.target([("Cookie", "csrf=xyz")]), [("Cookie", "sess=abc")])
        self.assertIn("csrf=xyz", seen["cookie"])
        self.assertIn("sess=abc", seen["cookie"])

    def test_a_bearer_token_is_sent(self):
        seen = self.send(self.target(), [("Authorization", "Bearer configured")])
        self.assertEqual(seen["authorization"], "Bearer configured")

    def test_the_requests_own_identity_wins(self):
        # A request that already names an identity is more specific than a
        # command-line default.
        seen = self.send(
            self.target([("Authorization", "Bearer specific")]),
            [("Authorization", "Bearer configured")],
        )
        self.assertEqual(seen["authorization"], "Bearer specific")

    def test_a_configured_header_fills_a_gap_without_disturbing_the_rest(self):
        seen = self.send(self.target([("X-Own", "own")]), [("X-Configured", "configured")])
        self.assertEqual(seen["x-own"], "own")
        self.assertEqual(seen["x-configured"], "configured")

    def test_an_empty_configured_header_changes_nothing(self):
        seen = self.send(self.target(), [("", "")])
        self.assertEqual(seen.get(""), None)

    def test_a_request_with_no_identity_still_works(self):
        self.assertTrue(self.send(self.target(), [])["host"].startswith("127.0.0.1"))


class CredentialParsing(unittest.TestCase):
    def parse(self, cookies=None, basic=None):
        return credentials(argparse.Namespace(cookie=cookies, basic_auth=basic))

    def test_a_pasted_cookie_header_loses_its_prefix(self):
        # The single most common way to get this wrong: copying the whole header
        # line out of a browser.
        self.assertEqual(self.parse(cookies=["Cookie: sess=abc"]), [("Cookie", "sess=abc")])

    def test_the_prefix_is_stripped_case_insensitively(self):
        self.assertEqual(self.parse(cookies=["cookie: sess=abc"]), [("Cookie", "sess=abc")])

    def test_a_bare_cookie_value_is_kept(self):
        self.assertEqual(self.parse(cookies=["sess=abc; csrf=xyz"]), [("Cookie", "sess=abc; csrf=xyz")])

    def test_several_cookie_arguments_are_each_kept(self):
        self.assertEqual(len(self.parse(cookies=["a=1", "b=2"])), 2)

    def test_surrounding_space_is_trimmed(self):
        self.assertEqual(self.parse(cookies=["  sess=abc  "]), [("Cookie", "sess=abc")])

    def test_an_empty_argument_is_ignored(self):
        # An unset shell variable expands to nothing; failing on that would break
        # scripts for no reason.
        self.assertEqual(self.parse(cookies=["", "   "]), [])

    def test_basic_auth_is_encoded(self):
        pairs = self.parse(basic="user:pass")
        self.assertEqual(pairs[0][0], "Authorization")
        self.assertTrue(pairs[0][1].startswith("Basic "))
        self.assertEqual(base64.b64decode(pairs[0][1].split()[1]).decode(), "user:pass")

    def test_a_password_containing_a_colon_survives(self):
        pairs = self.parse(basic="user:pa:ss")
        self.assertEqual(base64.b64decode(pairs[0][1].split()[1]).decode(), "user:pa:ss")

    def test_basic_auth_without_a_colon_is_rejected(self):
        # Guessing here would scan under the wrong identity.
        with self.assertRaises(SystemExit):
            self.parse(basic="nocolon")

    def test_cookies_and_basic_auth_can_be_combined(self):
        names = [name for name, _ in self.parse(cookies=["sess=abc"], basic="u:p")]
        self.assertEqual(names, ["Cookie", "Authorization"])


if __name__ == "__main__":
    unittest.main()
