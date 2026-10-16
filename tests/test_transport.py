"""What asks a scan to slow down, and how long it should wait.

Getting this wrong is not a style problem. A 429 that nothing recognises is
neither a finding nor a refusal, so the bypass ladder stops climbing, the action
is recorded as tested, and a rate-limited target is reported as one with nothing
in it.
"""

from __future__ import annotations

import email.utils
import time
import unittest

from injectorkit.core.httpmsg import Headers, Response
from injectorkit.engine import transport
from injectorkit.engine.transport import Transport


class RetryAfterHeader(unittest.TestCase):
    def headers(self, value: str) -> Headers:
        return Headers([("Retry-After", value)])

    def test_seconds(self):
        self.assertEqual(transport._retry_after(self.headers("5")), 5.0)

    def test_an_http_date(self):
        when = email.utils.formatdate(time.time() + 10, usegmt=True)
        value = transport._retry_after(self.headers(when))
        self.assertTrue(9 <= value <= 11, value)

    def test_a_date_in_the_past_is_zero_not_negative(self):
        when = email.utils.formatdate(time.time() - 60, usegmt=True)
        self.assertEqual(transport._retry_after(self.headers(when)), 0.0)

    def test_an_absent_header(self):
        self.assertIsNone(transport._retry_after(Headers()))

    def test_something_that_is_neither(self):
        self.assertIsNone(transport._retry_after(self.headers("soon")))


class WhatCountsAsBeingAskedToWait(unittest.TestCase):
    def response(self, status: int, retry_after: str | None = None) -> Response:
        headers = Headers([("Retry-After", retry_after)] if retry_after else [])
        return Response(status=status, headers=headers, body=b"")

    def test_429_always_counts(self):
        self.assertIsNotNone(Transport._asked_to_wait(self.response(429)))

    def test_429_without_a_header_still_waits_a_little(self):
        self.assertEqual(Transport._asked_to_wait(self.response(429)), 1.0)

    def test_503_counts_only_when_it_names_a_wait(self):
        # A 503 with no header is an ordinary server error; retrying it would be
        # guessing at what the target meant.
        self.assertIsNone(Transport._asked_to_wait(self.response(503)))
        self.assertEqual(Transport._asked_to_wait(self.response(503, "2")), 2.0)

    def test_403_is_a_refusal_not_a_slow_down(self):
        self.assertIsNone(Transport._asked_to_wait(self.response(403)))

    def test_a_200_is_never_a_wait(self):
        self.assertIsNone(Transport._asked_to_wait(self.response(200)))

    def test_the_pace_starts_at_zero_and_is_never_lowered(self):
        self.assertEqual(Transport()._pace, 0.0)


if __name__ == "__main__":
    unittest.main()
