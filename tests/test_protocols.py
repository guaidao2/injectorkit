"""Protocol bytes: the ones that have to be exactly right.

FastCGI earns its own test class here. Its name-value encoding is easy to write
one way and easy to read the other, and getting it wrong produces a stream whose
headers, lengths and padding all look correct while the server resets the
connection without a word - so the order is pinned down below rather than left
to a comment.
"""

from __future__ import annotations

import unittest
from urllib.parse import unquote

from injectorkit.core.protocols import (
    crlf_encode,
    fcgi_params,
    fcgi_request,
    gopher_http,
    gopher_raw,
    memcached_command,
    rebind_host,
    redis_command,
    with_host,
)


class Gopher(unittest.TestCase):
    def test_raw_encodes_the_payload(self):
        url = gopher_raw("127.0.0.1", 6379, b"PING\r\n")
        self.assertTrue(url.startswith("gopher://127.0.0.1:6379/_"))
        self.assertEqual(unquote(url.split("_", 1)[1]), "PING\r\n")

    def test_a_crlf_makes_it_onto_the_wire(self):
        self.assertIn("%0d%0a", gopher_raw("127.0.0.1", 6379, b"PING\r\n").lower())

    def test_http_over_gopher_carries_the_request_line(self):
        url = gopher_http("127.0.0.1", 8080, "/x")
        body = unquote(url.split("_", 1)[1])
        self.assertIn("GET /x HTTP/1.1", body)
        self.assertIn("Host:", body)


class Redis(unittest.TestCase):
    def test_a_command_becomes_the_wire_protocol(self):
        url = redis_command("127.0.0.1", 6379, "PING")
        body = unquote(url.split("_", 1)[1])
        self.assertEqual(body, "PING\r\n")

    def test_several_commands_are_joined(self):
        body = unquote(redis_command("127.0.0.1", 6379, "CONFIG SET dir /tmp", "SAVE").split("_", 1)[1])
        self.assertIn("CONFIG SET dir /tmp", body)
        self.assertIn("SAVE", body)

    def test_memcached_uses_its_own_terminator(self):
        body = unquote(memcached_command("127.0.0.1", 11211, "stats").split("_", 1)[1])
        self.assertTrue(body.endswith("\r\n"))


class FastCgiValueEncoding(unittest.TestCase):
    """Length, length, name, value - and never in the other order."""

    def test_both_lengths_come_before_the_name(self):
        encoded = fcgi_params({"A": "B"})
        self.assertEqual(encoded[0], 1, "first byte is the name length")
        self.assertEqual(encoded[1], 1, "second byte is the value length")
        self.assertEqual(encoded[2], ord("A"), "then the name")
        self.assertEqual(encoded[3], ord("B"), "then the value")

    def test_a_long_name_and_value_use_four_byte_lengths(self):
        name = "N" * 200
        value = "V" * 300
        encoded = fcgi_params({name: value})
        self.assertEqual(encoded[0] & 0x80, 0x80, "a long name is flagged in the first byte")
        self.assertEqual(encoded[4] & 0x80, 0x80, "so is a long value")
        self.assertIn(name.encode(), encoded)
        self.assertIn(value.encode(), encoded)

    def test_the_framing_lengths_agree_with_the_content(self):
        encoded = fcgi_params({"A": "B"})
        self.assertEqual(len(encoded), 4)

    def test_params_can_be_padded_to_the_eight_byte_boundary(self):
        # A record's content is padded to eight bytes; the padding is not part of
        # the encoded pairs.
        encoded = fcgi_params({"SCRIPT_FILENAME": "/var/www/index.php"})
        remainder = len(encoded) % 8
        padded = encoded + b"\x00" * ((8 - remainder) % 8)
        self.assertEqual(len(padded) % 8, 0)
        self.assertTrue(padded.startswith(encoded))


class FastCgiRequest(unittest.TestCase):
    def test_the_url_points_at_the_pool(self):
        url = fcgi_request("127.0.0.1", 9000, {"SCRIPT_FILENAME": "/x.php"})
        self.assertTrue(url.startswith("gopher://127.0.0.1:9000/_"))

    def test_the_php_value_rides_along(self):
        url = fcgi_request(
            "127.0.0.1",
            9000,
            {"SCRIPT_FILENAME": "/x.php", "PHP_VALUE": "auto_prepend_file = /tmp/a"},
        )
        body = unquote(url.split("_", 1)[1])
        self.assertIn("auto_prepend_file", body)

    def test_the_stream_starts_with_the_fastcgi_version(self):
        url = fcgi_request("127.0.0.1", 9000, {"SCRIPT_FILENAME": "/x.php"})
        raw = unquote(url.split("_", 1)[1]).encode("latin-1")
        self.assertEqual(raw[0], 1, "version 1")


class HeaderSplitting(unittest.TestCase):
    def test_crlf_encoding_escapes_both_characters(self):
        encoded = crlf_encode("a\r\nb")
        self.assertNotIn("\r", encoded)
        self.assertNotIn("\n", encoded)
        self.assertIn("%0d%0a", encoded.lower())


class HostRewriting(unittest.TestCase):
    def test_with_host_swaps_only_the_authority(self):
        changed = with_host("http://internal:8080/x?y=1", "attacker.example")
        self.assertTrue(changed.startswith("http://attacker.example"))
        self.assertIn("/x?y=1", changed)

    def test_rebind_host_is_a_hex_pair_under_the_domain(self):
        name = rebind_host("169.254.169.254", "192.168.44.1")
        self.assertTrue(name.endswith("rbndr.us"))
        left, right, _ = name.split(".", 2)
        self.assertEqual(left, "a9fea9fe")
        self.assertEqual(right, "c0a82c01")


if __name__ == "__main__":
    unittest.main()
