"""Out-of-band callbacks, and the alphabets a deployment insists on.

interactsh earns its place here for one reason: the correlation id has to be
twenty characters drawn from a specific alphabet. Anything else registers
successfully and then never attributes a single callback, so the run reports
"no interaction" for a target that was calling back the whole time. That is a
silent failure worth a test.
"""

from __future__ import annotations

import unittest
import urllib.error
import urllib.request

from injectorkit.engine import interactsh
from injectorkit.engine.oob import OOBListener

XID_ALPHABET = set("0123456789abcdefghijklmnopqrstuv")
ZBASE32_ALPHABET = set("ybndrfg8ejkmcpqxot1uwisza345h769")

# A high port, so the test does not collide with anything the lab uses.
LISTEN_PORT = 45991


class CorrelationId(unittest.TestCase):
    def test_it_is_twenty_characters(self):
        self.assertEqual(len(interactsh._xid()), 20)

    def test_it_stays_inside_the_xid_alphabet(self):
        for _ in range(25):
            self.assertTrue(set(interactsh._xid()) <= XID_ALPHABET, "a character outside the alphabet")

    def test_two_ids_differ(self):
        self.assertNotEqual(interactsh._xid(), interactsh._xid())


class Nonce(unittest.TestCase):
    def test_it_is_thirteen_characters(self):
        self.assertEqual(len(interactsh._nonce()), 13)

    def test_it_stays_inside_the_zbase32_alphabet(self):
        for _ in range(25):
            self.assertTrue(set(interactsh._nonce()) <= ZBASE32_ALPHABET)


class ServerName(unittest.TestCase):
    def test_a_bare_hostname_gains_a_scheme(self):
        self.assertEqual(interactsh._normalise("oast.pro"), "https://oast.pro")

    def test_a_url_keeps_its_own_scheme(self):
        self.assertEqual(interactsh._normalise("https://oast.pro/"), "https://oast.pro")

    def test_a_trailing_slash_is_not_part_of_the_server(self):
        self.assertFalse(interactsh._normalise("https://oast.pro/").endswith("/"))


class MissingCrypto(unittest.TestCase):
    def test_the_module_reports_whether_it_has_crypto(self):
        self.assertIsInstance(interactsh.HAVE_CRYPTO, bool)

    def test_a_client_without_crypto_explains_itself(self):
        if interactsh.HAVE_CRYPTO:
            self.skipTest("cryptography is installed here")
        with self.assertRaises(interactsh.InteractshError) as caught:
            interactsh.InteractshClient("oast.pro").start()
        self.assertIn("cryptography", str(caught.exception))


class LocalListener(unittest.TestCase):
    """The callback listener, which needs nothing but a socket."""

    def setUp(self):
        self.listener = OOBListener(bind="127.0.0.1", port=LISTEN_PORT, public_host="127.0.0.1")
        try:
            self.listener.start()
        except OSError as error:
            self.skipTest(f"cannot listen on {LISTEN_PORT}: {error}")

    def tearDown(self):
        self.listener.stop()

    def test_a_generated_url_carries_the_token(self):
        url, token = self.listener.new_url("probe")
        self.assertIn(token, url)
        self.assertTrue(url.startswith("http://127.0.0.1"))

    def test_a_request_to_the_url_is_recorded(self):
        url, token = self.listener.new_url("probe")
        try:
            urllib.request.urlopen(url, timeout=5).read()
        except (urllib.error.URLError, OSError) as error:
            self.skipTest(f"loopback request failed: {error}")
        self.assertTrue(self.listener.poll(token), "the callback was not recorded")
        self.assertEqual(self.listener.labels().get(token), "probe")

    def test_an_unknown_token_records_nothing(self):
        self.assertEqual(self.listener.poll("deadbeef" * 2), [])

    def test_a_redirect_token_carries_its_target(self):
        url, token = self.listener.new_redirect("http://169.254.169.254/")
        self.assertIn(token, url)
        self.assertEqual(self.listener.redirect_target(token), "http://169.254.169.254/")

    def test_an_unknown_redirect_token_has_no_target(self):
        self.assertIsNone(self.listener.redirect_target("nope"))


if __name__ == "__main__":
    unittest.main()
