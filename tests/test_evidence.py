"""Judging an observation: the layer where a false positive becomes a finding.

The first class here is the important one. A page that echoes what it was given
hands back the base64 the payload carried, and decoding that echo produces the
exact string a signature searches for - so the tool reports its own input as a
result unless the payload is removed before any decoding happens.
"""

from __future__ import annotations

import base64
import unittest
from urllib.parse import quote

from injectorkit.core.httpmsg import Headers, Response
from injectorkit.engine.blackboard import Confidence
from injectorkit.engine.evidence import Judge


def response(body: bytes, status: int = 200, headers: Headers | None = None) -> Response:
    return Response(status=status, headers=headers or Headers(), body=body)


class EchoedPayloadIsNotEvidence(unittest.TestCase):
    PHP_SOURCE = b"<?php echo 'hello'; ?>"

    def test_a_page_that_echoes_the_payload_is_not_a_finding(self):
        # The false positive that matters: the payload carries a base64 blob of
        # its own - a data:// URI, say - the page echoes it back, and decoding
        # that echo produces the very string a signature searches for. Without
        # stripping first, the tool reports its own input as a result.
        blob = base64.b64encode(b"<?php echo 'hello'; ?>").decode()
        payload = f"data://text/plain;base64,{blob}"
        body = f"<html>requested {payload}</html>".encode()
        self.assertFalse(
            Judge().signature(response(body), ["PD9waHA"], payload).confirmed,
            "the signature came out of the payload's own echo, not out of the target",
        )

    def test_the_same_body_is_a_finding_when_it_did_not_come_from_the_payload(self):
        # Identical response, no payload passed in to strip: now the base64 is
        # the page's own content and the signature legitimately matches.
        echoed = base64.b64encode(self.PHP_SOURCE).decode()
        verdict = Judge().signature(response(f"<html>{echoed}</html>".encode()), ["PD9waHA"])
        self.assertTrue(verdict.confirmed)

    def test_the_literal_payload_spelling_is_removed_too(self):
        payload = "root:x:0:0"
        body = f"<html>you said {payload}</html>".encode()
        self.assertFalse(Judge().signature(response(body), ["root:x:0:0"], payload).confirmed)


class SignatureMatching(unittest.TestCase):
    def test_a_plain_signature_matches(self):
        verdict = Judge().signature(response(b"root:x:0:0:root:/root:/bin/bash"), ["root:x:0:0"])
        self.assertTrue(verdict.confirmed)
        self.assertEqual(verdict.confidence, Confidence.CONFIRMED)

    def test_matching_ignores_case(self):
        self.assertTrue(Judge().signature(response(b"AMAZON"), ["amazon"]).confirmed)

    def test_a_base64_encoded_body_is_decoded_before_matching(self):
        body = base64.b64encode(b"<?php system($_GET['c']); ?>")
        self.assertTrue(Judge().signature(response(body), ["<?php system"]).confirmed)

    def test_a_signature_the_page_always_prints_does_not_count(self):
        # Present in the baseline response, so it says nothing about this probe.
        judge = Judge(baseline=b"<html>powered by framework</html>")
        self.assertFalse(judge.signature(response(b"<html>powered by framework</html>"), ["powered by"]).confirmed)

    def test_a_byte_signature_matches_through_a_text_response(self):
        # A class file starts with cafebabe and a servlet may hand it back in a
        # response that was decoded as text on the way out.
        verdict = Judge().signature(response("Êþº¾trailing".encode("latin-1")), ["cafebabe"])
        self.assertTrue(verdict.confirmed)

    def test_no_signature_means_no_verdict(self):
        self.assertFalse(Judge().signature(response(b"nothing here"), ["root:x:0:0"]).confirmed)


class Reflection(unittest.TestCase):
    def test_a_reflected_value_is_noted_but_not_conclusive(self):
        verdict = Judge().echo(response(b"<html>you sent marker123</html>"), "marker123")
        self.assertTrue(verdict.confirmed)
        self.assertEqual(verdict.confidence, Confidence.LIKELY)

    def test_a_value_already_in_the_baseline_is_not_reflection(self):
        judge = Judge(baseline=b"<html>marker123</html>")
        self.assertFalse(judge.echo(response(b"<html>marker123</html>"), "marker123").confirmed)


class PayloadStripping(unittest.TestCase):
    def test_the_payload_and_the_blob_it_carried_are_both_gone(self):
        blob = base64.b64encode(b"<?php echo 1; ?>").decode()
        payload = f"data://text/plain;base64,{blob}"
        cleaned = Judge.strip_payload(f"a {payload} b".encode(), payload)
        self.assertNotIn(payload.encode(), cleaned)
        self.assertNotIn(blob.encode(), cleaned)

    def test_the_payloads_own_words_are_not_evidence(self):
        # The page prints the request line, so the payload comes back encoded.
        # The payload happens to contain the string the signature looks for, and
        # decoding the echo brings it back - so the echo has to be stripped from
        # each decoded view as well, not only from the raw body.
        payload = "gopher://127.0.0.1:6379/_PING%0d%0a+PONG"
        body = f"<html>GET /?url={quote(payload, safe='')} HTTP/1.1</html>".encode()
        self.assertFalse(Judge().signature(response(body), ["+PONG"], payload).confirmed)

    def test_a_plain_payload_with_no_blob_is_still_removed(self):
        cleaned = Judge.strip_payload(b"a secret-token b", "secret-token")
        self.assertNotIn(b"secret-token", cleaned)

    def test_a_body_with_nothing_to_strip_is_returned_intact(self):
        self.assertEqual(Judge.strip_payload(b"plain", "absent"), b"plain")

    def test_decoded_views_offer_the_text_and_its_decodings(self):
        views = Judge.decoded_views(base64.b64encode(b"<?php echo 1; ?>"))
        self.assertTrue(any("<?php" in view for view in views), views)


if __name__ == "__main__":
    unittest.main()
