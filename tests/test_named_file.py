"""Judging a file whose contents nobody can predict.

The signature tables describe files the tool picked. The moment an operator names
one - a flag, a key, a config - no table can recognise what comes back, and a
wrapper that reads it perfectly well looks like silence. The fix is a control
request: the same wrapper, the same parameter, a path that cannot exist.

It is easy to get wrong in a way that looks like it works. A page that reflects
the parameter back answers the two requests with two different payloads, so the
responses differ by construction and every named file looks read. These tests are
mostly about that.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from injectorkit.core.httpmsg import Headers, Request
from injectorkit.core.params import Param, Where
from injectorkit.engine.evidence import Judge
from injectorkit.modules.proto.graph import MISSING_PATH, _differs_from_missing
from injectorkit.modules.proto.seeds import Wrapper

WRAPPER = Wrapper("bare", "{file}", family="read", signatures=("root:x:0:0",))


def context(bodies: list[str], echo: bool = False):
    """A run context whose transport answers with the given bodies, in order."""
    sent: list[str] = []
    queue = list(bodies)

    class Ctx:
        stopped = False

        def __init__(self):
            self.sent = sent

    ctx = Ctx()
    param = Param(where=Where.BODY, name="file", value="index.php")

    def inject(_ctx, _param, payload, _action):
        sent.append(payload)
        body = queue.pop(0)
        if echo:
            body = f"<textarea>{payload}</textarea>{body}"
        request = Request(method="POST", url="https://t/", headers=Headers())
        response = SimpleNamespace(error="", text=body, body=body.encode())
        return request, SimpleNamespace(response=response)

    return ctx, param, inject


class WhatCountsAsReadingAnUnknownFile(unittest.TestCase):
    def run_case(self, bodies, seen, payload="{file}", echo=False):
        ctx, param, inject = context(bodies, echo=echo)
        import injectorkit.modules.proto.graph as graph

        original = graph._inject
        graph._inject = inject
        try:
            return _differs_from_missing(ctx, param, WRAPPER, "/flag", seen, payload)
        finally:
            graph._inject = original

    def test_a_different_answer_means_the_file_was_read(self):
        self.assertTrue(self.run_case(["file contents here"], "the app said no"))

    def test_the_same_answer_means_it_was_not(self):
        self.assertFalse(self.run_case(["the app said no"], "the app said no"))

    def test_a_reflected_payload_is_not_mistaken_for_a_result(self):
        # The whole trap. The page prints the payload, so the two responses differ
        # by construction - they carry different payloads. Judged raw, every named
        # file on every reflecting page is reported as read.
        ctx, param, inject = context(["same page", "same page"], echo=True)
        import injectorkit.modules.proto.graph as graph

        original = graph._inject
        graph._inject = inject
        try:
            differs = _differs_from_missing(
                ctx, param, WRAPPER, "/flag", "<textarea>/flag</textarea>same page", "/flag"
            )
        finally:
            graph._inject = original
        self.assertFalse(differs)

    def test_a_real_result_still_gets_through_the_reflection(self):
        # And the reflection must not suppress a genuine one either.
        ctx, param, inject = context(["file contents here"], echo=True)
        import injectorkit.modules.proto.graph as graph

        original = graph._inject
        graph._inject = inject
        try:
            differs = _differs_from_missing(
                ctx, param, WRAPPER, "/flag", "<textarea>/flag</textarea>the app said no", "/flag"
            )
        finally:
            graph._inject = original
        self.assertTrue(differs)

    def test_a_path_that_cannot_exist_is_not_asked_again(self):
        # Asking for the missing path with the missing path as the target is the
        # control comparing itself; there is nothing to learn and it would recurse.
        self.assertFalse(self.run_case(["anything"], "anything"))

    def test_the_control_is_the_same_wrapper_for_a_path_that_cannot_exist(self):
        ctx, param, inject = context(["a"])
        import injectorkit.modules.proto.graph as graph

        original = graph._inject
        graph._inject = inject
        try:
            _differs_from_missing(ctx, param, WRAPPER, "/flag", "b", "{file}")
        finally:
            graph._inject = original
        self.assertIn(MISSING_PATH, ctx.sent[0])

    def test_an_error_response_is_not_evidence(self):
        ctx, param, _ = context([])

        def broken(_ctx, _param, _payload, _action):
            request = Request(method="POST", url="https://t/", headers=Headers())
            return request, SimpleNamespace(response=SimpleNamespace(error="timed out", text=""))

        import injectorkit.modules.proto.graph as graph

        original = graph._inject
        graph._inject = broken
        try:
            self.assertFalse(_differs_from_missing(ctx, param, WRAPPER, "/flag", "x", "{file}"))
        finally:
            graph._inject = original


class StrippingTheEchoIsWhatMakesItWork(unittest.TestCase):
    """The helper the comparison rests on, checked on its own."""

    def test_the_payload_is_removed_in_the_encoded_spelling_too(self):
        self.assertNotIn("php%3A%2F%2Ffilter", Judge.strip_echo("x php%3A%2F%2Ffilter y", "php://filter"))

    def test_the_rest_of_the_page_is_left_alone(self):
        self.assertEqual(Judge.strip_echo("before PAYLOAD after", "PAYLOAD"), "before  after")

    def test_nothing_to_strip(self):
        self.assertEqual(Judge.strip_echo("page", ""), "page")


if __name__ == "__main__":
    unittest.main()
