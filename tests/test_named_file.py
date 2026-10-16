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


class BodyImpliesPost(unittest.TestCase):
    """A request with a body is a POST unless the operator said otherwise.

    A GET carrying a body is read by almost nothing: PHP fills `$_POST` only for
    a POST, so the parameters are parsed out of the body by the tool and then
    never seen by the application. Measured on a live target, every probe
    answered with the page as though no parameter had been sent at all, and the
    run reported no evidence on a parameter that was injectable.
    """

    def _request(self, argv: list[str]):
        from injectorkit.cli import build_parser
        from injectorkit.engine.runner import request_from_args

        return request_from_args(build_parser().parse_args(argv), "proto")

    def test_a_body_with_no_method_means_post(self):
        self.assertEqual(
            self._request(["proto", "-u", "https://t/", "--data", "f=1"]).method, "POST"
        )

    def test_no_body_still_means_get(self):
        self.assertEqual(self._request(["proto", "-u", "https://t/"]).method, "GET")

    def test_an_explicit_method_is_not_second_guessed(self):
        request = self._request(["proto", "-u", "https://t/", "--data", "f=1", "-X", "PUT"])
        self.assertEqual(request.method, "PUT")

    def test_an_explicit_get_with_a_body_is_honoured(self):
        request = self._request(["proto", "-u", "https://t/", "--data", "f=1", "-X", "GET"])
        self.assertEqual(request.method, "GET")

    def test_a_form_body_declares_itself_as_one(self):
        request = self._request(["proto", "-u", "https://t/", "--data", "f=1"])
        self.assertEqual(
            request.headers.get("Content-Type"), "application/x-www-form-urlencoded"
        )

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


class WhichFileToAskFor(unittest.TestCase):
    """A wrapper's signatures and the files it is asked for have to agree.

    Asking one target per wrapper leaves half of a wrapper's own signature list
    unable to fire: it describes a file that is never requested, so the probe
    cannot succeed however well the target behaves. Measured on a live target
    where `php://filter/convert.base64-encode` was asked for `index.php` and
    nothing else, answered with the base64 of an HTML page, and reported a
    working read as no evidence - while `cm9vdDp4`, the base64 of `root:x`, had
    been in that wrapper's signature list all along.
    """

    def _wrapper(self, payload: str, signatures: tuple[str, ...], family: str = "php-read"):
        return Wrapper("w", payload, family=family, signatures=signatures)

    def test_a_scheme_wrapper_is_asked_for_both_kinds_of_file(self):
        from injectorkit.modules.proto.graph import _targets_for
        from injectorkit.modules.proto.seeds import FILE_TARGETS

        wrapper = self._wrapper(
            "php://filter/convert.base64-encode/resource={file}",
            ("PD9waHA", "cm9vdDp4"),
        )
        picked = _targets_for(wrapper, list(FILE_TARGETS))
        self.assertEqual(len(picked), 2)
        self.assertTrue(any(path.startswith("/") for path in picked))
        self.assertTrue(any(not path.startswith("/") for path in picked))

    def test_a_wrapper_naming_a_system_file_is_asked_for_one_first(self):
        from injectorkit.modules.proto.graph import _targets_for
        from injectorkit.modules.proto.seeds import FILE_TARGETS

        wrapper = self._wrapper("php://filter/resource={file}", ("root:x:0:0",))
        picked = _targets_for(wrapper, list(FILE_TARGETS))
        self.assertTrue(picked[0].startswith("/"), picked)

    def test_a_wrapper_that_serves_the_application_is_asked_for_that_first(self):
        from injectorkit.modules.proto.graph import _targets_for
        from injectorkit.modules.proto.seeds import FILE_TARGETS

        wrapper = self._wrapper("php://filter/resource={file}", ("<?php",))
        picked = _targets_for(wrapper, list(FILE_TARGETS))
        self.assertFalse(picked[0].startswith("/"), picked)

    def test_a_plain_path_wrapper_still_gets_one_absolute_path(self):
        from injectorkit.modules.proto.graph import _targets_for
        from injectorkit.modules.proto.seeds import FILE_TARGETS

        wrapper = self._wrapper("{file}", ("root:x:0:0",), family="read")
        picked = _targets_for(wrapper, list(FILE_TARGETS))
        self.assertEqual(len(picked), 1)
        self.assertTrue(picked[0].startswith("/"))

    def test_a_named_file_is_the_only_thing_asked_for(self):
        from injectorkit.modules.proto.graph import _targets_for

        wrapper = self._wrapper("php://filter/resource={file}", ("PD9waHA",))
        self.assertEqual(_targets_for(wrapper, ["/tmp/flag"]), ["/tmp/flag"])

    def test_no_targets_asks_for_nothing(self):
        from injectorkit.modules.proto.graph import _targets_for

        self.assertEqual(_targets_for(self._wrapper("php://x/{file}", ("<?php",)), []), [])


class RememberedAnswers(unittest.TestCase):
    """What is kept is the answer, not the fact that the question was asked.

    The session remembers that the read action ran on a page, and that is the
    right thing to skip - but "a file was read here once" is not the file, and a
    second run that skipped the action had the payload to show and nothing else.
    Keeping the answer instead means a later run re-asks and gets it back without
    spending a request.
    """

    def _ctx(self):
        from types import SimpleNamespace

        from injectorkit.engine.blackboard import Blackboard

        return SimpleNamespace(blackboard=Blackboard())

    def test_an_answer_is_kept_and_recalled(self):
        from injectorkit.modules.proto.graph import _remember_read, _remembered_read

        ctx = self._ctx()
        _remember_read(ctx, "/etc/passwd", "root:x:0:0:root:/root\n")
        self.assertEqual(_remembered_read(ctx, "/etc/passwd"), "root:x:0:0:root:/root\n")

    def test_a_file_never_read_is_not_remembered(self):
        from injectorkit.modules.proto.graph import _remembered_read

        self.assertEqual(_remembered_read(self._ctx(), "/etc/passwd"), "")

    def test_an_empty_answer_is_not_an_answer(self):
        from injectorkit.modules.proto.graph import _remember_read, _remembered_read

        ctx = self._ctx()
        _remember_read(ctx, "/etc/passwd", "")
        self.assertEqual(_remembered_read(ctx, "/etc/passwd"), "")

    def test_a_nameless_path_is_never_remembered(self):
        from injectorkit.modules.proto.graph import _remember_read, _remembered_read

        ctx = self._ctx()
        _remember_read(ctx, "", "root:x:0:0\n")
        self.assertEqual(_remembered_read(ctx, ""), "")

    def test_two_files_are_remembered_separately(self):
        from injectorkit.modules.proto.graph import _remember_read, _remembered_read

        ctx = self._ctx()
        _remember_read(ctx, "/etc/passwd", "passwd\n")
        _remember_read(ctx, "/flag", "flag{one}\n")
        self.assertEqual(_remembered_read(ctx, "/etc/passwd"), "passwd\n")
        self.assertEqual(_remembered_read(ctx, "/flag"), "flag{one}\n")

    def test_the_read_action_is_one_the_operator_can_ask_for_by_name(self):
        from injectorkit.modules.proto.graph import build_graph

        actions = build_graph().state("probe").actions
        read = next(item for item in actions if item.id == "probe.read")
        self.assertEqual(read.wanted, "read")
        self.assertTrue(read.is_wanted({"read": ["/etc/passwd"]}))

    def test_the_other_actions_are_still_skipped_on_a_warm_session(self):
        from injectorkit.modules.proto.graph import build_graph

        for item in build_graph().state("probe").actions:
            if item.id == "probe.read":
                continue
            self.assertEqual(item.wanted, "", item.id)


if __name__ == "__main__":
    unittest.main()
