"""Where a parameter lives, how it is rewritten, and how it is duplicated.

The parameter layer is where the tool meets the target's own parser, and the
tests here pin down the cases that cost time to get right: a body that must not
be re-encoded, a JSON value whose inner field has to arrive unescaped, and the
duplicate-parameter order that a filter and a runtime disagree about.
"""

from __future__ import annotations

import unittest
from urllib.parse import parse_qs, urlsplit

from injectorkit.core.httpmsg import Headers, Request
from injectorkit.core.params import Encode, Param, Where, extract_params, pollute, rewrite


def params_of(request):
    return {param.key(): param for param in extract_params(request)}


def upload_request(filename: str = "photo.png", content: bytes = b"PNG data") -> Request:
    """A multipart request carrying one file part."""
    boundary = "----ik"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="avatar"; filename="{filename}"\r\n'
        f"Content-Type: image/png\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return Request(
        method="POST",
        url="http://t/upload",
        headers=Headers([("Content-Type", f"multipart/form-data; boundary={boundary}")]),
        body=body,
    )


class Extraction(unittest.TestCase):
    def test_query_parameter(self):
        request = Request.from_url("http://t/f?url=http://example.com")
        found = params_of(request)
        self.assertIn("query:url", found)
        self.assertEqual(found["query:url"].value, "http://example.com")

    def test_query_parameter_keeps_its_wire_form(self):
        # Param.value is what travels on the wire, not what the application ends
        # up parsing out of it: a rewrite has to match the bytes actually in the
        # request, so an encoded value stays encoded here.
        request = Request.from_url("http://t/f?url=http%3A%2F%2Fexample.com")
        self.assertEqual(params_of(request)["query:url"].value, "http%3A%2F%2Fexample.com")

    def test_form_body_parameter(self):
        request = Request(
            method="POST",
            url="http://t/f",
            headers=Headers([("Content-Type", "application/x-www-form-urlencoded")]),
            body=b"url=http%3A%2F%2Fexample.com&other=1",
        )
        found = params_of(request)
        self.assertIn("body:url", found)
        self.assertEqual(found["body:url"].value, "http%3A%2F%2Fexample.com")

    def test_cookie_parameter(self):
        request = Request(
            method="GET",
            url="http://t/f",
            headers=Headers([("Cookie", "url=http://example.com; sid=1")]),
        )
        found = params_of(request)
        self.assertIn("cookie:url", found)
        self.assertEqual(found["cookie:url"].value, "http://example.com")

    def test_multipart_parameter(self):
        boundary = "----b"
        body = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"url\"\r\n\r\n"
            f"http://example.com\r\n--{boundary}--\r\n"
        ).encode()
        request = Request(
            method="POST",
            url="http://t/f",
            headers=Headers([("Content-Type", f"multipart/form-data; boundary={boundary}")]),
            body=body,
        )
        found = params_of(request)
        self.assertIn("multipart:url", found)
        self.assertEqual(found["multipart:url"].value, "http://example.com")

    def test_a_file_part_is_addressed_by_its_filename_too(self):
        # A part carrying a file has two values: the one the application reads
        # as a field, and the name it will be stored under. Only the second
        # reaches a path.
        request = upload_request()
        found = params_of(request)
        self.assertIn("multipart:avatar", found)
        self.assertIn("multipart-filename:avatar", found)
        self.assertEqual(found["multipart-filename:avatar"].value, "photo.png")

    def test_a_plain_part_has_no_filename(self):
        request = Request(
            method="POST",
            url="http://t/f",
            headers=Headers([("Content-Type", "multipart/form-data; boundary=b")]),
            body=b'--b\r\nContent-Disposition: form-data; name="note"\r\n\r\nhi\r\n--b--\r\n',
        )
        keys = params_of(request)
        self.assertIn("multipart:note", keys)
        self.assertNotIn("multipart-filename:note", keys)

    def test_json_field_nested_inside_a_document(self):
        request = Request.from_url('http://t/f?json={"ref":"http://example.com"}')
        found = params_of(request)
        embedded = [key for key in found if "json" in key.lower()]
        self.assertTrue(embedded, f"no json parameter found in {sorted(found)}")

    def test_the_whole_document_is_offered_when_nothing_else_fits(self):
        request = Request(
            method="POST",
            url="http://t/f",
            headers=Headers([("Content-Type", "application/json")]),
            body=b'{"a": {"b": "http://example.com"}}',
        )
        found = params_of(request)
        self.assertTrue(any(param.where is Where.JSON for param in found.values()))


class Rewriting(unittest.TestCase):
    def test_query_rewrite_replaces_only_that_value(self):
        request = Request.from_url("http://t/f?a=1&url=http://example.com&b=2")
        param = params_of(request)["query:url"]
        changed = rewrite(request, param, "gopher://127.0.0.1:6379/_PING", Encode.URL)
        query = parse_qs(urlsplit(changed.url).query)
        self.assertEqual(query["a"], ["1"])
        self.assertEqual(query["b"], ["2"])
        self.assertEqual(query["url"], ["gopher://127.0.0.1:6379/_PING"])

    def test_the_original_request_is_not_modified(self):
        request = Request.from_url("http://t/f?url=http://example.com")
        param = params_of(request)["query:url"]
        rewrite(request, param, "file:///etc/passwd", Encode.URL)
        self.assertIn("example.com", request.url)

    def test_body_rewrite_keeps_the_other_fields(self):
        request = Request(
            method="POST",
            url="http://t/f",
            headers=Headers([("Content-Type", "application/x-www-form-urlencoded")]),
            body=b"url=http%3A%2F%2Fexample.com&keep=me",
        )
        param = params_of(request)["body:url"]
        changed = rewrite(request, param, "http://169.254.169.254/", Encode.URL)
        self.assertIn(b"keep=me", changed.body)
        self.assertNotIn(b"example.com", changed.body)

    def test_content_length_follows_a_body_change(self):
        request = Request(
            method="POST",
            url="http://t/f",
            headers=Headers([("Content-Type", "application/x-www-form-urlencoded"), ("Content-Length", "26")]),
            body=b"url=http%3A%2F%2Fexample.com",
        )
        param = params_of(request)["body:url"]
        changed = rewrite(request, param, "x" * 100, Encode.URL)
        self.assertEqual(changed.headers.get("Content-Length"), str(len(changed.body)))


class Pollution(unittest.TestCase):
    """The same name twice: the filter reads one value, the runtime the other."""

    def test_the_original_value_comes_first(self):
        request = Request.from_url("http://t/f?url=http://example.com")
        param = params_of(request)["query:url"]
        dirty = pollute(request, param, "php://filter/convert.base64-encode/resource=index.php")
        values = parse_qs(urlsplit(dirty.url).query)["url"]
        self.assertEqual(len(values), 2)
        self.assertEqual(values[0], "http://example.com", "the filter judges the first value")
        self.assertEqual(values[-1], "php://filter/convert.base64-encode/resource=index.php")

    def test_a_parameter_that_came_after_is_preserved(self):
        request = Request.from_url("http://t/f?url=http://example.com&sid=1")
        param = params_of(request)["query:url"]
        dirty = pollute(request, param, "file:///etc/passwd")
        query = parse_qs(urlsplit(dirty.url).query)
        self.assertEqual(query["sid"], ["1"])
        self.assertEqual(query["url"][-1], "file:///etc/passwd")

    def test_other_parameters_are_not_duplicated(self):
        request = Request.from_url("http://t/f?url=http://example.com&sid=1")
        param = params_of(request)["query:url"]
        dirty = pollute(request, param, "file:///etc/passwd")
        self.assertEqual(len(parse_qs(urlsplit(dirty.url).query)["sid"]), 1)

    def test_a_body_parameter_is_also_polluted(self):
        request = Request(
            method="POST",
            url="http://t/f",
            headers=Headers([("Content-Type", "application/x-www-form-urlencoded")]),
            body=b"url=http%3A%2F%2Fexample.com",
        )
        param = params_of(request)["body:url"]
        dirty = pollute(request, param, "file:///etc/passwd")
        values = parse_qs(dirty.body.decode())["url"]
        self.assertEqual(values[0], "http://example.com")
        self.assertEqual(values[-1], "file:///etc/passwd")

    def test_a_header_cannot_be_polluted_even_when_it_is_named(self):
        # The same finding stated from the other side: naming a header with -H
        # makes it injectable, but it does not make duplication possible.
        request = Request(
            method="GET", url="http://t/f", headers=Headers([("X-Forwarded-Host", "clean")])
        )
        param = Param(
            where=Where.HEADER,
            name="X-Forwarded-Host",
            value="clean",
            header="X-Forwarded-Host",
        )
        dirty = pollute(request, param, "evil")
        self.assertEqual(list(dirty.headers), [("X-Forwarded-Host", "clean")])

    def test_the_original_request_is_left_alone(self):
        request = Request.from_url("http://t/f?url=http://example.com")
        param = params_of(request)["query:url"]
        pollute(request, param, "file:///etc/passwd")
        self.assertEqual(parse_qs(urlsplit(request.url).query)["url"], ["http://example.com"])


class HeadersAsParameters(unittest.TestCase):
    """Headers an application reads as input, rather than as transport."""

    def test_a_forwarding_header_is_injectable(self):
        request = Request(method="GET", url="http://t/f", headers=Headers([("X-Forwarded-For", "127.0.0.1")]))
        self.assertIn("header:X-Forwarded-For", params_of(request))

    def test_an_authorization_header_is_injectable(self):
        request = Request(method="GET", url="http://t/f", headers=Headers([("Authorization", "Bearer token")]))
        self.assertIn("header:Authorization", params_of(request))

    def test_a_rewrite_header_is_injectable(self):
        request = Request(method="GET", url="http://t/f", headers=Headers([("X-Original-URL", "/admin")]))
        self.assertIn("header:X-Original-URL", params_of(request))

    def test_transport_headers_are_left_alone(self):
        # Rewriting Accept-Encoding tells nobody anything and costs a request.
        request = Request(
            method="GET",
            url="http://t/f",
            headers=Headers([("Accept-Encoding", "gzip"), ("Accept", "*/*"), ("User-Agent", "x")]),
        )
        self.assertEqual([key for key in params_of(request) if key.startswith("header:")], [])

    def test_a_header_is_rewritten_in_place(self):
        request = Request(method="GET", url="http://t/f", headers=Headers([("X-Forwarded-For", "127.0.0.1")]))
        param = params_of(request)["header:X-Forwarded-For"]
        changed = rewrite(request, param, "169.254.169.254", Encode.NONE)
        self.assertEqual(changed.headers.get_all("X-Forwarded-For"), ["169.254.169.254"])
        self.assertEqual(request.headers.get("X-Forwarded-For"), "127.0.0.1")

    def test_a_header_can_be_percent_encoded_on_the_way_out(self):
        request = Request(method="GET", url="http://t/f", headers=Headers([("Referer", "http://t/")]))
        param = params_of(request)["header:Referer"]
        changed = rewrite(request, param, "http://169.254.169.254/", Encode.URL)
        self.assertEqual(changed.headers.get("Referer"), "http%3A%2F%2F169.254.169.254%2F")

    def test_a_header_is_not_polluted(self):
        # Not because the technique is worthless, but because the transport
        # cannot perform it: `urllib` holds headers in a dict and replaces by
        # name, so a second occurrence is collapsed before the request leaves.
        # A model-level duplicate would be recorded as tried and change nothing
        # on the wire - which is exactly what a test at this layer cannot see.
        request = Request(
            method="GET", url="http://t/f", headers=Headers([("X-Forwarded-For", "127.0.0.1")])
        )
        param = params_of(request)["header:X-Forwarded-For"]
        dirty = pollute(request, param, "169.254.169.254", Encode.NONE)
        self.assertEqual(dirty.headers.get_all("X-Forwarded-For"), ["127.0.0.1"])

    def test_an_unnamed_header_counts_when_the_operator_named_it(self):
        # -H is how a house authentication header gets in: the tool cannot know
        # the application reads it, but the operator does.
        request = Request(method="GET", url="http://t/f", headers=Headers([("X-Tenant", "acme")]))
        self.assertNotIn("header:X-Tenant", params_of(request))
        named = {param.key() for param in extract_params(request, extra_headers=frozenset({"x-tenant"}))}
        self.assertIn("header:X-Tenant", named)


class MultipartRewrite(unittest.TestCase):
    """Rewriting a part, which had no test at all until a filename bug slipped past.

    Extraction was covered and rewriting was not, so the filename position could
    be extracted, handed to the injector, and silently never reach the payload.
    """

    BOUNDARY = "----ik"

    def request(self) -> Request:
        body = (
            f"--{self.BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="url"\r\n\r\n'
            f"http://example.com\r\n"
            f"--{self.BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="avatar"; filename="photo.png"\r\n'
            f"Content-Type: image/png\r\n\r\nPNGDATA\r\n"
            f"--{self.BOUNDARY}--\r\n"
        ).encode()
        return Request(
            method="POST",
            url="http://t/upload",
            headers=Headers([("Content-Type", f"multipart/form-data; boundary={self.BOUNDARY}")]),
            body=body,
        )

    def test_a_field_value_is_replaced(self):
        request = self.request()
        param = params_of(request)["multipart:url"]
        out = rewrite(request, param, "PAYLOAD", Encode.NONE)
        self.assertIn(b"PAYLOAD", out.body)
        self.assertNotIn(b"http://example.com", out.body)

    def test_a_filename_is_replaced(self):
        request = self.request()
        param = params_of(request)["multipart-filename:avatar"]
        out = rewrite(request, param, "shell.php", Encode.NONE)
        self.assertIn(b'filename="shell.php"', out.body)
        self.assertNotIn(b"photo.png", out.body)

    def test_the_part_content_survives_a_filename_change(self):
        # Only the name is the payload; the bytes the browser was sending stay.
        request = self.request()
        param = params_of(request)["multipart-filename:avatar"]
        out = rewrite(request, param, "shell.php", Encode.NONE)
        self.assertIn(b"PNGDATA", out.body)

    def test_the_other_part_is_untouched(self):
        request = self.request()
        param = params_of(request)["multipart-filename:avatar"]
        out = rewrite(request, param, "shell.php", Encode.NONE)
        self.assertIn(b"http://example.com", out.body)

    def test_the_body_stays_well_formed(self):
        request = self.request()
        param = params_of(request)["multipart:url"]
        out = rewrite(request, param, "PAYLOAD", Encode.NONE)
        text = out.body.decode("latin-1")
        self.assertEqual(text.count(f"--{self.BOUNDARY}"), 3)
        self.assertTrue(text.endswith(f"--{self.BOUNDARY}--\r\n"))

    def test_content_length_matches_the_body(self):
        request = self.request()
        param = params_of(request)["multipart:url"]
        out = rewrite(request, param, "PAYLOAD", Encode.NONE)
        self.assertEqual(out.headers.get("Content-Length"), str(len(out.body)))

    def test_the_original_request_is_left_alone(self):
        request = self.request()
        before = request.body
        param = params_of(request)["multipart:url"]
        rewrite(request, param, "PAYLOAD", Encode.NONE)
        self.assertEqual(request.body, before)


class Encoding(unittest.TestCase):
    def test_none_leaves_the_value_as_it_is(self):
        request = Request.from_url("http://t/f?url=x")
        param = params_of(request)["query:url"]
        changed = rewrite(request, param, "a b&c", Encode.NONE)
        self.assertIn("a b&c", changed.url)

    def test_url_encoding_makes_the_value_travel_intact(self):
        request = Request.from_url("http://t/f?url=x")
        param = params_of(request)["query:url"]
        changed = rewrite(request, param, "gopher://127.0.0.1:6379/_PING", Encode.URL)
        self.assertEqual(parse_qs(urlsplit(changed.url).query)["url"], ["gopher://127.0.0.1:6379/_PING"])


if __name__ == "__main__":
    unittest.main()
