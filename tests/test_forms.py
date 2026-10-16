"""Reading the forms a page declares.

Most of a real target's parameters live in a form body rather than in the URL, so
parsing them is what makes `--forms` worth anything. The cases below are the ones
a hand-written parser tends to miss.
"""

from __future__ import annotations

import unittest

from injectorkit.core.forms import form_request, parse_forms


class Parsing(unittest.TestCase):
    def test_a_simple_get_form(self):
        forms = parse_forms(
            '<form action="/search" method="get"><input name="q" value="x"></form>',
            "http://t/",
        )
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0].method, "GET")
        self.assertEqual([field.name for field in forms[0].fields], ["q"])

    def test_a_post_form(self):
        forms = parse_forms(
            '<form action="/submit" method="post"><input name="url"></form>',
            "http://t/",
        )
        self.assertEqual(forms[0].method, "POST")

    def test_the_method_defaults_to_get(self):
        forms = parse_forms('<form action="/a"><input name="q"></form>', "http://t/")
        self.assertEqual(forms[0].method, "GET")

    def test_a_relative_action_is_resolved_against_the_page(self):
        forms = parse_forms('<form action="search"><input name="q"></form>', "http://t/dir/page")
        self.assertEqual(forms[0].action, "http://t/dir/search")

    def test_a_form_with_no_action_posts_to_the_page_itself(self):
        forms = parse_forms('<form method="post"><input name="q"></form>', "http://t/page")
        self.assertEqual(forms[0].action, "http://t/page")

    def test_several_forms_are_all_returned(self):
        forms = parse_forms(
            '<form action="/a"><input name="x"></form><form action="/b"><input name="y"></form>',
            "http://t/",
        )
        self.assertEqual(len(forms), 2)

    def test_a_textarea_is_a_field(self):
        forms = parse_forms('<form action="/a"><textarea name="body">hi</textarea></form>', "http://t/")
        self.assertIn("body", [field.name for field in forms[0].fields])

    def test_a_select_is_a_field(self):
        document = '<form action="/a"><select name="mode"><option value="1">one</option></select></form>'
        forms = parse_forms(document, "http://t/")
        self.assertIn("mode", [field.name for field in forms[0].fields])

    def test_a_button_without_a_name_is_not_a_field(self):
        document = '<form action="/a"><button>go</button><input name="q"></form>'
        forms = parse_forms(document, "http://t/")
        self.assertEqual([field.name for field in forms[0].fields], ["q"])

    def test_an_input_without_a_name_is_ignored(self):
        document = '<form action="/a"><input value="x"><input name="q"></form>'
        forms = parse_forms(document, "http://t/")
        self.assertEqual([field.name for field in forms[0].fields], ["q"])

    def test_a_page_with_no_form_yields_nothing(self):
        self.assertEqual(parse_forms("<html><body>nothing</body></html>", "http://t/"), [])


class RequestFromForm(unittest.TestCase):
    def test_a_get_form_puts_the_fields_in_the_query(self):
        forms = parse_forms('<form action="/search" method="get"><input name="q" value="abc"></form>', "http://t/")
        request = form_request(forms[0], "http://t/")
        self.assertEqual(request.method, "GET")
        self.assertIn("q=abc", request.url)

    def test_a_post_form_urlencodes_the_body(self):
        forms = parse_forms('<form action="/s" method="post"><input name="u" value="http://x"></form>', "http://t/")
        request = form_request(forms[0], "http://t/")
        self.assertEqual(request.method, "POST")
        self.assertIn(b"u=", request.body)
        self.assertNotIn(b"http://x", request.body, "the value should be encoded in the body")

    def test_a_file_field_makes_the_form_multipart(self):
        document = (
            '<form action="/up" method="post" enctype="multipart/form-data">'
            '<input type="file" name="f"><input name="note" value="n"></form>'
        )
        forms = parse_forms(document, "http://t/")
        request = form_request(forms[0], "http://t/")
        self.assertIn("multipart/form-data", request.headers.get("Content-Type", ""))
        self.assertIn(b'name="note"', request.body)

    def test_the_query_string_of_the_action_is_kept(self):
        forms = parse_forms('<form action="/search?lang=en" method="post"><input name="q"></form>', "http://t/")
        request = form_request(forms[0], "http://t/")
        self.assertIn("lang=en", request.url)


if __name__ == "__main__":
    unittest.main()
