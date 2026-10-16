"""Asking for something only execution can produce.

A page that echoes a payload back will happily return the word "echo", the
marker, and everything around them. So a check for a marker the payload itself
contains proves nothing - an application that never executed anything passes it.

What it cannot return by echoing is the *result* of the arithmetic. The payload
carries `$((8649+7150))`; the response has to carry `15799`.
"""

from __future__ import annotations

import unittest

from injectorkit.engine.arithmetic import Arithmetic


class TheQuestion(unittest.TestCase):
    def test_the_command_carries_the_addition_not_the_sum(self):
        check = Arithmetic()
        command = check.command()
        self.assertIn(str(check.left), command)
        self.assertIn(str(check.right), command)
        self.assertNotIn(check.answer, command)

    def test_the_markers_are_fresh_each_time(self):
        # An earlier attempt's output - still sitting in a log - must not be
        # mistaken for this one's.
        first, second = Arithmetic(), Arithmetic()
        self.assertNotEqual(first.open, second.open)
        self.assertNotEqual(first.close, second.close)

    def test_the_answer_is_the_sum(self):
        check = Arithmetic()
        check.left, check.right = 1234, 5678
        self.assertEqual(check.answer, "6912")

    def test_a_caller_can_supply_its_own_expression(self):
        check = Arithmetic()
        self.assertIn("echo $((7*6))", check.command("$((7*6))"))


class WhatCountsAsProof(unittest.TestCase):
    def test_echoing_the_payload_back_is_not_proof(self):
        # The whole reason this exists. The page returned exactly what was sent
        # and nothing ran.
        check = Arithmetic()
        page = f"<textarea>{check.command()}</textarea>"
        self.assertIsNone(check.proved(page))

    def test_the_sum_between_the_markers_is_proof(self):
        check = Arithmetic()
        page = f"<pre>{check.open}\n{check.answer}\n{check.close}</pre>"
        self.assertEqual(check.proved(page), check.answer)

    def test_the_markers_without_the_sum_are_not_proof(self):
        check = Arithmetic()
        page = f"{check.open}not the number{check.close}"
        self.assertIsNone(check.proved(page))

    def test_missing_markers_are_not_proof(self):
        check = Arithmetic()
        self.assertIsNone(check.proved("a page with nothing in it"))

    def test_an_unclosed_pair_is_not_proof(self):
        check = Arithmetic()
        self.assertIsNone(check.proved(f"{check.open}{check.answer}"))

    def test_a_wrong_number_is_not_proof(self):
        # A page full of digits must not satisfy a check by accident.
        check = Arithmetic()
        page = f"{check.open}999999{check.close}"
        self.assertIsNone(check.proved(page))

    def test_the_surroundings_do_not_matter(self):
        # The answer arrives inside a wall of other output, as it does from a log.
        check = Arithmetic()
        page = (
            "1.2.3.4 - - \"GET / HTTP/1.1\" 200 9 \"-\" \"curl\"\n"
            f"some earlier line {check.open}{check.answer}{check.close} trailing\n"
        )
        self.assertEqual(check.proved(page), check.answer)

    def test_the_latest_pair_is_the_one_that_counts(self):
        # An old run's markers, complete and correct, must not answer for this
        # one. Only the last pair is this attempt's.
        old = Arithmetic()
        check = Arithmetic()
        page = f"{old.open}{old.answer}{old.close}"
        page += f"{check.open}{check.answer}{check.close}"
        self.assertEqual(check.proved(page), check.answer)


    def test_the_answer_is_found_whichever_order_the_page_prints_it_in(self):
        """A page may echo the command before running it or after, and neither
        order can be assumed. Looking only at the last marker pair reports a
        target that ran the command as one that did not."""
        arithmetic = Arithmetic()
        payload = arithmetic.command()
        before = f"running: {payload}\n{arithmetic.open}\n{arithmetic.answer}\n{arithmetic.close}\n"
        after = f"{arithmetic.open}\n{arithmetic.answer}\n{arithmetic.close}\nrunning: {payload}\n"
        self.assertEqual(arithmetic.proved(before), arithmetic.answer)
        self.assertEqual(arithmetic.proved(after), arithmetic.answer)

    def test_an_echoed_payload_alone_still_proves_nothing(self):
        arithmetic = Arithmetic()
        self.assertIsNone(arithmetic.proved(f"running: {arithmetic.command()}"))


if __name__ == "__main__":
    unittest.main()
