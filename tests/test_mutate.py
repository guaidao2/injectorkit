"""Turning one seed into a ladder of spellings.

Two rules here were learned the hard way and are pinned down below: the request
budget counts variants in total rather than per generation, and a value that is
already in transport form must not be encoded a second time.
"""

from __future__ import annotations

import unittest

from injectorkit.core.mutate import (
    Kind,
    Mutator,
    Variant,
    all_mutators,
    applicable,
    generations,
    mutator,
    register,
)


class VariantDescription(unittest.TestCase):
    def test_the_seed_itself_is_generation_zero(self):
        self.assertEqual(Variant(value="x", generation=0).describe(), "gen0 (x)")

    def test_a_mutation_lists_what_produced_it(self):
        described = Variant(value="X", generation=1, mutators=("upper-scheme",)).describe()
        self.assertIn("upper-scheme", described)


class GenerationZero(unittest.TestCase):
    def test_the_untouched_value_comes_first(self):
        # An unprotected target must cost one request per seed and never see a
        # mutation, so gen0 is always present and always at the front.
        variants = generations("http://example.com", Kind.SSRF, max_generation=2)
        self.assertEqual(variants[0].value, "http://example.com")
        self.assertEqual(variants[0].generation, 0)
        self.assertEqual(variants[0].mutators, ())

    def test_every_value_appears_once(self):
        variants = generations("http://example.com/path?x=1", Kind.SSRF, max_generation=3)
        values = [variant.value for variant in variants]
        self.assertEqual(len(values), len(set(values)))


class Budget(unittest.TestCase):
    def test_the_limit_bounds_the_total_not_each_generation(self):
        # Treating it as a per-generation budget lets generation two and beyond
        # never appear, which reads as "no bypass worked" when nothing was tried.
        bounded = generations("gopher://127.0.0.1:6379/_PING", Kind.PROTOCOL, max_generation=3, limit=5)
        self.assertLessEqual(len(bounded), 5)

    def test_a_later_generation_reaches_the_list(self):
        variants = generations("http://example.com", Kind.SSRF, max_generation=2, limit=60)
        self.assertTrue(any(variant.generation >= 1 for variant in variants))

    def test_generations_are_bounded_by_the_cap(self):
        variants = generations("http://example.com", Kind.SSRF, max_generation=1, limit=60)
        self.assertTrue(all(variant.generation <= 1 for variant in variants))


class EncodedValuesStayEncoded(unittest.TestCase):
    def test_an_encoded_value_is_never_encoded_again(self):
        # Encoding a value that is already in transport form makes the target
        # receive a literal percent sequence, so the bypass silently never
        # happens and the run reads as a failure rather than as a bug. The check
        # is on the mutator's own claim - `produces_encoded` - not on its name.
        encoders = {item.name for item in all_mutators() if item.produces_encoded}
        if not encoders:
            self.skipTest("no mutator claims to produce an encoded value")
        variants = generations("http://example.com/a%2Fb", Kind.SSRF, max_generation=3, limit=120)
        for variant in variants:
            if not variant.encoded:
                continue
            first = next((index for index, name in enumerate(variant.mutators) if name in encoders), None)
            if first is None:
                continue
            self.assertFalse(
                set(variant.mutators[first + 1:]) & encoders,
                f"{variant.describe()} encoded an already-encoded value",
            )


class MutatorSelection(unittest.TestCase):
    def test_a_mutator_with_no_kinds_applies_everywhere(self):
        self.assertTrue(Mutator(name="any", apply=lambda value: value).matches(Kind.SSRF))

    def test_a_scoped_mutator_only_matches_its_kinds(self):
        scoped = Mutator(name="only-ssrf", apply=lambda value: value, kinds=(Kind.SSRF,))
        self.assertTrue(scoped.matches(Kind.SSRF))
        self.assertFalse(scoped.matches(Kind.PROTOCOL))

    def test_an_exclusion_wins_over_an_inclusion(self):
        excluded = Mutator(
            name="not-protocol",
            apply=lambda value: value,
            kinds=(Kind.SSRF, Kind.PROTOCOL),
            excludes=(Kind.PROTOCOL,),
        )
        self.assertFalse(excluded.matches(Kind.PROTOCOL))

    def test_a_family_already_used_is_not_offered_again(self):
        all_names = {item.name for item in applicable(Kind.SSRF)}
        self.assertTrue(all_names)
        family = next((item.family for item in all_mutators() if item.family), "")
        if family:
            reduced = {item.name for item in applicable(Kind.SSRF, frozenset({family}))}
            self.assertLess(len(reduced), len(all_names))


class Registry(unittest.TestCase):
    def test_the_builtin_catalogue_is_loaded(self):
        names = [item.name for item in all_mutators()]
        self.assertGreater(len(names), 5)
        self.assertEqual(len(names), len(set(names)), "a name is registered twice")

    def test_registering_twice_does_not_double_the_catalogue(self):
        # A module registers when it is imported, and a test that imports it may
        # register again. Two entries under one name is a rewrite sent twice.
        before = [item.name for item in all_mutators()]
        item = all_mutators()[0]
        register(item)
        self.assertEqual([entry.name for entry in all_mutators()], before)

    def test_every_rewrite_fits_in_one_generation(self):
        """A budget smaller than the catalogue is a rewrite that is never sent.

        The budget used to be a fixed number, and two of the classes already had
        more rewrites than it - so whichever ones ranked last were never tried,
        silently. Adding a rewrite has to widen the generation, not starve the
        one at the end of it.
        """
        from injectorkit.engine.inject import generation_budget

        for kind in Kind:
            available = len(applicable(kind))
            if not available:
                continue
            self.assertGreaterEqual(
                generation_budget(kind, frozenset()),
                available,
                f"{kind.value}: the generation is smaller than its catalogue",
            )

    def test_the_catalogue_stays_under_the_generation_ceiling(self):
        """When the catalogue reaches the ceiling the two rules conflict.

        The budget is the catalogue when the catalogue is smaller, so every
        rewrite reaches the wire; the ceiling caps it so a grown catalogue cannot
        turn one parameter into a flood. Past the ceiling a rewrite starts being
        dropped for want of budget, and that has to be a failing test rather than
        something somebody notices later.
        """
        from injectorkit.engine.inject import GENERATION_CEILING

        for kind in Kind:
            available = len(applicable(kind))
            if not available:
                continue
            self.assertLess(
                available,
                GENERATION_CEILING,
                f"{kind.value}: the catalogue has reached the ceiling, so a rewrite is being "
                "dropped for want of budget - raise GENERATION_CEILING or split the family",
            )

    def test_a_mutator_can_be_found_by_name(self):
        first = all_mutators()[0]
        self.assertIs(mutator(first.name), first)

    def test_every_mutator_has_a_callable(self):
        for item in all_mutators():
            self.assertTrue(callable(item.apply), item.name)


if __name__ == "__main__":
    unittest.main()
