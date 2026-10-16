"""The command injection module's judgements, offline.

These lock the things that were measured rather than reasoned about while the
module was written, because every one of them is the kind of wrong that still
looks right:
a proof that computes differently per dialect, a rewrite that is valid in one
shell and not another, and three rewrites that were tried and do not work.
"""

from __future__ import annotations

import unittest

from injectorkit.core.mutate import Kind, applicable, generations
from injectorkit.engine.arithmetic import Arithmetic
from injectorkit.modules.cmdi.mutators import register as register_mutators
from injectorkit.modules.cmdi.seeds import (
    CMD,
    DELIVERIES,
    POSIX,
    SHELLS,
    question,
    seeds,
)

register_mutators()


def names() -> set[str]:
    return {mutator.name for mutator in applicable(Kind.COMMAND)}


class WhatAProofLooksLikeInEachDialect(unittest.TestCase):
    def test_posix_computes_in_an_arithmetic_expansion(self):
        arithmetic = Arithmetic()
        self.assertIn("$((", question(POSIX, arithmetic, DELIVERIES[0]))

    def test_cmd_uses_a_set_statement(self):
        # `echo set /a 1+2` prints the expression, which is the one thing the
        # proof must not do.
        arithmetic = Arithmetic()
        text = question(CMD, arithmetic, DELIVERIES[0])
        self.assertIn("set /a", text)
        self.assertNotIn("echo set", text)

    def test_cmd_joins_with_ampersand_not_semicolon(self):
        self.assertEqual(CMD.join, " & ")

    def test_the_proof_never_carries_its_own_answer(self):
        arithmetic = Arithmetic()
        for shell in SHELLS:
            for delivery in DELIVERIES:
                self.assertNotIn(arithmetic.answer, question(shell, arithmetic, delivery))

    def test_powershell_prints_and_computes_its_own_way(self):
        # Measured on pwsh 7: the POSIX spelling answers `\5` where the proof
        # wants `5`, so this is a different language rather than the same one
        # under another name, and the seed has to be written in the one there.
        from injectorkit.modules.cmdi.seeds import POWERSHELL

        arithmetic = Arithmetic()
        text = question(POWERSHELL, arithmetic, DELIVERIES[0])
        self.assertIn("Write-Output", text)
        self.assertIn(f"({arithmetic.left}+{arithmetic.right})", text)
        self.assertNotIn("$((", text)

    def test_each_dialect_prints_a_literal_and_a_sum(self):
        # The whole language requirement: if a shell cannot do these two, the
        # question cannot be asked in it at all.
        arithmetic = Arithmetic()
        for shell in SHELLS:
            text = question(shell, arithmetic, DELIVERIES[0])
            self.assertIn(arithmetic.open, shell.literal(arithmetic.open), shell.name)
            self.assertIn(shell.total(arithmetic.left, arithmetic.right), text, shell.name)

    def test_every_delivery_marks_out_a_way_in(self):
        for delivery in DELIVERIES:
            self.assertTrue(delivery.why, delivery.name)

    def test_the_direct_delivery_needs_nothing(self):
        first = DELIVERIES[0]
        self.assertEqual((first.prefix, first.suffix), ("", ""))

    def test_there_is_one_seed_per_delivery(self):
        arithmetic = Arithmetic()
        self.assertEqual(len(seeds(arithmetic, POSIX)), len(DELIVERIES))


class DialectsGateRewritesRatherThanDroppingThem(unittest.TestCase):
    """A rewrite one shell cannot run is held back, not removed."""

    def test_posix_refuses_the_bash_only_family(self):
        self.assertFalse(POSIX.allows("cmd-brace"))

    def test_bash_allows_what_posix_does_not(self):
        from injectorkit.modules.cmdi.seeds import BASH

        self.assertTrue(BASH.allows("cmd-brace"))

    def test_cmd_refuses_the_posix_expansion_rewrites(self):
        for family in ("cmd-space", "cmd-brace", "cmd-compute"):
            self.assertFalse(CMD.allows(family), family)

    def test_the_bash_only_rewrite_exists_in_the_catalogue(self):
        # Held back for dash, not deleted: a bash target runs it.
        self.assertIn("cmd-space-brace", names())


class WhatWasMeasuredAndLeftOut(unittest.TestCase):
    """Registrations refused, with the reason, so they are not added back."""

    def test_bare_ifs_is_absent(self):
        # `echo$IFSA` reads the variable `IFSA`, which is empty, so the command
        # prints nothing. Measured on dash: the braces and the positional form
        # both work, the bare one does not.
        self.assertNotIn("cmd-space-ifs", names())
        self.assertIn("cmd-space-ifs-brace", names())
        self.assertIn("cmd-space-ifs-positional", names())

    def test_the_substitution_wrappers_are_absent(self):
        # `ping ... $(echo A; echo 5; echo B)` answers
        # `ping: B: Name or service not known`: the command runs and the proof
        # comes back as an argument instead of as output.
        self.assertNotIn("cmd-wrap-backtick", names())
        self.assertNotIn("cmd-wrap-subshell", names())

    def test_the_separator_family_exists_because_the_proof_joins_statements(self):
        # The proof is three statements, so its own joiners are characters a
        # filter can key on: a rule blocking `;` blocks every seed the module
        # builds until they change too.
        self.assertIn("cmd-sep-newline", names())
        self.assertIn("cmd-sep-amp", names())

    def test_the_pipe_form_is_absent(self):
        # `; echo A| echo B| echo C` answers with one marker instead of three:
        # the payload runs and the proof never comes back, which reads as a miss
        # on a target where the injection worked.
        self.assertNotIn("cmd-sep-pipe", names())


class ExcludingAFamilyKeepsItOut(unittest.TestCase):
    def families_of(self, variants) -> set[str]:
        """The families a set of variants used. `Variant.mutators` holds names."""
        from injectorkit.core.mutate import mutator

        return {mutator(name).family for variant in variants for name in variant.mutators}

    def test_an_excluded_family_produces_no_variant(self):
        seed = "; echo IKOPEN; echo IKCLOSE"
        plain = generations(seed, Kind.COMMAND, max_generation=2, limit=200)
        held = generations(
            seed,
            Kind.COMMAND,
            max_generation=2,
            limit=200,
            exclude_families=frozenset({"cmd-space"}),
        )
        self.assertIn("cmd-space", self.families_of(plain))
        self.assertNotIn("cmd-space", self.families_of(held))

    def test_generation_zero_survives_any_exclusion(self):
        # The seed is always sent, whatever is held back.
        seed = "; echo IKOPEN; echo IKCLOSE"
        held = generations(
            seed, Kind.COMMAND, max_generation=2, limit=200, exclude_families=frozenset({"cmd-space"})
        )
        self.assertEqual([v for v in held if v.generation == 0][0].value, seed)

    def test_a_rewrite_of_a_different_family_still_applies(self):
        seed = "; echo IKOPEN; echo IKCLOSE"
        held = generations(
            seed,
            Kind.COMMAND,
            max_generation=2,
            limit=200,
            exclude_families=frozenset({"cmd-space"}),
        )
        self.assertIn("cmd-name", self.families_of(held))


class TheFourAnswers(unittest.TestCase):
    """Filtered and unreached are different findings and are said differently."""

    def _ctx(self, refusals: int):
        bypass = type("B", (), {"refusals": lambda self: refusals})()
        return type("C", (), {"bypass": bypass})()

    def test_a_refused_run_says_it_was_not_reached_rather_than_ruled_out(self):
        from injectorkit.modules.cmdi.graph import verdict

        text = verdict(self._ctx(47))
        self.assertIn("nothing got past the filter", text)
        self.assertIn("not reached, not ruled out", text)

    def test_an_unrefused_run_says_the_parameter_does_not_appear_to_reach_a_shell(self):
        from injectorkit.modules.cmdi.graph import verdict

        text = verdict(self._ctx(0))
        self.assertIn("nothing was refused", text)
        self.assertNotIn("filter", text)

    def test_the_two_are_not_the_same_sentence(self):
        from injectorkit.modules.cmdi.graph import verdict

        self.assertNotEqual(verdict(self._ctx(0)), verdict(self._ctx(1)))


class OutputSurvivesTheTarget(unittest.TestCase):
    def test_a_stream_that_cannot_be_reconfigured_is_not_fatal(self):
        # A response body is decoded so that no byte is lost, so any byte above
        # 0x7f becomes a character - and a console that cannot show it raises on
        # print. Measured on Windows: a run died printing the command output it
        # had just gone and got.
        import io
        import sys as _sys

        from injectorkit.runtime import make_output_safe

        saved = (_sys.stdout, _sys.stderr)
        try:
            _sys.stdout, _sys.stderr = io.StringIO(), io.StringIO()
            make_output_safe()
            make_output_safe()
        finally:
            _sys.stdout, _sys.stderr = saved

    def test_it_narrows_the_error_handler_on_a_real_stream(self):
        import io
        import sys as _sys

        from injectorkit.runtime import make_output_safe

        stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        saved = (_sys.stdout, _sys.stderr)
        try:
            _sys.stdout, _sys.stderr = stream, stream
            make_output_safe()
            stream.write("caf\N{LATIN SMALL LETTER E WITH ACUTE}")  # not ascii
            stream.flush()
        finally:
            _sys.stdout, _sys.stderr = saved


if __name__ == "__main__":
    unittest.main()
