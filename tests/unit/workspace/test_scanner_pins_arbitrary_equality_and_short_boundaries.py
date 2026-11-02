# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two readings of a pin the solver got wrong, in opposite directions.

* ``===`` is arbitrary string equality (PEP 440), satisfied by the one version
  spelled exactly as written. Modelled as padded ``==`` equality, ``===1.0`` and
  ``===1.0.0`` read COMPATIBLE though no string is both: the wrong direction,
  a workspace accepted and then not installable for both projects.
* The witness search reached inside an open interval only one release segment
  deeper than the shallower boundary, so ``>1`` with ``<1.0.1`` (satisfied by
  ``1.0.0.1``) read INCOMPATIBLE: the safe direction, a refusal the operator
  could not act on, since the pins are satisfiable.
"""

import pytest

from automated_security_helper.workspace.scanner_pins import (
    PinVerdict,
    compare_pin_set,
    compare_pins,
)

pytestmark = pytest.mark.unit


class TestArbitraryEqualityIsStringEquality:
    def test_two_spellings_of_one_padded_version_are_incompatible(self):
        assert compare_pins("===1.0", "===1.0.0") is PinVerdict.INCOMPATIBLE

    def test_arbitrary_equality_meets_a_padded_equality_at_the_spelled_version(self):
        """``==1.0.0`` accepts ``1.0``; ``===1.0`` is that one spelling."""
        assert compare_pins("===1.0", "==1.0.0") is PinVerdict.COMPATIBLE

    def test_arbitrary_equality_inside_a_range_is_compatible(self):
        assert compare_pins("===1.0", ">=1,<2") is PinVerdict.COMPATIBLE

    def test_arbitrary_equality_outside_a_range_is_incompatible(self):
        assert compare_pins("===3.0", ">=1,<2") is PinVerdict.INCOMPATIBLE

    def test_the_set_reading_agrees(self):
        assert compare_pin_set(["===1.0", "===1.0.0", ">=1"]) is PinVerdict.INCOMPATIBLE
        assert compare_pin_set(["===1.0", "==1.0.0", ">=1"]) is PinVerdict.COMPATIBLE


class TestAnArbitraryEqualityTextWithALeadingZeroIsUndecidable:
    """``===1.00`` parses to the tuple ``(1, 0)`` as ``===1.0`` does, though the
    two name different strings, so the pair read COMPATIBLE: the wrong direction."""

    @pytest.mark.parametrize("text", ["===01.0", "===1.00", "===1.0.00"])
    def test_a_text_that_is_not_its_tuples_spelling_is_not_modelled(self, text):
        assert compare_pins(text, ">=1") is PinVerdict.UNDECIDABLE
        assert compare_pins(">=1", text) is PinVerdict.UNDECIDABLE

    def test_two_spellings_that_parse_alike_are_not_compatible(self):
        assert compare_pins("===1.0", "===1.00") is PinVerdict.UNDECIDABLE
        assert compare_pins("===1.00", "===01.0") is PinVerdict.UNDECIDABLE
        assert compare_pin_set(["===1.0", "===1.00"]) is PinVerdict.UNDECIDABLE

    def test_the_same_text_twice_is_still_compatible(self):
        """Textually identical pins are folded before they are parsed."""
        assert compare_pins("===1.00", "===1.00") is PinVerdict.COMPATIBLE

    def test_a_canonical_text_is_still_compared(self):
        assert compare_pins("===10.0", ">=1,<20") is PinVerdict.COMPATIBLE
        assert compare_pins("===10.0", ">=1,<2") is PinVerdict.INCOMPATIBLE


class TestTheWitnessSearchReachesEveryOpenInterval:
    @pytest.mark.parametrize(
        ("first", "second"),
        [
            (">1", "<1.0.1"),
            (">1.0", "<1.0.0.1"),
            (">1", "<1.0.0.0.1"),
            (">2.5", "<2.5.0.1"),
        ],
    )
    def test_a_region_below_a_deeper_boundary_is_found(self, first, second):
        """Each pair is satisfied by the shallower boundary zero-padded to the
        deeper one's length with a trailing ``1`` (``1.0.0.1`` for the first)."""
        assert compare_pins(first, second) is PinVerdict.COMPATIBLE
        assert compare_pins(second, first) is PinVerdict.COMPATIBLE

    def test_an_empty_region_is_still_refused(self):
        assert compare_pins(">=1.0.1", "<1.0.1") is PinVerdict.INCOMPATIBLE
        assert compare_pins(">1.0.1", "<=1.0.1") is PinVerdict.INCOMPATIBLE
