# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for scanner version-pin compatibility.

The interesting cases are the ones where the verdict has to be UNDECIDABLE
rather than a guess, and the ones where two pins overlap only at a single
version. Both directions matter: a wrong COMPATIBLE lets a project be scanned
by a tool version it excluded, a wrong INCOMPATIBLE only costs an error message.
"""

import pytest

from automated_security_helper.workspace.scanner_pins import (
    PinVerdict,
    compare_pins,
)


# ---------------------------------------------------------------------------
# Identical and trivially-overlapping pins
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pin",
    [
        ">=1.7.0,<2.0.0",
        "==1.2.3",
        "~=1.4.5",
        ">=1.0",
        "!=1.5.0",
        # An unparseable pin still compares equal to itself without a solver.
        ">=1.0.0rc1",
        "@some-nonsense",
    ],
)
def test_identical_pins_are_compatible(pin):
    assert compare_pins(pin, pin) is PinVerdict.COMPATIBLE


def test_whitespace_only_difference_is_compatible():
    assert compare_pins(">=1.7.0, <2.0.0", ">=1.7.0,<2.0.0") is PinVerdict.COMPATIBLE


def test_specifier_order_only_difference_is_compatible():
    assert compare_pins("<2.0.0,>=1.7.0", ">=1.7.0,<2.0.0") is PinVerdict.COMPATIBLE


# ---------------------------------------------------------------------------
# Compatible but different
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "a,b",
    [
        # A tighter lower bound still leaves the whole upper range.
        (">=1.0", ">=2.0"),
        (">=1.7.0,<2.0.0", ">=1.8.0"),
        # Overlapping windows.
        (">=1.0,<2.0", ">=1.5,<3.0"),
        # Exactly one version in common.
        ("<=1.5.0", ">=1.5.0"),
        ("==1.5.0", ">=1.0,<2.0"),
        # Compatible-release operator against a range it sits inside.
        ("~=1.4.5", ">=1.0,<2.0"),
        # A hole that does not empty the range.
        ("!=1.5.0", ">=1.0,<2.0"),
        # Prefix match inside a wider window.
        ("==1.4.*", ">=1.0,<2.0"),
        # Strict inequalities that leave room only for a deeper release
        # segment: 1.0.0.1 satisfies both.
        (">1.0.0", "<1.0.1"),
        # An empty pin constrains nothing.
        ("", ">=2.0"),
    ],
)
def test_overlapping_pins_are_compatible(a, b):
    assert compare_pins(a, b) is PinVerdict.COMPATIBLE
    assert compare_pins(b, a) is PinVerdict.COMPATIBLE


# ---------------------------------------------------------------------------
# Incompatible
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "a,b",
    [
        # Disjoint major ranges -- the motivating real case.
        (">=1.7.0,<2.0.0", ">=2.0.0"),
        (">=2.0.0,<3.0.0", ">=1.0.0,<2.0.0"),
        # Two different exact pins.
        ("==1.2.3", "==1.2.4"),
        # An exact pin excluded by the other side.
        ("==1.5.0", "!=1.5.0"),
        ("==1.5.0", ">1.5.0"),
        # Prefix matches on different prefixes.
        ("==1.4.*", "==1.5.*"),
        # Compatible-release against a major it forbids.
        ("~=1.4.5", ">=2.0"),
        # Bounds that cross.
        ("<1.0", ">=2.0"),
        # A single-point range with the point punched out.
        (">=1.5.0,<=1.5.0", "!=1.5.0"),
    ],
)
def test_disjoint_pins_are_incompatible(a, b):
    assert compare_pins(a, b) is PinVerdict.INCOMPATIBLE
    assert compare_pins(b, a) is PinVerdict.INCOMPATIBLE


# ---------------------------------------------------------------------------
# Undecidable -- must not be guessed either way
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "a,b",
    [
        # Pre-release, post-release, dev-release and local segments are outside
        # the modelled subset.
        (">=1.0.0rc1", ">=2.0"),
        (">=1.0.post1", "<2.0"),
        (">=1.0.dev0", "<2.0"),
        ("==1.0+local", ">=1.0"),
        # An explicit epoch.
        (">=1!1.0", ">=1.0"),
        # Not a specifier at all.
        ("latest", ">=1.0"),
        ("1.2.3", ">=1.0"),
        # An operator outside the modelled set.
        ("~1.2.3", ">=1.0"),
        # Arbitrary equality against a non-release string.
        ("===weird-build", ">=1.0"),
    ],
)
def test_unmodelled_pins_are_undecidable(a, b):
    assert compare_pins(a, b) is PinVerdict.UNDECIDABLE
    assert compare_pins(b, a) is PinVerdict.UNDECIDABLE


def test_arbitrary_equality_on_a_release_version_is_modelled():
    """``===1.2.3`` names one release version, so it can be compared."""
    assert compare_pins("===1.2.3", ">=1.0,<2.0") is PinVerdict.COMPATIBLE
    assert compare_pins("===1.2.3", ">=2.0") is PinVerdict.INCOMPATIBLE


def test_verdict_is_symmetric_over_a_grid():
    """Whatever the verdict, it must not depend on argument order."""
    pins = [
        ">=1.7.0,<2.0.0",
        ">=2.0.0",
        "==1.2.3",
        "~=1.4.5",
        "!=1.5.0",
        "<1.0",
        "==1.4.*",
        ">=1.0.0rc1",
        "",
    ]
    for a in pins:
        for b in pins:
            assert compare_pins(a, b) is compare_pins(b, a), (a, b)
