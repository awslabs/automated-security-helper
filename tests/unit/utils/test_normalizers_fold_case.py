# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A normalized name can be made unique on a filesystem that ignores case.

``get_normalized_filename`` keeps letters as they are, so ``A.yaml`` and ``a.yaml``
are two names and one directory on APFS and NTFS, and the second input's output
overwrote the first's. ``fold_case=True`` escapes every letter that has a
lower-case form, so two names that differ in case alone stay apart. The default
is unchanged, because it names files and directories already written.
"""

import pytest

from automated_security_helper.utils.normalizers import get_normalized_filename

pytestmark = pytest.mark.unit

#: U+00C9, a capital with a lower-case form of its own.
E_ACUTE_CAPITAL = chr(0xC9)
#: U+01C5, a title-case letter: neither the capital nor the small form.
DZ_TITLE_CASE = chr(0x1C5)
#: U+01C6, the small form of the title-case letter above.
DZ_SMALL = chr(0x1C6)
#: U+212A, the Kelvin sign, which lower-cases to a plain k.
KELVIN = chr(0x212A)


def test_the_default_keeps_letters_as_they_are():
    assert get_normalized_filename("A.yaml") == "A__yaml"
    assert get_normalized_filename("a.yaml") == "a__yaml"
    assert get_normalized_filename("Dockerfile") == "Dockerfile"


def test_with_fold_case_a_capital_is_its_code_point():
    assert get_normalized_filename("A.yaml", fold_case=True) == "_x41__yaml"
    assert get_normalized_filename("a.yaml", fold_case=True) == "a__yaml"
    assert get_normalized_filename(E_ACUTE_CAPITAL, fold_case=True) == "_xc9"
    assert get_normalized_filename("Dockerfile", fold_case=True) == "_x44ockerfile"


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("A.yaml", "a.yaml"),
        ("Dir/File.yaml", "dir/file.yaml"),
        ("dir/File.yaml", "Dir/file.yaml"),
        ("README", "readme"),
        (DZ_TITLE_CASE, DZ_SMALL),
        (KELVIN, "k"),
        (E_ACUTE_CAPITAL, E_ACUTE_CAPITAL.lower()),
    ],
)
def test_names_that_differ_in_case_alone_stay_apart_when_case_is_ignored(left, right):
    folded_left = get_normalized_filename(left, fold_case=True)
    folded_right = get_normalized_filename(right, fold_case=True)

    assert folded_left.lower() != folded_right.lower()


#: U+03C2, the final sigma: lower-case already, and it folds to U+03C3.
SIGMA_FINAL = chr(0x3C2)
#: U+03C3, the sigma.
SIGMA = chr(0x3C3)
#: U+017F, the long s: lower-case already, and it folds to a plain s.
LONG_S = chr(0x17F)
#: U+00B5, the micro sign: lower-case already, and it folds to U+03BC.
MICRO = chr(0xB5)
#: U+03BC, the Greek small mu.
MU = chr(0x3BC)
#: U+0131, the dotless i: lower-case, its own folding, and a plain I in capitals.
DOTLESS_I = chr(0x131)


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (SIGMA_FINAL, SIGMA),
        (LONG_S, "s"),
        (MICRO, MU),
        (DOTLESS_I, "i"),
        ("x" + SIGMA_FINAL + "y.yaml", "x" + SIGMA + "y.yaml"),
    ],
)
def test_letters_that_fold_to_one_stay_apart_when_case_is_ignored(left, right):
    """A case-insensitive filesystem folds with the case-folding table or the
    upper-case one, not with ``str.lower``: each pair below is lower-case on both
    sides and is still one name there."""
    folded_left = get_normalized_filename(left, fold_case=True)
    folded_right = get_normalized_filename(right, fold_case=True)

    assert left.casefold() == right.casefold() or left.upper() == right.upper()
    assert folded_left.casefold() != folded_right.casefold()
    assert folded_left.upper() != folded_right.upper()


def test_a_letter_that_is_its_own_folding_still_passes_through():
    """The control: fold_case escapes what can collide, not every non-ASCII
    letter, and it leaves the digits and the plain lower-case letters alone."""
    assert get_normalized_filename(SIGMA, fold_case=True) == SIGMA
    assert get_normalized_filename(MU, fold_case=True) == MU
    assert get_normalized_filename("a5", fold_case=True) == "a5"
    assert get_normalized_filename(SIGMA_FINAL, fold_case=True) == "_u03c2"
    assert get_normalized_filename(LONG_S, fold_case=True) == "_u017f"
    assert get_normalized_filename(MICRO, fold_case=True) == "_xb5"
    assert get_normalized_filename(DOTLESS_I, fold_case=True) == "_u0131"


def test_by_default_two_names_that_differ_in_case_alone_are_one_name_there():
    """What fold_case is for: the capitals pass through, so a case-insensitive
    filesystem sees one name."""
    assert get_normalized_filename("A.yaml").lower() == (
        get_normalized_filename("a.yaml").lower()
    )


def test_distinct_names_stay_distinct_with_fold_case():
    names = ["a", "A", "a.b", "A.b", "a_b", "a/b", "A/b", "a b", "A B", "-a", "-A"]

    folded = [get_normalized_filename(name, fold_case=True) for name in names]

    assert len({name.lower() for name in folded}) == len(names)


def test_fold_case_leaves_no_capital_in_a_name_below_the_astral_planes():
    """The one capital the scheme can write is the ``U`` of the eight-digit token
    for a code point above 0xFFFF, which no four-digit token reads as once
    lower-cased."""
    name = get_normalized_filename("Hello World/Caf" + E_ACUTE_CAPITAL, fold_case=True)

    assert name == name.lower()
