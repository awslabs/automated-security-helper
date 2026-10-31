# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A line a location states and this module cannot read is not an absent line.

An absent line matches at file level. A line given as ``10.5`` or ``"abc"`` read as
no line too, so the location matched every line of its file; ``10.0`` was refused
as well. ``str.isdigit`` admits a superscript digit that ``int()`` rejects, which
raised ValueError out of the whole aggregation check, from the line helper and from
an indexed field path with a superscript in the brackets.
"""

import sys

import pytest

from automated_security_helper.utils.meta_analysis.field_mapping import (
    get_value_from_path,
    parse_field_path,
)
from automated_security_helper.utils.meta_analysis.locations_match import (
    _line_number,
    locations_match,
)

pytestmark = pytest.mark.unit

#: U+00B2, which str.isdigit accepts and int() refuses.
SUPERSCRIPT_TWO = chr(0xB2)
#: U+0663, an Arabic-Indic digit three, which int() reads as 3.
ARABIC_INDIC_THREE = chr(0x663)


def _sarif(uri="a.py", start=3, end=5):
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": start, "endLine": end},
        }
    }


def test_a_float_of_a_whole_value_is_the_line_it_names():
    assert locations_match(_sarif(start=3.0, end=5.0), _sarif()) is True
    # And it is a line, not a wildcard: far from 3 to 5, it does not match.
    assert locations_match(_sarif(start=30.0, end=40.0), _sarif()) is False
    assert locations_match(_sarif(), _sarif(start=30.0, end=40.0)) is False


@pytest.mark.parametrize(
    "bad",
    [10.5, "abc", True, float("nan"), float("inf"), "1e3", "-3", ""],
    ids=repr,
)
def test_a_stated_line_that_reads_as_no_line_matches_nothing(bad):
    # Each read as an absent line, which matches at file level, so all of these
    # matched every line of the file.
    assert locations_match(_sarif(start=bad, end=bad), _sarif()) is False
    assert locations_match(_sarif(), _sarif(start=bad, end=bad)) is False
    # One readable line beside an unreadable one is still not a placeable range.
    assert locations_match(_sarif(start=3, end=bad), _sarif()) is False


def test_a_superscript_digit_is_no_line_and_raises_nothing():
    assert _line_number(SUPERSCRIPT_TWO) is None
    location = _sarif(start=SUPERSCRIPT_TWO, end=SUPERSCRIPT_TWO)
    assert locations_match(location, _sarif()) is False


def test_an_absent_line_still_matches_at_file_level():
    """The control: nothing stated is not the same as something unreadable."""
    artifact = {"uri": "a.py"}
    no_region = {"physicalLocation": {"artifactLocation": artifact}}
    empty_region = {"physicalLocation": {"artifactLocation": artifact, "region": {}}}
    null_lines = _sarif(start=None, end=None)

    for location in (no_region, empty_region, null_lines):
        assert locations_match(location, _sarif()) is True
        assert locations_match(_sarif(), location) is True


@pytest.fixture
def small_digit_limit():
    """The interpreter's limit on digits converted to an integer, at its minimum
    for the test, so a long digit string raises without a huge one."""
    if not hasattr(sys, "set_int_max_str_digits"):
        pytest.skip("this interpreter has no limit on integer string conversion")
    original = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    yield 700
    sys.set_int_max_str_digits(original)


@pytest.mark.parametrize(
    "value, expected",
    [
        (7, 7),
        (10.0, 10),
        ("10", 10),
        (" 7 ", 7),
        (ARABIC_INDIC_THREE, 3),
        (2.5, None),
        (True, None),
        (SUPERSCRIPT_TWO, None),
        (None, None),
    ],
    ids=lambda value: ascii(value)[:20],
)
def test_the_line_number_reading(value, expected):
    assert _line_number(value) == expected


def test_more_digits_than_the_interpreter_converts_is_no_line(small_digit_limit):
    assert _line_number("9" * small_digit_limit) is None


def test_a_superscript_index_in_a_field_path_is_no_path(small_digit_limit):
    # int() of the superscript raised ValueError, out of every caller that
    # parses a path.
    path = f"a[{SUPERSCRIPT_TWO}]"
    assert parse_field_path(path) is None
    assert parse_field_path("a[" + "9" * small_digit_limit + "]") is None
    assert get_value_from_path({"a": [1, 2, 3]}, path) == {
        "exists": False,
        "value": None,
    }
    # An ASCII index is read as before.
    assert parse_field_path("a[1]") == [("key", "a"), ("index", 1)]
