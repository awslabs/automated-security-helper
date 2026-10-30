# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``locations_match`` at the edges of what a scanner's SARIF carries.

A ``physicalLocation``, ``artifactLocation`` or ``region`` given as JSON null raised
TypeError; a line number given as a digit string raised TypeError on the first
``<=``; a side with no start line was a wildcard that matched any range; and a
POSIX path such as ``/a:/file`` lost its leading slash to the drive-letter rule.
"""

import pytest

from automated_security_helper.utils.meta_analysis.locations_match import (
    _line_ranges_compatible,
    _normalize_file_path,
    file_paths_match,
    locations_match,
)

pytestmark = pytest.mark.unit


def _sarif(uri="a.py", start=3, end=5):
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": start, "endLine": end},
        }
    }


@pytest.mark.parametrize(
    "location",
    [
        {"physicalLocation": None},
        {"physicalLocation": {"artifactLocation": None, "region": None}},
        {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": None}},
    ],
)
def test_a_null_sub_object_is_read_as_absent(location):
    # Raised TypeError ("argument of type 'NoneType' is not iterable") before.
    assert locations_match(location, _sarif()) in (True, False)
    assert locations_match(_sarif(), location) in (True, False)


def test_a_null_region_matches_at_file_level():
    assert (
        locations_match(
            {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": None}},
            _sarif(),
        )
        is True
    )


def test_a_digit_string_line_is_the_integer_it_spells():
    # Raised TypeError ("'<=' not supported between 'str' and 'int'") before.
    assert locations_match(_sarif(start="3", end="5"), _sarif()) is True
    assert locations_match(_sarif(start="30", end="40"), _sarif()) is False
    assert locations_match(
        {"file_path": "a.py", "start_line": "3", "end_line": "5"}, _sarif()
    )


def test_a_missing_start_line_is_the_end_line_alone_not_a_wildcard():
    # A lone end line of 10 against lines 100 to 120 read as compatible.
    assert _line_ranges_compatible(None, 10, 100, 120) is False
    assert _line_ranges_compatible(100, 120, None, 10) is False
    # The end line inside the other range is compatible, as before.
    assert _line_ranges_compatible(None, 15, 10, 15) is True
    assert _line_ranges_compatible(None, 12, 10, 15) is True
    # Two lone end lines: equal or close.
    assert _line_ranges_compatible(None, 12, None, 12) is True
    assert _line_ranges_compatible(None, 12, None, 40) is False


def test_a_posix_path_whose_third_character_is_a_colon_keeps_its_slash():
    # Only a letter before the colon is a drive; "1:" is a POSIX name.
    assert _normalize_file_path("file:///1:/file.py") == "/1:/file.py"
    assert _normalize_file_path("file:///C:/proj/a.py") == "C:/proj/a.py"
    assert file_paths_match("file:///1:/file.py", "/1:/file.py")
