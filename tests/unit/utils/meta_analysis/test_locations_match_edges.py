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
    "location, expected",
    [
        # No physicalLocation, or no artifactLocation: the location names no file,
        # and the other side names a.py, so they are not one place.
        ({"physicalLocation": None}, False),
        ({"physicalLocation": {"artifactLocation": None, "region": None}}, False),
        # The file is a.py and there is no region: a match at file level.
        (
            {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": None}},
            True,
        ),
    ],
    ids=["null-physical-location", "null-artifact-and-region", "null-region"],
)
def test_a_null_sub_object_is_read_as_absent(location, expected):
    # Raised TypeError ("argument of type 'NoneType' is not iterable") before. The
    # answer is each case's own, and the same from either side: asserting only a
    # boolean would also pass a null sub-object that matched everything.
    assert locations_match(location, _sarif()) is expected
    assert locations_match(_sarif(), location) is expected
    # A null sub-object does not make the location match a different file either.
    assert locations_match(location, _sarif(uri="other.py")) is False
    assert locations_match(_sarif(uri="other.py"), location) is False


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


def test_a_percent_escape_in_a_file_uri_is_decoded_as_aggregation_decodes_it():
    # Aggregation decodes a file:// URI when it turns it into a path, so the
    # scanner's a%20b.py meets the aggregate's "a b.py".
    assert _normalize_file_path("file:///work/a%20b.py") == "/work/a b.py"
    assert _normalize_file_path("file:///work/caf%C3%A9.py") == "/work/café.py"
    assert file_paths_match("file:///work/app/src/a%20b.py", "src/a b.py")
    # A relative URI is written as spelled, escapes included, so it is compared
    # as spelled: decoding it read a%20b.py against the aggregate's a%20b.py as
    # two files.
    assert _normalize_file_path("src/caf%C3%A9.py") == "src/caf%C3%A9.py"
    assert file_paths_match("src/a%20b.py", "src/a%20b.py")
    # A name with no escape in it is untouched.
    assert _normalize_file_path("src/100%.py") == "src/100%.py"


def test_a_literal_escape_in_a_file_name_is_not_decoded_twice():
    # A file named a%20b.py is spelled a%2520b.py in a file:// URI; aggregation
    # decodes it once to a%20b.py. Decoding both sides read the aggregate's copy
    # as "a b.py" and reported the location as lost.
    assert _normalize_file_path("file:///work/app/src/a%2520b.py") == (
        "/work/app/src/a%20b.py"
    )
    assert file_paths_match("file:///work/app/src/a%2520b.py", "src/a%20b.py")
    assert not file_paths_match("file:///work/app/src/a%2520b.py", "src/a b.py")
