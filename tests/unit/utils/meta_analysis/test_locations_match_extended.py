import pytest

from automated_security_helper.utils.meta_analysis.locations_match import (
    locations_match,
)

pytestmark = pytest.mark.unit


def test_locations_match_partial_fields():
    """Test locations_match with locations that have only some matching fields."""
    loc1 = {"file_path": "test.py", "start_line": 10}
    loc2 = {"file_path": "test.py", "start_line": 10, "end_line": 15}

    assert locations_match(loc1, loc2) is True


def test_locations_match_null_start_line():
    """Test locations_match with a null start_line in one location."""
    loc1 = {"file_path": "test.py", "start_line": None, "end_line": 15}
    loc2 = {"file_path": "test.py", "start_line": 10, "end_line": 15}

    assert locations_match(loc1, loc2) is True


def test_locations_match_null_end_line():
    """Test locations_match with a null end_line in one location."""
    loc1 = {"file_path": "test.py", "start_line": 10, "end_line": None}
    loc2 = {"file_path": "test.py", "start_line": 10, "end_line": 15}

    assert locations_match(loc1, loc2) is True


def test_locations_match_different_start_lines():
    """Test locations_match with off-by-one start lines (common across scanners)."""
    loc1 = {"file_path": "test.py", "start_line": 10, "end_line": 15}
    loc2 = {"file_path": "test.py", "start_line": 11, "end_line": 15}

    # Off-by-one with overlapping ranges should match (bug #152 fix)
    assert locations_match(loc1, loc2) is True


def test_locations_match_different_end_lines():
    """Two ranges with the same start line overlap whatever their end lines are:
    one scanner reports the statement, another the block. Ranges whose start
    lines differ by up to 5 are accepted, so these, closer than that, are too."""
    loc1 = {"file_path": "test.py", "start_line": 10, "end_line": 15}
    loc2 = {"file_path": "test.py", "start_line": 10, "end_line": 16}

    assert locations_match(loc1, loc2) is True


def test_a_file_uri_matches_the_relative_path_aggregation_writes():
    """Aggregation rewrites a file:// URI to a path relative to the scan root, so
    a preserved finding compared as raw text read as unmatched."""
    loc1 = {"file_path": "file:///work/app/src/a.py", "start_line": 10}
    loc2 = {"file_path": "src/a.py", "start_line": 10}

    assert locations_match(loc1, loc2) is True


def test_an_absolute_path_matches_its_relative_tail_at_a_component_boundary():
    assert locations_match(
        {"file_path": "/work/app/src/a.py", "start_line": 1},
        {"file_path": "src/a.py", "start_line": 1},
    )
    # "a.py" is not the tail "ba.py" of "/work/app/ba.py".
    assert not locations_match(
        {"file_path": "/work/app/ba.py", "start_line": 1},
        {"file_path": "a.py", "start_line": 1},
    )


def test_two_relative_paths_are_compared_whole():
    assert not locations_match(
        {"file_path": "src/a.py", "start_line": 1},
        {"file_path": "other/src/a.py", "start_line": 1},
    )
    assert locations_match(
        {"file_path": "./src/a.py", "start_line": 1},
        {"file_path": "src/a.py", "start_line": 1},
    )


def test_locations_match_no_common_fields():
    """Test locations_match with locations that have no common fields."""
    loc1 = {"file_path": "test.py"}
    loc2 = {"start_line": 10, "end_line": 15}

    assert locations_match(loc1, loc2) is True  # No conflicting fields
