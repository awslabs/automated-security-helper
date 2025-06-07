from automated_security_helper.utils.meta_analysis.locations_match import (
    locations_match,
)


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
    """Test locations_match with different start_line values."""
    loc1 = {"file_path": "test.py", "start_line": 10, "end_line": 15}
    loc2 = {"file_path": "test.py", "start_line": 11, "end_line": 15}

    assert locations_match(loc1, loc2) is False


def test_locations_match_different_end_lines():
    """Test locations_match with different end_line values."""
    loc1 = {"file_path": "test.py", "start_line": 10, "end_line": 15}
    loc2 = {"file_path": "test.py", "start_line": 10, "end_line": 16}

    assert locations_match(loc1, loc2) is False


def test_locations_match_no_common_fields():
    """Test locations_match with locations that have no common fields."""
    loc1 = {"file_path": "test.py"}
    loc2 = {"start_line": 10, "end_line": 15}

    assert locations_match(loc1, loc2) is True  # No conflicting fields
