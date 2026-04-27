from automated_security_helper.utils.meta_analysis.locations_match import (
    locations_match,
)


def test_locations_match_identical():
    """Test matching identical locations."""
    loc1 = {"file_path": "test.py", "start_line": 10, "end_line": 15}

    loc2 = {"file_path": "test.py", "start_line": 10, "end_line": 15}

    assert locations_match(loc1, loc2) is True


def test_locations_match_different_uri():
    """Test matching locations with different URIs."""
    loc1 = {"file_path": "test.py", "start_line": 10, "end_line": 15}

    loc2 = {"file_path": "other.py", "start_line": 10, "end_line": 15}

    assert locations_match(loc1, loc2) is False


def test_locations_match_different_lines():
    """Test matching locations with overlapping line ranges (off-by-one is common)."""
    loc1 = {"file_path": "test.py", "start_line": 10, "end_line": 15}

    loc2 = {"file_path": "test.py", "start_line": 11, "end_line": 16}

    # Overlapping ranges with small start-line diff should match (bug #152 fix)
    assert locations_match(loc1, loc2) is True


def test_locations_match_missing_fields():
    """Test matching locations with missing fields."""
    loc1 = {"file_path": "test.py", "start_line": None, "end_line": None}

    loc2 = {"file_path": "test.py", "start_line": 10, "end_line": 15}

    assert locations_match(loc1, loc2) is True
