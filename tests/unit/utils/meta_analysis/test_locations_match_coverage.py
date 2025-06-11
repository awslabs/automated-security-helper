"""Unit tests for locations_match module to increase coverage."""

from automated_security_helper.utils.meta_analysis.locations_match import (
    locations_match,
)


def test_locations_match_exact_match():
    """Test locations_match with exact matches."""
    # Create test locations
    location1 = {
        "physicalLocation": {
            "artifactLocation": {"uri": "file.py"},
            "region": {"startLine": 10, "endLine": 15},
        }
    }
    location2 = {
        "physicalLocation": {
            "artifactLocation": {"uri": "file.py"},
            "region": {"startLine": 10, "endLine": 15},
        }
    }

    # Test exact match
    assert locations_match(location1, location2) is True


def test_locations_match_different_files():
    """Test locations_match with different files."""
    # Create test locations with different files
    location1 = {
        "physicalLocation": {
            "artifactLocation": {"uri": "file1.py"},
            "region": {"startLine": 10, "endLine": 15},
        }
    }
    location2 = {
        "physicalLocation": {
            "artifactLocation": {"uri": "file2.py"},
            "region": {"startLine": 10, "endLine": 15},
        }
    }

    # Test different files
    assert locations_match(location1, location2) is False


def test_locations_match_overlapping_regions():
    """Test locations_match with overlapping regions."""
    # Create test locations with overlapping regions
    location1 = {
        "physicalLocation": {
            "artifactLocation": {"uri": "file.py"},
            "region": {"startLine": 10, "endLine": 15},
        }
    }
    location2 = {
        "physicalLocation": {
            "artifactLocation": {"uri": "file.py"},
            "region": {"startLine": 12, "endLine": 18},
        }
    }

    # Test overlapping regions
    assert locations_match(location1, location2) is True


def test_locations_match_non_overlapping_regions():
    """Test locations_match with non-overlapping regions."""
    # Create test locations with non-overlapping regions
    location1 = {
        "physicalLocation": {
            "artifactLocation": {"uri": "file.py"},
            "region": {"startLine": 10, "endLine": 15},
        }
    }
    location2 = {
        "physicalLocation": {
            "artifactLocation": {"uri": "file.py"},
            "region": {"startLine": 20, "endLine": 25},
        }
    }

    # Test non-overlapping regions
    assert locations_match(location1, location2) is False


def test_locations_match_missing_fields():
    """Test locations_match with missing fields."""
    # Test with missing physicalLocation
    location1 = {}
    location2 = {
        "physicalLocation": {
            "artifactLocation": {"uri": "file.py"},
            "region": {"startLine": 10, "endLine": 15},
        }
    }
    assert locations_match(location1, location2) is False

    # Test with missing artifactLocation
    location1 = {"physicalLocation": {"region": {"startLine": 10, "endLine": 15}}}
    assert locations_match(location1, location2) is False

    # Test with missing uri
    location1 = {
        "physicalLocation": {
            "artifactLocation": {},
            "region": {"startLine": 10, "endLine": 15},
        }
    }
    assert locations_match(location1, location2) is False

    # Test with missing region
    location1 = {"physicalLocation": {"artifactLocation": {"uri": "file.py"}}}
    assert locations_match(location1, location2) is True  # region is optional


def test_locations_match_with_only_start_line():
    """Test locations_match with only startLine."""
    # Create test locations with only startLine
    location1 = {
        "physicalLocation": {
            "artifactLocation": {"uri": "file.py"},
            "region": {"startLine": 10},
        }
    }
    location2 = {
        "physicalLocation": {
            "artifactLocation": {"uri": "file.py"},
            "region": {"startLine": 10},
        }
    }

    # Test exact match with only startLine
    assert locations_match(location1, location2) is True

    # Test different startLine
    location2["physicalLocation"]["region"]["startLine"] = 11
    assert locations_match(location1, location2) is False
