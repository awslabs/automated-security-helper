from automated_security_helper.utils.meta_analysis.extract_location_info import (
    extract_location_info,
)


def test_extract_location_info_with_full_location():
    """Test extract_location_info with a complete location object."""
    result = {
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "test.py"},
                    "region": {"startLine": 10, "endLine": 15},
                }
            }
        ]
    }

    location_info = extract_location_info(result)

    assert location_info["file_path"] == "test.py"
    assert location_info["start_line"] == 10
    assert location_info["end_line"] == 15


def test_extract_location_info_with_multiple_locations():
    """Test extract_location_info with multiple locations."""
    result = {
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "test1.py"},
                    "region": {"startLine": 10, "endLine": 15},
                }
            },
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "test2.py"},
                    "region": {"startLine": 20, "endLine": 25},
                }
            },
        ]
    }

    location_info = extract_location_info(result)

    # Should use the first location
    assert location_info["file_path"] == "test1.py"
    assert location_info["start_line"] == 10
    assert location_info["end_line"] == 15


def test_extract_location_info_with_missing_region():
    """Test extract_location_info with a location that has no region."""
    result = {
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "test.py"}
                    # No region
                }
            }
        ]
    }

    location_info = extract_location_info(result)

    assert location_info["file_path"] == "test.py"
    assert location_info["start_line"] is None
    assert location_info["end_line"] is None


def test_extract_location_info_with_partial_region():
    """Test extract_location_info with a location that has a partial region."""
    result = {
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "test.py"},
                    "region": {
                        "startLine": 10
                        # No endLine
                    },
                }
            }
        ]
    }

    location_info = extract_location_info(result)

    assert location_info["file_path"] == "test.py"
    assert location_info["start_line"] == 10
    assert location_info["end_line"] is None
