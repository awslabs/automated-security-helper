from automated_security_helper.utils.meta_analysis.extract_location_info import (
    extract_location_info,
)


def test_extract_location_info_with_location():
    """Test extracting location info from a result with location."""
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


def test_extract_location_info_without_location():
    """Test extracting location info from a result without location."""
    result = {"message": {"text": "Test finding"}}

    location_info = extract_location_info(result)

    assert location_info["file_path"] is None
    assert location_info["start_line"] is None
    assert location_info["end_line"] is None


def test_extract_location_info_partial_location():
    """Test extracting location info from a result with partial location info."""
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
