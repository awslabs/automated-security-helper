from automated_security_helper.utils.meta_analysis.extract_result_summary import (
    extract_result_summary,
)


def test_extract_result_summary_complete():
    """Test extracting summary from a complete result."""
    result = {
        "ruleId": "TEST001",
        "level": "error",
        "message": {"text": "Test finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "test.py"},
                    "region": {"startLine": 10, "endLine": 15},
                }
            }
        ],
    }

    summary = extract_result_summary(result)

    assert summary["ruleId"] == "TEST001"
    assert summary["message"] == "Test finding"
    assert "location" in summary
    assert summary["location"]["file_path"] == "test.py"
    assert summary["location"]["start_line"] == 10
    assert summary["location"]["end_line"] == 15


def test_extract_result_summary_minimal():
    """Test extracting summary from a minimal result."""
    result = {"ruleId": "TEST001", "message": {"text": "Test finding"}}

    summary = extract_result_summary(result)

    assert summary["ruleId"] == "TEST001"
    assert summary["message"] == "Test finding"
    assert "location" in summary
    assert summary["location"]["file_path"] is None
    assert summary["location"]["start_line"] is None
    assert summary["location"]["end_line"] is None
