from automated_security_helper.utils.meta_analysis.compare_result_fields import (
    compare_result_fields,
)


def test_compare_result_fields_identical():
    """Test comparing identical result fields."""
    original_result = {
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

    aggregated_result = original_result.copy()

    missing_fields = compare_result_fields(original_result, aggregated_result)

    # No fields should be missing
    assert len(missing_fields) == 0


def test_compare_result_fields_different():
    """Test comparing results with different fields."""
    original_result = {
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
        "extra_field": "value",
    }

    aggregated_result = {
        "ruleId": "TEST001",
        "level": "warning",  # Different level
        "message": {"text": "Test finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "test.py"},
                    "region": {"startLine": 10, "endLine": 15},
                }
            }
        ],
        # Missing extra_field
    }

    missing_fields = compare_result_fields(original_result, aggregated_result)

    # The extra_field should be reported as missing
    assert len(missing_fields) > 0
    assert any(field["path"] == "extra_field" for field in missing_fields)
