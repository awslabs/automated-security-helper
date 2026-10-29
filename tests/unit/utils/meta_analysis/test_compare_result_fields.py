import pytest

from automated_security_helper.utils.meta_analysis.field_mapping import (
    compare_result_fields,
)

pytestmark = pytest.mark.unit


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


def test_every_importance_is_one_validate_sarif_aggregation_buckets_by():
    """The validator keys its missing_fields buckets on critical / important /
    informational; "high" and "medium", which this function wrote, were a KeyError
    there on every reported difference."""
    from automated_security_helper.utils.meta_analysis.field_mapping import (
        IMPORTANCE_LEVELS,
    )

    original = {"ruleId": "R1", "level": "error", "extra_field": "value"}
    aggregated = {"ruleId": "R1", "level": "warning"}

    missing = compare_result_fields(original, aggregated)

    assert {field["path"] for field in missing} == {"level", "extra_field"}
    assert all(field["importance"] in IMPORTANCE_LEVELS for field in missing)
    by_path = {field["path"]: field["importance"] for field in missing}
    assert by_path["level"] == "critical"
    assert by_path["extra_field"] == "informational"


def test_a_nested_field_the_aggregate_dropped_is_reported():
    """Every field of the original is compared, not two hard-coded names."""
    original = {
        "ruleId": "R1",
        "message": {"text": "finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"startLine": 3, "endLine": 4},
                }
            }
        ],
    }
    aggregated = {
        "ruleId": "R1",
        "message": {"text": "finding"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}],
    }

    missing = compare_result_fields(original, aggregated)

    paths = {field["path"] for field in missing}
    assert "locations[0].physicalLocation.region.startLine" in paths
    assert "locations[0].physicalLocation.region.endLine" in paths
    assert all(field["importance"] == "critical" for field in missing)


def test_fields_aggregation_rewrites_on_purpose_are_not_differences():
    original = {"ruleId": "R1", "ruleIndex": 3, "analysisTarget": {"uri": "a.py"}}
    aggregated = {"ruleId": "R1", "ruleIndex": 0}

    assert compare_result_fields(original, aggregated) == []
