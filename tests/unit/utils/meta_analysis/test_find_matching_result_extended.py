from automated_security_helper.utils.meta_analysis.find_matching_result import (
    find_matching_result,
)


def test_find_matching_result_with_empty_results():
    """Test find_matching_result with empty results list."""
    original_result = {
        "ruleId": "TEST001",
        "level": "error",
        "message": {"text": "Test finding"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "test.py"}}}],
    }
    aggregated_results = []

    match = find_matching_result(original_result, aggregated_results)
    assert match is None


def test_find_matching_result_with_partial_match():
    """Test find_matching_result with a partial match."""
    original_result = {
        "ruleId": "TEST001",
        "level": "error",
        "message": {"text": "Test finding"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "test.py"}}}],
    }
    aggregated_results = [
        {
            "ruleId": "TEST001",
            "level": "warning",  # Different level
            "message": {"text": "Test finding"},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "test.py"}}}
            ],
        }
    ]

    match = find_matching_result(original_result, aggregated_results)
    assert match is aggregated_results[0]


def test_find_matching_result_with_multiple_matches():
    """Test find_matching_result with multiple potential matches."""
    original_result = {
        "ruleId": "TEST001",
        "level": "error",
        "message": {"text": "Test finding"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "test.py"}}}],
    }
    aggregated_results = [
        {
            "ruleId": "TEST002",  # Different rule ID
            "level": "error",
            "message": {"text": "Test finding"},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "test.py"}}}
            ],
        },
        {
            "ruleId": "TEST001",
            "level": "error",
            "message": {"text": "Test finding"},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "test.py"}}}
            ],
        },
    ]

    match = find_matching_result(original_result, aggregated_results)
    assert match is aggregated_results[1]


def test_find_matching_result_with_no_locations():
    """Test find_matching_result with results that have no locations."""
    original_result = {
        "ruleId": "TEST001",
        "level": "error",
        "message": {"text": "Test finding"},
        # No locations
    }
    aggregated_results = [
        {
            "ruleId": "TEST001",
            "level": "error",
            "message": {"text": "Test finding"},
            # No locations
        }
    ]

    match = find_matching_result(original_result, aggregated_results)
    assert match is aggregated_results[0]
