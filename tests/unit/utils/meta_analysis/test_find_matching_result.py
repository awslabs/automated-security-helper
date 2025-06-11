from automated_security_helper.utils.meta_analysis.find_matching_result import (
    find_matching_result,
)


def test_find_matching_result_exact_match():
    """Test finding an exact matching result."""
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

    aggregated_results = [
        {
            "ruleId": "OTHER001",
            "level": "warning",
            "message": {"text": "Other finding"},
        },
        # Exact copy of original_result
        {
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
        },
        {"ruleId": "TEST002", "level": "error", "message": {"text": "Another finding"}},
    ]

    match = find_matching_result(original_result, aggregated_results)

    assert match is not None
    assert match["ruleId"] == "TEST001"
    assert match["message"]["text"] == "Test finding"


def test_find_matching_result_similar_match():
    """Test finding a similar matching result."""
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

    aggregated_results = [
        {
            "ruleId": "OTHER001",
            "level": "warning",
            "message": {"text": "Other finding"},
        },
        # Similar to original_result but with different level
        {
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
        },
        {"ruleId": "TEST002", "level": "error", "message": {"text": "Another finding"}},
    ]

    match = find_matching_result(original_result, aggregated_results)

    assert match is not None
    assert match["ruleId"] == "TEST001"
    assert match["level"] == "warning"  # Different from original


def test_find_matching_result_no_match():
    """Test finding no matching result."""
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

    aggregated_results = [
        {
            "ruleId": "OTHER001",
            "level": "warning",
            "message": {"text": "Other finding"},
        },
        {"ruleId": "TEST002", "level": "error", "message": {"text": "Another finding"}},
    ]

    match = find_matching_result(original_result, aggregated_results)

    assert match is None
