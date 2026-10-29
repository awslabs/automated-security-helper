import pytest

from automated_security_helper.utils.meta_analysis.sarif_analysis import (
    find_matching_result,
)

pytestmark = pytest.mark.unit


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


def _located(rule_id, uri, line, **extra):
    return {
        "ruleId": rule_id,
        "message": {"text": "finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
        **extra,
    }


def test_an_equal_analysis_target_does_not_match_a_different_location():
    """analysisTarget was compared after the locations had already disagreed, so a
    finding aggregation dropped was counted as matched against another one of the
    same rule in the same analyzed file."""
    original = _located("R1", "src/a.py", 10, analysisTarget={"uri": "src/a.py"})
    aggregated = [_located("R1", "src/a.py", 400, analysisTarget={"uri": "src/a.py"})]

    assert find_matching_result(original, aggregated) is None


def test_two_results_with_no_target_uri_are_not_the_same_target():
    original = {"ruleId": "R1", "message": {"text": "one"}, "analysisTarget": {}}
    aggregated = [{"ruleId": "R1", "message": {"text": "two"}, "analysisTarget": {}}]

    assert find_matching_result(original, aggregated) is None


def test_a_result_without_a_location_does_not_match_a_located_one():
    """extract_location_info always returns the three keys, so the "no location"
    branches never ran and locations_match read two all-None locations as equal:
    a result with no location matched any aggregated result of its rule."""
    original = {"ruleId": "R1", "message": {"text": "one"}}
    aggregated = [_located("R1", "src/a.py", 10)]

    assert find_matching_result(original, aggregated) is None


def test_a_result_without_a_location_matches_on_its_message_only():
    original = {"ruleId": "R1", "message": {"text": "one"}}
    aggregated = [
        {"ruleId": "R1", "message": {"text": "two"}},
        {"ruleId": "R1", "message": {"text": "one"}},
    ]

    assert find_matching_result(original, aggregated) is aggregated[1]


def test_an_aggregated_result_already_taken_is_not_offered_again():
    original = _located("R1", "src/a.py", 10)
    aggregated = [_located("R1", "src/a.py", 10)]

    taken = {id(aggregated[0])}
    assert find_matching_result(original, aggregated, exclude_ids=taken) is None
    assert find_matching_result(original, aggregated) is aggregated[0]
