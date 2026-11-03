import pytest

from automated_security_helper.utils.meta_analysis.sarif_analysis import (
    validate_sarif_aggregation,
)

pytestmark = pytest.mark.unit


def test_validate_sarif_aggregation():
    """Test validating SARIF aggregation."""
    # Setup test data
    original_reports = {
        "scanner1": {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Scanner 1"}},
                    "results": [
                        {
                            "ruleId": "RULE001",
                            "level": "error",
                            "message": {"text": "Finding 1"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "test.py"},
                                        "region": {"startLine": 10, "endLine": 15},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        },
        "scanner2": {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Scanner 2"}},
                    "results": [
                        {
                            "ruleId": "RULE002",
                            "level": "warning",
                            "message": {"text": "Finding 2"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "other.py"},
                                        "region": {"startLine": 20, "endLine": 25},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    }

    aggregated_report = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Aggregated Scanner"}},
                "results": [
                    {
                        "ruleId": "RULE001",
                        "level": "error",
                        "message": {"text": "Finding 1"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.py"},
                                    "region": {"startLine": 10, "endLine": 15},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "RULE002",
                        "level": "warning",
                        "message": {"text": "Finding 2"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "other.py"},
                                    "region": {"startLine": 20, "endLine": 25},
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }

    # Test function
    validation_results = validate_sarif_aggregation(original_reports, aggregated_report)

    # Verify results
    assert "missing_fields" in validation_results
    assert "match_statistics" in validation_results
    assert "unmatched_results" in validation_results
    assert "summary" in validation_results

    # Check that all original results were matched
    assert validation_results["match_statistics"]["scanner1"]["total_results"] == 1
    assert validation_results["match_statistics"]["scanner1"]["matched_results"] == 1
    assert validation_results["match_statistics"]["scanner2"]["total_results"] == 1
    assert validation_results["match_statistics"]["scanner2"]["matched_results"] == 1

    # Check summary statistics
    assert validation_results["summary"]["total_findings"] == 2
    assert validation_results["summary"]["matched_findings"] == 2


def _result(rule_id, uri, line, level="error", text="finding"):
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "endLine": line},
                }
            }
        ],
    }


def _report(*runs_results):
    return {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "t"}}, "results": list(results)}
            for results in runs_results
        ],
    }


def test_a_level_difference_is_bucketed_as_critical_not_a_key_error():
    """compare_result_fields wrote importance "high"; the buckets here are
    critical / important / informational, so any reported difference raised
    KeyError out of the whole validation."""
    original = {"bandit": _report([_result("R1", "a.py", 3, level="error")])}
    aggregated = _report([_result("R1", "a.py", 3, level="warning")])

    results = validate_sarif_aggregation(original, aggregated)

    critical = results["missing_fields"]["bandit"]["critical"]
    assert [field["path"] for field in critical] == ["level"]
    assert results["match_statistics"]["bandit"]["critical_fields_missing"] == 1
    assert results["summary"]["critical_missing_fields"] == 1


def test_every_run_of_a_multi_run_aggregate_is_read():
    """A workspace scan writes one run per project; reading runs[0] alone left the
    second run's findings unmatched."""
    original = {
        "bandit": _report([_result("R1", "a.py", 3)], [_result("R2", "b.py", 7)])
    }
    aggregated = _report([_result("R1", "a.py", 3)], [_result("R2", "b.py", 7)])

    results = validate_sarif_aggregation(original, aggregated)

    assert results["match_statistics"]["bandit"]["total_results"] == 2
    assert results["match_statistics"]["bandit"]["matched_results"] == 2
    assert results["unmatched_results"] == {}


def test_a_uri_aggregation_made_relative_counts_no_critical_field_missing():
    """A scanner writes file:///<scan root>/src/a.py; aggregation writes src/a.py.
    The results pair (locations_match compares the two as paths), and the field
    comparison has to read the rewritten URI the same way, or every matched
    result of a healthy aggregation counts one critical field missing."""
    original = {
        "bandit": _report(
            [
                _result("R1", "file:///work/app/src/a.py", 3),
                _result("R2", "/work/app/src/b.py", 7),
            ]
        )
    }
    aggregated = _report([_result("R1", "src/a.py", 3), _result("R2", "src/b.py", 7)])

    results = validate_sarif_aggregation(original, aggregated)

    assert results["match_statistics"]["bandit"]["matched_results"] == 2
    assert results["match_statistics"]["bandit"]["critical_fields_missing"] == 0
    assert results["summary"]["critical_missing_fields"] == 0
    assert results["missing_fields"]["bandit"]["critical"] == []


def test_two_originals_cannot_share_one_aggregated_result():
    """Two identical original findings against one surviving aggregated copy: one
    was dropped by aggregation, and both were counted as matched."""
    original = {"bandit": _report([_result("R1", "a.py", 3), _result("R1", "a.py", 3)])}
    aggregated = _report([_result("R1", "a.py", 3)])

    results = validate_sarif_aggregation(original, aggregated)

    assert results["match_statistics"]["bandit"]["total_results"] == 2
    assert results["match_statistics"]["bandit"]["matched_results"] == 1
    assert len(results["unmatched_results"]["bandit"]) == 1
