from automated_security_helper.utils.meta_analysis.validate_sarif_aggregation import (
    validate_sarif_aggregation,
)


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
