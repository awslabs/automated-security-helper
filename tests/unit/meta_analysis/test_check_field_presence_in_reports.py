from automated_security_helper.utils.meta_analysis.check_field_presence_in_reports import (
    check_field_presence_in_reports,
)


def test_check_field_presence_in_reports():
    """Test checking field presence in reports."""
    # Setup test data
    field_paths = {
        "version": {"type": {"str"}, "scanners": {"scanner1"}},
        "runs[0].tool.driver.name": {
            "type": {"str"},
            "scanners": {"scanner1", "scanner2"},
        },
        "runs[0].results[0].ruleId": {"type": {"str"}, "scanners": {"scanner1"}},
        "runs[0].results[0].message.text": {"type": {"str"}, "scanners": {"scanner2"}},
    }

    aggregate_report = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Aggregated Scanner"}},
                "results": [{"ruleId": "RULE001", "message": {"text": "Finding 1"}}],
            }
        ],
    }

    flat_reports = {
        "scanner1": {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Scanner 1"}},
                    "results": [{"ruleId": "RULE001"}],
                }
            ],
        },
        "scanner2": {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Scanner 2"}},
                    "results": [{"message": {"text": "Finding 1"}}],
                }
            ],
        },
    }

    # Test function
    result = check_field_presence_in_reports(
        field_paths, aggregate_report, flat_reports
    )

    # Verify results
    assert "version" in result
    assert result["version"]["in_aggregate"] is True
    assert "scanners" in result["version"]
    assert "scanner1" in result["version"]["scanners"]

    assert "runs[0].tool.driver.name" in result
    assert result["runs[0].tool.driver.name"]["in_aggregate"] is True
    assert "scanners" in result["runs[0].tool.driver.name"]
    assert "scanner1" in result["runs[0].tool.driver.name"]["scanners"]
    assert "scanner2" in result["runs[0].tool.driver.name"]["scanners"]

    assert "runs[0].results[0].ruleId" in result
    assert result["runs[0].results[0].ruleId"]["in_aggregate"] is True
    assert "scanners" in result["runs[0].results[0].ruleId"]
    assert "scanner1" in result["runs[0].results[0].ruleId"]["scanners"]

    assert "runs[0].results[0].message.text" in result
    assert result["runs[0].results[0].message.text"]["in_aggregate"] is True
    assert "scanners" in result["runs[0].results[0].message.text"]
    assert "scanner2" in result["runs[0].results[0].message.text"]["scanners"]
