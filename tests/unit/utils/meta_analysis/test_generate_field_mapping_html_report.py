"""Unit tests for generate_field_mapping_html_report.py."""

import pytest

from automated_security_helper.utils.meta_analysis.reporting import (
    generate_html_report,
)

pytestmark = pytest.mark.unit


def test_generate_html_report(tmp_path):
    """Test generate_html_report function."""
    # Create test data with the expected structure
    data = {
        "missing_fields": {
            "test_scanner": {
                "critical": [
                    {
                        "path": "test_field",
                        "importance": "critical",
                        "paths": ["path1", "path2"],
                        "original_value": "test_value",
                    }
                ],
                "important": [],
                "informational": [],
            }
        },
        "match_statistics": {
            "test_scanner": {
                "total_matches": 10,
                "exact_matches": 5,
                "partial_matches": 3,
                "no_matches": 2,
                "matched_results": 8,
                "total_results": 10,
                "field_preservation_rate": 0.8,
                "critical_fields_missing": 1,
                "important_fields_missing": 0,
                "informational_fields_missing": 0,
            }
        },
        "summary": {
            "total_findings": 10,
            "matched_findings": 8,
            "critical_missing_fields": 1,
            "important_missing_fields": 0,
            "informational_missing_fields": 0,
        },
        "fields": [
            {
                "name": "test_field",
                "importance": "critical",
                "paths": ["path1", "path2"],
            }
        ],
    }

    report = tmp_path / "test_report.html"

    result = generate_html_report(data, str(report))

    # Should return None (writes to file)
    assert result is None

    # The report is written there, as HTML naming the scanner
    html = report.read_text(encoding="utf-8")
    assert html.rstrip().endswith("</html>")
    assert "test_scanner" in html
