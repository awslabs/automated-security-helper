"""Unit tests for generate_field_mapping_html_report.py."""

from unittest.mock import patch, mock_open

from automated_security_helper.utils.meta_analysis.generate_field_mapping_html_report import (
    generate_html_report,
)


def test_generate_html_report():
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

    # Mock file writing more specifically to avoid system file calls
    with patch(
        "automated_security_helper.utils.meta_analysis.generate_field_mapping_html_report.open",
        mock_open(),
    ) as mock_file:
        # Call function
        result = generate_html_report(data, "test_report.html")

        # Should return None (writes to file)
        assert result is None

        # Verify file was opened for writing
        mock_file.assert_called_once_with(
            "test_report.html", mode="w", encoding="utf-8"
        )
