"""Unit tests for generate_field_mapping_html_report.py."""

from automated_security_helper.utils.meta_analysis.generate_field_mapping_html_report import (
    generate_html_report,
)


def test_generate_html_report():
    """Test generate_html_report function."""
    # Create test data
    data = {
        "fields": [
            {"name": "test_field", "importance": "HIGH", "paths": ["path1", "path2"]}
        ]
    }

    # Call function
    result = generate_html_report(data, "Test Report")

    # Verify result contains expected elements
    assert "<!DOCTYPE html>" in result
    assert "<title>Test Report</title>" in result
    assert "test_field" in result
    assert "HIGH" in result
    assert "path1" in result
    assert "path2" in result
