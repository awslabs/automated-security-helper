"""Unit tests for generate_field_mapping_html_report.py."""

import pytest
from unittest.mock import patch, MagicMock, mock_open

from automated_security_helper.utils.meta_analysis.generate_field_mapping_html_report import (
    generate_field_mapping_html_report,
    generate_html_report,
    generate_field_mapping_report,
)


@patch("automated_security_helper.utils.meta_analysis.generate_field_mapping_html_report.generate_html_report")
@patch("automated_security_helper.utils.meta_analysis.generate_field_mapping_html_report.generate_field_mapping_report")
def test_generate_field_mapping_html_report(mock_generate_field_mapping_report, mock_generate_html_report):
    """Test generate_field_mapping_html_report function."""
    # Setup mocks
    mock_generate_field_mapping_report.return_value = {"fields": [{"name": "test_field"}]}
    mock_generate_html_report.return_value = "<html>Test Report</html>"

    # Call function
    result = generate_field_mapping_html_report(
        sarif_files=["test.sarif"],
        output_file="report.html",
        title="Test Report"
    )

    # Verify mocks were called with correct parameters
    mock_generate_field_mapping_report.assert_called_once_with(["test.sarif"])
    mock_generate_html_report.assert_called_once_with(
        {"fields": [{"name": "test_field"}]},
        "Test Report"
    )

    # Verify result
    assert result == "<html>Test Report</html>"


@patch("builtins.open", new_callable=mock_open)
@patch("automated_security_helper.utils.meta_analysis.generate_field_mapping_html_report.generate_html_report")
@patch("automated_security_helper.utils.meta_analysis.generate_field_mapping_html_report.generate_field_mapping_report")
def test_generate_field_mapping_html_report_with_output_file(
    mock_generate_field_mapping_report, mock_generate_html_report, mock_file
):
    """Test generate_field_mapping_html_report function with output file."""
    # Setup mocks
    mock_generate_field_mapping_report.return_value = {"fields": [{"name": "test_field"}]}
    mock_generate_html_report.return_value = "<html>Test Report</html>"

    # Call function
    result = generate_field_mapping_html_report(
        sarif_files=["test.sarif"],
        output_file="report.html",
        title="Test Report",
        write_to_file=True
    )

    # Verify file was written
    mock_file.assert_called_once_with("report.html", "w", encoding="utf-8")
    mock_file().write.assert_called_once_with("<html>Test Report</html>")

    # Verify result
    assert result == "<html>Test Report</html>"


@patch("automated_security_helper.utils.meta_analysis.generate_field_mapping_html_report.extract_field_paths")
@patch("automated_security_helper.utils.meta_analysis.generate_field_mapping_html_report.categorize_field_importance")
def test_generate_field_mapping_report(mock_categorize_field_importance, mock_extract_field_paths):
    """Test generate_field_mapping_report function."""
    # Setup mocks
    mock_extract_field_paths.return_value = {"field1": ["path1"], "field2": ["path2"]}
    mock_categorize_field_importance.return_value = "HIGH"

    # Mock open and json.load
    mock_sarif_data = {"runs": [{"results": [{"ruleId": "test"}]}]}

    with patch("builtins.open", mock_open(read_data="{}")) as mock_file, \
         patch("json.load", return_value=mock_sarif_data):

        # Call function
        result = generate_field_mapping_report(["test.sarif"])

        # Verify result structure
        assert "fields" in result
        assert len(result["fields"]) == 2
        assert any(field["name"] == "field1" for field in result["fields"])
        assert any(field["name"] == "field2" for field in result["fields"])


def test_generate_html_report():
    """Test generate_html_report function."""
    # Create test data
    data = {
        "fields": [
            {
                "name": "test_field",
                "importance": "HIGH",
                "paths": ["path1", "path2"]
            }
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