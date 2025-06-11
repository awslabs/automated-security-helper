"""Tests for reporter plugins."""

from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults


class TestJSONFormatter:
    """Test cases for JSONReporter."""

    def test_json_formatter(
        self, sample_ash_model: AshAggregatedResults, test_plugin_context
    ):
        """Test JSON formatter output structure."""
        formatter = FlatJSONReporter(context=test_plugin_context)
        result = formatter.report(sample_ash_model)
        assert result is not None
        assert isinstance(result, str)
        assert result.startswith("[")
        assert result.endswith("]")
        assert "id" in result
        assert "severity" in result


class TestHTMLFormatter:
    """Test cases for HTMLReporter."""

    def test_html_formatter(self, sample_ash_model, test_plugin_context):
        """Test HTML formatter output structure."""
        formatter = HtmlReporter(context=test_plugin_context)
        result = formatter.report(sample_ash_model)
        assert result is not None
        assert isinstance(result, str)
        assert result.startswith("\n<!DOCTYPE html>")
        assert "<html>" in result
        assert "</html>" in result
        assert "<table>" in result


class TestCSVFormatter:
    """Test cases for CSVReporter."""

    def test_csv_formatter(self, sample_ash_model, test_plugin_context):
        """Test CSV formatter output structure."""
        formatter = CsvReporter(context=test_plugin_context)
        result = formatter.report(sample_ash_model)
        assert result is not None
        assert isinstance(result, str)

        # Check for header row
        lines = result.strip().split("\n")
        assert len(lines) >= 1
        header = lines[0].split(",")

        # Verify expected columns are present
        expected_columns = ["ID", "Title", "Description", "Severity", "Scanner"]
        for col in expected_columns:
            assert any(col.lower() in h.lower() for h in header), (
                f"Column {col} not found in header"
            )
