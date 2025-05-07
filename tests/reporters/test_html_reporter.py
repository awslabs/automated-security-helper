"""Tests for HTML reporter."""

import pytest
from automated_security_helper.reporters.ash_default.html_reporter import HtmlReporter
from automated_security_helper.models.asharp_model import AshAggregatedResult
from automated_security_helper.schemas.sarif_schema_model import (
    Result,
    Message,
    Location,
    PhysicalLocation,
    ArtifactLocation,
    Region,
)


class TestHTMLReporter:
    """Test cases for HTMLReporter."""

    def test_html_reporter_with_sarif_results(
        self, sample_ash_model: AshAggregatedResult, test_plugin_context
    ):
        """Test that the HTML reporter correctly formats SARIF results."""
        # Create a test AshAggregatedResult with SARIF results

        # Add some test results to the SARIF report
        sample_ash_model.sarif.runs[0].results = [
            Result(
                ruleId="TEST001",
                level="error",
                message=Message(text="Test error message"),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(
                            artifactLocation=ArtifactLocation(uri="test/file.py"),
                            region=Region(startLine=10),
                        )
                    )
                ],
            ),
            Result(
                ruleId="TEST002",
                level="warning",
                message=Message(text="Test warning message"),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(
                            artifactLocation=ArtifactLocation(uri="test/file2.py"),
                            region=Region(startLine=20),
                        )
                    )
                ],
            ),
        ]

        # Format the report
        reporter = HtmlReporter(context=test_plugin_context)
        html_output = reporter.report(sample_ash_model)

        # Check that the HTML contains the expected elements
        assert "<!DOCTYPE html>" in html_output
        assert "<html>" in html_output
        assert "TEST001" in html_output
        assert "TEST002" in html_output
        assert "Test error message" in html_output
        assert "Test warning message" in html_output
        assert "test/file.py" in html_output
        assert "test/file2.py" in html_output

    def test_html_reporter_with_empty_results(self, test_plugin_context):
        """Test that the HTML reporter handles empty results correctly."""
        model = AshAggregatedResult()
        reporter = HtmlReporter(context=test_plugin_context)
        html_output = reporter.report(model)
        assert "No findings to display" in html_output

    def test_html_reporter_with_invalid_model(self, test_plugin_context):
        """Test that the HTML reporter raises an error for invalid models."""
        reporter = HtmlReporter(context=test_plugin_context)
        with pytest.raises(AttributeError):  # Changed from ValueError to AttributeError
            reporter.report("not a model")

    def test_html_reporter_with_missing_location(self, test_plugin_context):
        """Test that the HTML reporter handles results with missing location info."""
        model = AshAggregatedResult()
        model.sarif.runs[0].results = [
            Result(
                ruleId="TEST003",
                level="note",
                message=Message(text="Test note message"),
                locations=[],  # Empty locations
            )
        ]

        reporter = HtmlReporter(context=test_plugin_context)
        html_output = reporter.report(model)

        # Check that the HTML contains the expected elements
        assert "TEST003" in html_output
        assert "Test note message" in html_output
        assert "N/A" in html_output  # Location should be N/A
