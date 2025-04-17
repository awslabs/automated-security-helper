import pytest
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.reporters.ash_default import HTMLReporter
from automated_security_helper.schemas.sarif_schema_model import (
    Result,
    Message,
    Location,
    PhysicalLocation,
    ArtifactLocation,
    Region,
)


def test_html_reporter_with_sarif_results(sample_ash_model: ASHARPModel):
    """Test that the HTML reporter correctly formats SARIF results."""
    # Create a test ASHARPModel with SARIF results

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
    reporter = HTMLReporter()
    html_output = reporter.format(sample_ash_model)

    # Verify the output contains expected elements
    assert "Security Scan Results" in html_output
    assert "TEST001" in html_output
    assert "TEST002" in html_output
    assert "Test error message" in html_output
    assert "Test warning message" in html_output
    assert "test/file.py:10" in html_output
    assert "test/file2.py:20" in html_output
    assert 'class="severity-error"' in html_output
    assert 'class="severity-warning"' in html_output


def test_html_reporter_with_empty_results():
    """Test that the HTML reporter handles empty results correctly."""
    model = ASHARPModel()
    reporter = HTMLReporter()
    html_output = reporter.format(model)

    assert "No findings to display" in html_output


def test_html_reporter_with_invalid_model():
    """Test that the HTML reporter raises an error for invalid models."""
    reporter = HTMLReporter()
    with pytest.raises(ValueError, match="only supports ASHARPModel"):
        reporter.format("invalid model")


def test_html_reporter_with_missing_location():
    """Test that the HTML reporter handles results with missing location info."""
    model = ASHARPModel()
    model.sarif.runs[0].results = [
        Result(
            ruleId="TEST003",
            level="note",
            message=Message(text="Test note message"),
            locations=[],  # Empty locations
        )
    ]

    reporter = HTMLReporter()
    html_output = reporter.format(model)

    assert "TEST003" in html_output
    assert "Test note message" in html_output
    assert "N/A" in html_output  # Location should show as N/A
