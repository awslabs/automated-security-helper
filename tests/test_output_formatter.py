"""Unit tests for output formatter module."""

from importlib.metadata import version
import json
import pytest
from automated_security_helper.models.core import Location, Scanner
from automated_security_helper.models.iac_scan import IaCVulnerability
from automated_security_helper.core.output_formatter import (
    OutputFormatter,
    JSONReporter,
    HTMLReporter,
    CSVReporter,
)
from automated_security_helper.models.asharp_model import ASHARPModel


@pytest.fixture
def sample_ash_model():
    model = ASHARPModel(
        scanners_used=[
            Scanner(name="bandit", version=version("bandit")),
            Scanner(name="cdk_nag", version=version("cdk_nag")),
            Scanner(name="checkov", version=version("checkov")),
            Scanner(name="jupyterlab", version=version("jupyterlab")),
            Scanner(name="nbconvert", version=version("nbconvert")),
        ],
        findings=[
            IaCVulnerability(
                id="finding-1",
                title="AwsSolutionsChecks/finding-1 - SQL Injection",
                compliance_frameworks=["AwsSolutionsChecks"],
                description="SQL Injection vulnerability",
                severity="HIGH",
                location=Location(
                    file_path="path/to/file", snippet="sql.query(user_input + ';GO')"
                ),
                resource_name="LambdaFunction1",
                rule_id="AwsSolutionsChecks/finding-1",
                status="OPEN",
            )
        ],
        metadata={"scanner": "test_scanner", "timestamp": "2023-01-01T00:00:00Z"},
    )
    return model


def test_json_formatter(sample_ash_model):
    formatter = JSONReporter()
    output = formatter.format(sample_ash_model)

    # Verify output is valid JSON
    parsed = json.loads(output)
    assert "findings" in parsed
    assert "metadata" in parsed
    assert parsed["findings"][0] == sample_ash_model.findings[0].model_dump()
    assert parsed["metadata"] == sample_ash_model.metadata.model_dump()


def test_html_formatter(sample_ash_model):
    formatter = HTMLReporter()
    output = formatter.format(sample_ash_model)

    # Verify basic HTML structure
    assert "<!DOCTYPE html>" in output
    assert "<html>" in output
    assert "<title>ASH Results</title>" in output
    assert "<h1>Security Scan Results</h1>" in output

    # Verify content is included and properly escaped
    assert "SQL Injection vulnerability" in output
    assert "&lt;" not in output  # Verify no double-escaping


def test_csv_formatter(sample_ash_model):
    formatter = CSVReporter()
    output = formatter.format(sample_ash_model)

    # Verify CSV structure
    lines = output.strip().split("\n")
    assert len(lines) >= 1  # At least header row

    # Verify header row
    header = lines[0].split(",")
    assert "Finding ID" in header
    assert "Severity" in header
    assert "Description" in header
    assert "Location" in header


def test_output_formatter_format_selection():
    formatter = OutputFormatter()
    model = ASHARPModel()

    # Test JSON format
    json_output = formatter.format(model, "json")
    assert isinstance(json_output, str)
    assert json.loads(json_output)  # Verify valid JSON

    # Test HTML format
    html_output = formatter.format(model, "html")
    assert isinstance(html_output, str)
    assert "<!DOCTYPE html>" in html_output

    # Test CSV format
    csv_output = formatter.format(model, "csv")
    assert isinstance(csv_output, str)
    assert "Finding ID,Severity,Description,Location" in csv_output


def test_output_formatter_invalid_format():
    formatter = OutputFormatter()
    model = ASHARPModel()

    with pytest.raises(ValueError):
        formatter.format(model, "invalid_format")
