"""Unit tests for output formatter module."""

from importlib.metadata import version
import json
import pytest
from automated_security_helper.models.core import Scanner
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.reporters.csv_reporter import CSVReporter
from automated_security_helper.reporters.html_reporter import HTMLReporter
from automated_security_helper.reporters.json_reporter import JSONReporter


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
        metadata={"scanner": "test_scanner", "timestamp": "2023-01-01T00:00:00Z"},
    )
    return model


def test_json_formatter(sample_ash_model):
    formatter = JSONReporter()
    output = formatter.format(sample_ash_model)

    # Verify output is valid JSON
    parsed = json.loads(output)
    assert "sarif" in parsed
    assert "cyclonedx" in parsed
    assert "additional_reports" in parsed
    assert "ash_config" in parsed
    assert "metadata" in parsed
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
