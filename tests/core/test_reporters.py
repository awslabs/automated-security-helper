"""Unit tests for output formatter module."""

import json
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.reporters.ash_default import CSVReporter
from automated_security_helper.reporters.ash_default import HTMLReporter
from automated_security_helper.reporters.ash_default import JSONReporter


def test_json_formatter(sample_ash_model: ASHARPModel):
    formatter = JSONReporter()
    output = formatter.format(sample_ash_model)

    # Verify output is valid JSON
    parsed = json.loads(output)
    assert "sarif" in parsed
    assert "cyclonedx" in parsed
    assert "additional_reports" in parsed
    assert "ash_config" in parsed
    assert "metadata" in parsed


def test_html_formatter(sample_ash_model):
    formatter = HTMLReporter()
    output = formatter.format(sample_ash_model)

    # Verify basic HTML structure
    assert "<!DOCTYPE html>" in output
    assert "<html>" in output
    assert "<title>ASH Results</title>" in output
    assert "<h1>Security Scan Results</h1>" in output

    # Verify content is included and properly escaped
    assert "<td>CKV_AWS_53</td>" in output
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
