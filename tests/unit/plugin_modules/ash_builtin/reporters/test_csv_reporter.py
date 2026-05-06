"""Tests for CsvReporter plugin."""

import csv
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
    CSVReporterConfig,
)


@pytest.fixture
def csv_reporter(test_plugin_context):
    """Create a CsvReporter instance."""
    return CsvReporter(context=test_plugin_context)


class TestCSVReporterConfig:
    """Tests for CSVReporterConfig defaults."""

    def test_default_config_values(self):
        """Config has correct defaults."""
        config = CSVReporterConfig()
        assert config.name == "csv"
        assert config.extension == "csv"
        assert config.enabled is True


class TestCsvReporter:
    """Tests for CsvReporter."""

    def test_model_post_init_sets_default_config(self, test_plugin_context):
        """If config is None, model_post_init sets a default CSVReporterConfig."""
        reporter = CsvReporter(config=None, context=test_plugin_context)
        assert reporter.config is not None
        assert isinstance(reporter.config, CSVReporterConfig)

    def test_sarif_field_mappings_returns_dict(self):
        """sarif_field_mappings returns a non-empty dict mapping paths to headers."""
        mappings = CsvReporter.sarif_field_mappings()
        assert mappings is not None
        assert isinstance(mappings, dict)
        assert "runs[].results[].ruleId" in mappings
        assert mappings["runs[].results[].ruleId"] == "Rule ID"

    def test_report_empty_model_returns_header_only(
        self, csv_reporter, sample_ash_model
    ):
        """When there are no vulnerabilities, only the header row is produced."""
        result = csv_reporter.report(sample_ash_model)

        lines = result.strip().split("\n")
        assert len(lines) == 1  # header only
        # Verify some expected header columns
        assert "ID" in lines[0]
        assert "Severity" in lines[0]
        assert "Scanner" in lines[0]

    def test_report_with_vulnerabilities(self, csv_reporter):
        """When there are vulnerabilities, data rows follow the header."""
        model = MagicMock()
        vuln = MagicMock()
        vuln.model_dump.return_value = {
            "id": "V1",
            "title": "Test Finding",
            "severity": "high",
            "scanner": "bandit",
        }
        model.to_flat_vulnerabilities.return_value = [vuln]

        result = csv_reporter.report(model)

        reader = csv.reader(StringIO(result))
        rows = list(reader)
        assert len(rows) == 2  # header + 1 data row
        assert rows[0] == ["id", "title", "severity", "scanner"]
        assert rows[1] == ["V1", "Test Finding", "high", "bandit"]

    def test_report_none_values_become_empty_string(self, csv_reporter):
        """None values in vulnerability fields are written as empty strings."""
        model = MagicMock()
        vuln = MagicMock()
        vuln.model_dump.return_value = {
            "id": "V2",
            "title": None,
            "severity": "low",
        }
        model.to_flat_vulnerabilities.return_value = [vuln]

        result = csv_reporter.report(model)

        reader = csv.reader(StringIO(result))
        rows = list(reader)
        # None should become empty string
        assert rows[1][1] == ""

    def test_report_multiple_vulnerabilities(self, csv_reporter):
        """Multiple vulnerabilities produce multiple data rows."""
        model = MagicMock()
        vulns = []
        for i in range(3):
            v = MagicMock()
            v.model_dump.return_value = {"id": f"V{i}", "severity": "medium"}
            vulns.append(v)
        model.to_flat_vulnerabilities.return_value = vulns

        result = csv_reporter.report(model)

        reader = csv.reader(StringIO(result))
        rows = list(reader)
        assert len(rows) == 4  # header + 3 data rows
