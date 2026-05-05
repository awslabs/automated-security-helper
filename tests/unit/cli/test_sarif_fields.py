"""Tests for cli/inspect/sarif_fields.py — covers flatten_sarif_results, _flatten_object, and related helpers."""

import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from automated_security_helper.cli.inspect.sarif_fields import (
    flatten_sarif_results,
    _flatten_object,
    get_scanner_name_from_path,
)


class TestFlattenSarifResults:
    """Tests for flatten_sarif_results."""

    def test_empty_sarif_data(self):
        included, excluded = flatten_sarif_results({})
        assert included == {}
        assert excluded == {}

    def test_no_runs(self):
        included, excluded = flatten_sarif_results({"runs": []})
        assert included == {}
        assert excluded == {}

    def test_run_with_no_results(self):
        included, excluded = flatten_sarif_results({"runs": [{"tool": {}}]})
        assert included == {}
        assert excluded == {}

    def test_basic_result_flattening(self):
        sarif_data = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "TEST001",
                            "message": {"text": "Finding message"},
                            "level": "error",
                        }
                    ]
                }
            ]
        }
        included, excluded = flatten_sarif_results(sarif_data)
        assert "runs[].results[].ruleId" in included
        assert "runs[].results[].level" in included

    def test_nested_dict_flattening(self):
        sarif_data = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "TEST001",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/main.py"},
                                        "region": {"startLine": 10},
                                    }
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        included, excluded = flatten_sarif_results(sarif_data)
        # Should contain nested paths with [] for arrays
        assert "runs[].results[].ruleId" in included

    def test_properties_field_not_expanded(self):
        sarif_data = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "TEST001",
                            "properties": {
                                "tags": ["security"],
                                "nested": {"deep": "value"},
                            },
                        }
                    ]
                }
            ]
        }
        included, excluded = flatten_sarif_results(sarif_data)
        # properties should be present but not further expanded
        assert "runs[].results[].properties" in included
        # Sub-keys should NOT be expanded
        assert "runs[].results[].properties.tags" not in included
        assert "runs[].results[].properties.nested" not in included

    def test_array_uses_bracket_notation(self):
        sarif_data = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "TEST001",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "test.py"}
                                    }
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        included, excluded = flatten_sarif_results(sarif_data)
        # Arrays should use [] notation
        has_bracket_notation = any("[]" in key for key in included)
        assert has_bracket_notation


class TestFlattenObject:
    """Tests for _flatten_object helper."""

    def test_flat_dict(self):
        result = {}
        excluded = {}
        with patch(
            "automated_security_helper.cli.inspect.sarif_fields.should_include_field",
            return_value=True,
        ):
            _flatten_object({"key": "value", "num": 42}, "prefix", result, excluded)
        assert "prefix.key" in result
        assert "prefix.num" in result

    def test_nested_dict(self):
        result = {}
        with patch(
            "automated_security_helper.cli.inspect.sarif_fields.should_include_field",
            return_value=True,
        ):
            _flatten_object({"outer": {"inner": "val"}}, "prefix", result, None)
        assert "prefix.outer.inner" in result

    def test_list_uses_bracket_notation(self):
        result = {}
        with patch(
            "automated_security_helper.cli.inspect.sarif_fields.should_include_field",
            return_value=True,
        ):
            _flatten_object(
                [{"item": "val"}], "prefix", result, None
            )
        assert "prefix[].item" in result

    def test_empty_list(self):
        result = {}
        _flatten_object([], "prefix", result, None)
        assert result == {}

    def test_properties_stops_expansion(self):
        result = {}
        with patch(
            "automated_security_helper.cli.inspect.sarif_fields.should_include_field",
            return_value=True,
        ):
            _flatten_object(
                {"properties": {"deep": {"nested": "val"}}},
                "prefix",
                result,
                None,
            )
        assert "prefix.properties" in result
        assert "prefix.properties.deep" not in result

    def test_excluded_fields_tracked(self):
        result = {}
        excluded = {}
        with patch(
            "automated_security_helper.cli.inspect.sarif_fields.should_include_field",
            side_effect=lambda path: "excluded_key" not in path,
        ):
            _flatten_object(
                {"included_key": "yes", "excluded_key": "no"},
                "prefix",
                result,
                excluded,
            )
        assert "prefix.included_key" in result
        assert "prefix.excluded_key" in excluded


class TestGetScannerNameFromPath:
    """Tests for get_scanner_name_from_path."""

    def test_scanner_in_scanners_dir(self):
        path = "/output/scanners/bandit/results.sarif"
        assert get_scanner_name_from_path(path) == "bandit"

    def test_scanner_in_deep_path(self):
        path = "/some/deep/scanners/checkov/output/report.sarif"
        assert get_scanner_name_from_path(path) == "checkov"

    def test_file_not_in_scanners_dir(self):
        path = "/output/reports/my_report.sarif"
        name = get_scanner_name_from_path(path)
        assert name == "my_report"

    def test_bare_filename(self):
        path = "results.sarif"
        name = get_scanner_name_from_path(path)
        assert name == "results"
