#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the read-only MCP tools: explain, diff, config, suppression, profiles.

These tools differ from the scan tools in that they parse caller-supplied files,
so most of their untested surface is malformed-input handling. Three of them
store structured data as JSON strings inside a string field (FlatVulnerability's
``references`` and ``raw_data``), and each has a fallback for the case where that
string is not actually JSON -- those fallbacks are what several tests below pin.

Real ``FlatVulnerability`` and ``AshConfig`` instances are used rather than
doubles. A double would let a test pass while referring to a field the model does
not have, which is precisely the failure these tests exist to rule out.
"""

import importlib
import json
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp_tools import (
    _load_flat_vulns_for_explain,
    mcp_diff_scan_results,
    mcp_explain_finding,
    mcp_list_scanners,
    mcp_select_profile,
    mcp_set_source_zip_chunk,
    mcp_suggest_suppression,
    mcp_validate_config,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability

_TOOLS = "automated_security_helper.cli.mcp_tools"


def _vuln(**overrides):
    """A minimal valid FlatVulnerability; overrides replace individual fields."""
    fields = {
        "id": "finding-1",
        "title": "Hardcoded credential",
        "description": "A credential is embedded in source.",
        "severity": "HIGH",
        "scanner": "detect-secrets",
        "scanner_type": "SAST",
    }
    fields.update(overrides)
    return FlatVulnerability(**fields)


class TestLoadFlatVulnsForExplain:
    def test_defaults_to_the_ash_output_directory_under_cwd(
        self, tmp_path, monkeypatch
    ):
        """results_path=None resolves to <cwd>/.ash/ash_output.

        Asserted through the error message, which names the file it looked for,
        so the test pins the location rather than just the failure.
        """
        monkeypatch.chdir(tmp_path)

        with pytest.raises(FileNotFoundError) as excinfo:
            _load_flat_vulns_for_explain(None)

        expected = tmp_path / ".ash" / "ash_output" / "ash_aggregated_results.json"
        assert str(expected) in str(excinfo.value)
        assert "Results file not found" in str(excinfo.value)

    def test_a_directory_argument_is_used_as_the_output_directory(self, tmp_path):
        out = tmp_path / "ash_output"
        out.mkdir()

        with pytest.raises(FileNotFoundError) as excinfo:
            _load_flat_vulns_for_explain(str(out))

        assert str(out / "ash_aggregated_results.json") in str(excinfo.value)

    def test_a_file_argument_is_read_relative_to_its_parent(self, tmp_path):
        out = tmp_path / "ash_output"
        out.mkdir()
        pointer = out / "some_other_file.json"
        pointer.write_text("{}")

        with pytest.raises(FileNotFoundError) as excinfo:
            _load_flat_vulns_for_explain(str(pointer))

        assert str(out / "ash_aggregated_results.json") in str(excinfo.value)


class TestExplainFinding:
    def test_unreadable_results_are_reported_rather_than_raised(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)

        result = mcp_explain_finding("finding-1")

        assert result["success"] is False
        assert result["operation"] == "explain_finding"
        assert "Failed to load scan results" in result["error"]

    def test_unknown_finding_id_is_reported(self):
        with patch(f"{_TOOLS}._load_flat_vulns_for_explain", return_value=[_vuln()]):
            result = mcp_explain_finding("no-such-finding")

        assert result["success"] is False
        assert "Finding 'no-such-finding' not found in scan results" in result["error"]

    def test_json_encoded_references_are_decoded_into_a_list(self):
        vuln = _vuln(references=json.dumps(["https://example.test/a"]))

        with patch(f"{_TOOLS}._load_flat_vulns_for_explain", return_value=[vuln]):
            result = mcp_explain_finding("finding-1")

        assert result["success"] is True
        assert result["finding"]["references"] == ["https://example.test/a"]

    def test_non_json_references_are_wrapped_in_a_single_element_list(self):
        """The field is typed as a JSON string but scanners do not always comply."""
        vuln = _vuln(references="see the vendor advisory")

        with patch(f"{_TOOLS}._load_flat_vulns_for_explain", return_value=[vuln]):
            result = mcp_explain_finding("finding-1")

        assert result["success"] is True
        assert result["finding"]["references"] == ["see the vendor advisory"]

    def test_absent_references_become_an_empty_list(self):
        with patch(f"{_TOOLS}._load_flat_vulns_for_explain", return_value=[_vuln()]):
            result = mcp_explain_finding("finding-1")

        assert result["finding"]["references"] == []

    def test_json_encoded_raw_data_is_decoded_into_a_dict(self):
        vuln = _vuln(raw_data=json.dumps({"check_id": "B105"}))

        with patch(f"{_TOOLS}._load_flat_vulns_for_explain", return_value=[vuln]):
            result = mcp_explain_finding("finding-1")

        assert result["finding"]["scanner_metadata"] == {"check_id": "B105"}

    def test_non_json_raw_data_is_preserved_under_a_raw_key(self):
        vuln = _vuln(raw_data="B105:hardcoded_password_string")

        with patch(f"{_TOOLS}._load_flat_vulns_for_explain", return_value=[vuln]):
            result = mcp_explain_finding("finding-1")

        assert result["finding"]["scanner_metadata"] == {
            "raw": "B105:hardcoded_password_string"
        }

    def test_absent_raw_data_becomes_an_empty_dict(self):
        with patch(f"{_TOOLS}._load_flat_vulns_for_explain", return_value=[_vuln()]):
            result = mcp_explain_finding("finding-1")

        assert result["finding"]["scanner_metadata"] == {}

    @pytest.mark.parametrize(
        "severity, expected_phrase",
        [
            ("CRITICAL", "above any threshold"),
            ("HIGH", "above MEDIUM threshold"),
            ("LOW", "below MEDIUM threshold"),
        ],
    )
    def test_known_severities_get_their_rationale(self, severity, expected_phrase):
        vuln = _vuln(severity=severity)

        with patch(f"{_TOOLS}._load_flat_vulns_for_explain", return_value=[vuln]):
            result = mcp_explain_finding("finding-1")

        assert expected_phrase in result["finding"]["severity_rationale"]

    def test_unrecognized_severity_falls_back_to_a_generic_rationale(self):
        vuln = _vuln(severity="MODERATE")

        with patch(f"{_TOOLS}._load_flat_vulns_for_explain", return_value=[vuln]):
            result = mcp_explain_finding("finding-1")

        assert result["finding"]["severity_rationale"] == "MODERATE severity"


class TestDiffScanResults:
    def test_missing_before_file_is_named_in_the_error(self, tmp_path):
        after = tmp_path / "after.json"
        after.write_text("{}")

        result = mcp_diff_scan_results(str(tmp_path / "absent.json"), str(after))

        assert result["success"] is False
        assert "before_path does not exist" in result["error"]

    def test_missing_after_file_is_named_in_the_error(self, tmp_path):
        before = tmp_path / "before.json"
        before.write_text("{}")

        result = mcp_diff_scan_results(str(before), str(tmp_path / "absent.json"))

        assert result["success"] is False
        assert "after_path does not exist" in result["error"]

    def test_unparseable_result_file_is_reported_not_raised(self, tmp_path):
        before = tmp_path / "before.json"
        after = tmp_path / "after.json"
        before.write_text("this is not json at all")
        after.write_text("this is not json either")

        result = mcp_diff_scan_results(str(before), str(after))

        assert result["success"] is False
        assert "Failed to parse result file" in result["error"]


class TestValidateConfig:
    def test_neither_content_nor_path_is_a_usable_error(self):
        result = mcp_validate_config()

        assert result["valid"] is False
        assert result["errors"] == [
            {
                "field": "",
                "message": "Either config_content or config_path must be provided.",
                "type": "missing_input",
            }
        ]

    def test_missing_config_file_is_reported_against_the_path_field(self, tmp_path):
        result = mcp_validate_config(config_path=str(tmp_path / "absent.yaml"))

        assert result["valid"] is False
        assert result["errors"][0]["field"] == "config_path"
        assert result["errors"][0]["type"] == "file_not_found"
        assert "Config file not found" in result["errors"][0]["message"]

    @pytest.mark.parametrize(
        "raw_error, expected_type, expected_field",
        [
            ("YAML parsing error near line 4", "yaml_parse_error", ""),
            ("JSON parsing error at offset 12", "json_parse_error", ""),
            (
                "Missing required field 'project_name'",
                "missing_required_field",
                "project_name",
            ),
            ("Config sets internal-only field 'mode'", "internal_field", "mode"),
            ("Unknown top-level entry 'scannerz'", "unknown_field", "scannerz"),
            (
                "Invalid value for 'severity_threshold'",
                "invalid_field",
                "severity_threshold",
            ),
            ("Duplicate scanner entry 'bandit'", "duplicate_field", "bandit"),
            ("Something went sideways", "validation_error", ""),
        ],
    )
    def test_validator_errors_are_classified_by_message(
        self, tmp_path, raw_error, expected_type, expected_field
    ):
        config = tmp_path / "ash.yaml"
        config.write_text("project_name: demo\n")

        with patch(
            "automated_security_helper.config.config_validator."
            "ConfigValidator.validate_config_file",
            return_value=(False, [raw_error]),
        ):
            result = mcp_validate_config(config_path=str(config))

        assert result["valid"] is False
        assert len(result["errors"]) == 1
        assert result["errors"][0]["type"] == expected_type
        assert result["errors"][0]["field"] == expected_field
        assert result["errors"][0]["message"] == raw_error

    def test_a_valid_config_reports_no_errors(self, tmp_path):
        config = tmp_path / "ash.yaml"
        config.write_text("project_name: demo\n")

        with patch(
            "automated_security_helper.config.config_validator."
            "ConfigValidator.validate_config_file",
            return_value=(True, []),
        ):
            result = mcp_validate_config(config_path=str(config))

        assert result["valid"] is True
        assert result["errors"] == []

    def test_inline_content_is_validated_through_a_temporary_file(self):
        seen = {}

        def _capture(path, source_dir=None):
            seen["suffix"] = path.suffix
            seen["text"] = path.read_text()
            return (True, [])

        with patch(
            "automated_security_helper.config.config_validator."
            "ConfigValidator.validate_config_file",
            side_effect=_capture,
        ):
            result = mcp_validate_config(config_content="project_name: inline\n")

        assert result["valid"] is True
        assert seen["suffix"] == ".yaml"
        assert seen["text"] == "project_name: inline\n"


class TestSuggestSuppression:
    def test_defaults_to_the_ash_output_results_file_under_cwd(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)

        result = mcp_suggest_suppression("finding-1")

        assert result["success"] is False
        expected = tmp_path / ".ash" / "ash_output" / "ash_aggregated_results.json"
        assert str(expected) in result["error"]
        assert "Results file not found" in result["error"]

    def test_unparseable_results_file_is_reported_not_raised(self, tmp_path):
        results = tmp_path / "ash_aggregated_results.json"
        results.write_text("definitely not json")

        result = mcp_suggest_suppression("finding-1", results_path=str(results))

        assert result["success"] is False
        assert "Failed to parse results file" in result["error"]


class TestSelectProfile:
    @pytest.fixture
    def one_profile(self, tmp_path):
        """A registry holding a single profile named "baseline"."""
        from automated_security_helper.cli.mcp.profile_registry import ProfileEntry
        from automated_security_helper.config.ash_config import AshConfig

        path = tmp_path / "baseline.yaml"
        path.write_text("project_name: baseline-project\n")
        return {
            "baseline": ProfileEntry(
                name="baseline",
                path=path,
                config=AshConfig(project_name="baseline-project"),
                path_sha256="0" * 64,
            )
        }

    def test_patch_ops_and_override_yaml_together_are_refused(self):
        result = mcp_select_profile("baseline", patch_ops=[], override_yaml="{}")

        assert result["success"] is False
        assert result["error"] == "patch_ops and override_yaml are mutually exclusive"

    def test_unknown_profile_with_an_empty_registry_says_none_registered(self):
        with patch(
            "automated_security_helper.cli.mcp.profile_registry.get_profile_registry",
            return_value={},
        ):
            result = mcp_select_profile("ghost")

        assert result["success"] is False
        assert "none registered" in result["error"]

    def test_unknown_profile_lists_the_known_ones(self, one_profile):
        with patch(
            "automated_security_helper.cli.mcp.profile_registry.get_profile_registry",
            return_value=one_profile,
        ):
            result = mcp_select_profile("ghost")

        assert result["success"] is False
        assert "known: baseline" in result["error"]

    def test_unparseable_override_yaml_is_reported(self, one_profile):
        with patch(
            "automated_security_helper.cli.mcp.profile_registry.get_profile_registry",
            return_value=one_profile,
        ):
            result = mcp_select_profile("baseline", override_yaml="key: [unclosed")

        assert result["success"] is False
        assert "override_yaml parse error" in result["error"]

    def test_unknown_top_level_field_in_override_yaml_is_reported(self, one_profile):
        with patch(
            "automated_security_helper.cli.mcp.profile_registry.get_profile_registry",
            return_value=one_profile,
        ):
            result = mcp_select_profile(
                "baseline", override_yaml="not_a_real_field: 1\n"
            )

        assert result["success"] is False
        assert "unknown top-level field(s): not_a_real_field" in result["error"]

    def test_wrongly_typed_override_yaml_is_reported_as_a_validation_error(
        self, one_profile
    ):
        """project_name is typed str; strict validation must refuse an int."""
        with patch(
            "automated_security_helper.cli.mcp.profile_registry.get_profile_registry",
            return_value=one_profile,
        ):
            result = mcp_select_profile("baseline", override_yaml="project_name: 123\n")

        assert result["success"] is False
        assert "override_yaml validation error" in result["error"]
        assert "project_name" in result["error"]


class TestSetSourceZipChunk:
    def test_validation_failure_is_returned_as_an_error_response(self):
        with patch(
            "automated_security_helper.cli.mcp.source_delivery.set_source_zip_chunk",
            side_effect=ValueError("chunk 3 arrived out of order"),
        ):
            result = mcp_set_source_zip_chunk(
                upload_id="up-1",
                sequence=3,
                data_b64="",
                last=False,
                session_id="sess-1",
            )

        assert result["success"] is False
        assert result["error"] == "chunk 3 arrived out of order"

    def test_successful_chunk_result_is_merged_into_the_response(self):
        with patch(
            "automated_security_helper.cli.mcp.source_delivery.set_source_zip_chunk",
            return_value={"received": 1024, "next_sequence": 1, "last": False},
        ):
            result = mcp_set_source_zip_chunk(
                upload_id="up-1",
                sequence=0,
                data_b64="AAAA",
                last=False,
                session_id="sess-1",
            )

        assert result == {
            "success": True,
            "received": 1024,
            "next_sequence": 1,
            "last": False,
        }


# --- mcp_list_scanners -------------------------------------------------------
#
# Synthetic scanner classes below stand in for real plugin classes. They are
# plain classes, not Mocks: mcp_list_scanners reads __name__ and walks
# model_fields["config"].annotation.__args__, and a Mock would fabricate both,
# so the name-derivation logic could never be observed failing.


class _FieldInfo:
    def __init__(self, annotation):
        self.annotation = annotation


class _Union:
    def __init__(self, *args):
        self.__args__ = args


class ExplodingScannerConfig:
    def __init__(self):
        raise RuntimeError("config class cannot be instantiated")


class NamelessScannerConfig:
    name = None
    enabled = False


class PlainThingScanner:
    """No config field at all, so the name is derived from the class name."""

    offline_strategy = None


class ExplodingScanner:
    offline_strategy = None
    model_fields = {"config": _FieldInfo(_Union(ExplodingScannerConfig))}


class NamelessScanner:
    offline_strategy = None
    model_fields = {"config": _FieldInfo(_Union(NamelessScannerConfig))}


class TestListScanners:
    @staticmethod
    def _run(scanner_classes, pkg_dist=None, pkg_dist_error=None):
        loader = "automated_security_helper.plugins.loader"
        patches = [
            patch(f"{loader}.load_internal_plugins"),
            patch(f"{loader}.load_additional_plugin_modules"),
            patch(
                "automated_security_helper.plugins.ash_plugin_manager.plugin_modules",
                return_value=scanner_classes,
            ),
        ]
        if pkg_dist_error is not None:
            patches.append(
                patch(
                    "importlib.metadata.packages_distributions",
                    side_effect=pkg_dist_error,
                )
            )
        else:
            patches.append(
                patch(
                    "importlib.metadata.packages_distributions",
                    return_value=pkg_dist or {},
                )
            )
        with patches[0], patches[1], patches[2], patches[3]:
            return mcp_list_scanners()

    def test_class_name_is_converted_to_snake_case_without_the_scanner_suffix(self):
        results = self._run([PlainThingScanner])

        assert [r["name"] for r in results] == ["plain_thing"]
        assert results[0]["offline_strategy"] == "unknown"
        assert results[0]["version"] is None

    def test_a_config_class_that_cannot_be_built_defaults_to_enabled(self):
        results = self._run([ExplodingScanner])

        assert results[0]["name"] == "exploding"
        assert results[0]["enabled"] is True

    def test_a_config_without_a_name_keeps_its_own_enabled_default(self):
        results = self._run([NamelessScanner])

        assert results[0]["name"] == "nameless"
        assert results[0]["enabled"] is False

    def test_offline_strategy_is_read_from_the_class_when_present(self):
        class _Strategy:
            value = "skip"

        class CachedThingScanner:
            offline_strategy = _Strategy()

        results = self._run([CachedThingScanner])

        assert results[0]["offline_strategy"] == "skip"

    def test_an_external_plugin_distribution_is_loaded_as_a_plugin_module(self):
        loader = "automated_security_helper.plugins.loader"

        with (
            patch(f"{loader}.load_internal_plugins"),
            patch(f"{loader}.load_additional_plugin_modules") as load_extra,
            patch(
                "automated_security_helper.plugins.ash_plugin_manager.plugin_modules",
                return_value=[],
            ),
            patch(
                "importlib.metadata.packages_distributions",
                return_value={
                    "acme_scan": ["ash_acme_plugins"],
                    "requests": ["requests"],
                },
            ),
        ):
            mcp_list_scanners()

        load_extra.assert_called_once_with(
            ["automated_security_helper.plugin_modules.acme_scan"]
        )

    def test_unavailable_distribution_metadata_does_not_break_the_listing(self):
        """packages_distributions raising falls back to the well-known modules."""
        results = self._run(
            [PlainThingScanner], pkg_dist_error=RuntimeError("no metadata")
        )

        assert [r["name"] for r in results] == ["plain_thing"]

    def test_a_missing_well_known_plugin_module_is_skipped(self):
        loader = "automated_security_helper.plugins.loader"
        real_import = importlib.import_module

        def _import(name, *args, **kwargs):
            if ".plugin_modules." in name:
                raise ImportError(f"no module named {name}")
            return real_import(name, *args, **kwargs)

        with (
            patch(f"{loader}.load_internal_plugins"),
            patch(
                "automated_security_helper.plugins.ash_plugin_manager.plugin_modules",
                return_value=[PlainThingScanner],
            ),
            patch("importlib.metadata.packages_distributions", return_value={}),
            patch("importlib.import_module", side_effect=_import),
        ):
            results = mcp_list_scanners()

        assert [r["name"] for r in results] == ["plain_thing"]
