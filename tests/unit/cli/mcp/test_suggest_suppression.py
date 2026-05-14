# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for mcp_suggest_suppression and ash://schema/suppression resource."""

import json
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from automated_security_helper.cli.mcp_tools import mcp_suggest_suppression
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability


def _make_vuln(
    id: str = "bandit-B101-abc12345",
    file_path: str = "src/app.py",
    rule_id: str = "B101",
    line_start: int = 42,
    line_end: int = 42,
) -> FlatVulnerability:
    return FlatVulnerability(
        id=id,
        title="Use of assert detected",
        description="Use of assert statement detected",
        severity="MEDIUM",
        scanner="bandit",
        scanner_type="SAST",
        rule_id=rule_id,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
    )


def _make_aggregated_json(vulns: list) -> dict:
    """Build minimal ash_aggregated_results.json-compatible dict.

    from_additional_report prepends scanner_name to the entry id, so we strip
    the leading "<scanner>-" prefix from the FlatVulnerability id when building
    the entry so that the reconstructed id matches the original.
    """
    findings_by_scanner: dict = {}
    for v in vulns:
        scanner = v.scanner
        prefix = f"{scanner}-"
        # Strip the scanner prefix that from_additional_report will re-add
        entry_id = v.id[len(prefix):] if v.id.startswith(prefix) else v.id
        if scanner not in findings_by_scanner:
            findings_by_scanner[scanner] = []
        findings_by_scanner[scanner].append({
            "id": entry_id,
            "title": v.title,
            "description": v.description,
            "severity": v.severity,
            "type": v.scanner_type,
            "rule_id": v.rule_id,
            "file_path": v.file_path,
            "line_start": v.line_start,
            "line_end": v.line_end,
        })
    return {
        "metadata": {
            "scan_id": "test-scan",
            "scan_timestamp": "2026-01-01T00:00:00+00:00",
            "summary_stats": {
                "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "suppressed": 0
            },
        },
        "sarif": {"version": "2.1.0", "runs": []},
        "additional_reports": findings_by_scanner,
        "scanner_results": {},
    }


class TestSuggestionContent:
    def test_suggestion_includes_path_and_rule_id(self, tmp_path):
        vuln = _make_vuln(file_path="src/app.py", rule_id="B101")
        results_file = tmp_path / "ash_aggregated_results.json"
        results_file.write_text(json.dumps(_make_aggregated_json([vuln])))

        result = mcp_suggest_suppression(
            finding_id=vuln.id,
            results_path=str(results_file),
        )

        assert result["success"] is True
        suppression_json = result["json"]
        assert suppression_json["path"] == "src/app.py"
        assert suppression_json["rule_id"] == "B101"

    def test_suggestion_yaml_round_trips_via_pydantic(self, tmp_path):
        vuln = _make_vuln()
        results_file = tmp_path / "ash_aggregated_results.json"
        results_file.write_text(json.dumps(_make_aggregated_json([vuln])))

        result = mcp_suggest_suppression(
            finding_id=vuln.id,
            results_path=str(results_file),
        )

        assert result["success"] is True
        parsed = yaml.safe_load(result["yaml"])
        suppression = AshSuppression.model_validate(parsed)
        assert suppression.path == "src/app.py"
        assert suppression.rule_id == "B101"

    def test_suggestion_json_matches_yaml(self, tmp_path):
        vuln = _make_vuln()
        results_file = tmp_path / "ash_aggregated_results.json"
        results_file.write_text(json.dumps(_make_aggregated_json([vuln])))

        result = mcp_suggest_suppression(
            finding_id=vuln.id,
            results_path=str(results_file),
        )

        assert result["success"] is True
        from_yaml = yaml.safe_load(result["yaml"])
        assert from_yaml == result["json"]

    def test_suggestion_includes_line_start_and_line_end(self, tmp_path):
        vuln = _make_vuln(line_start=10, line_end=15)
        results_file = tmp_path / "ash_aggregated_results.json"
        results_file.write_text(json.dumps(_make_aggregated_json([vuln])))

        result = mcp_suggest_suppression(
            finding_id=vuln.id,
            results_path=str(results_file),
        )

        assert result["success"] is True
        assert result["json"]["line_start"] == 10
        assert result["json"]["line_end"] == 15


class TestExpirationDefault:
    def test_suggestion_default_expiration_90_days_from_today(self, tmp_path):
        vuln = _make_vuln()
        results_file = tmp_path / "ash_aggregated_results.json"
        results_file.write_text(json.dumps(_make_aggregated_json([vuln])))

        result = mcp_suggest_suppression(
            finding_id=vuln.id,
            results_path=str(results_file),
        )

        assert result["success"] is True
        expected = (date.today() + timedelta(days=90)).strftime("%Y-%m-%d")
        assert result["json"]["expiration"] == expected

    def test_explicit_expiration_overrides_default(self, tmp_path):
        vuln = _make_vuln()
        results_file = tmp_path / "ash_aggregated_results.json"
        results_file.write_text(json.dumps(_make_aggregated_json([vuln])))

        result = mcp_suggest_suppression(
            finding_id=vuln.id,
            results_path=str(results_file),
            expiration="2030-12-31",
        )

        assert result["success"] is True
        assert result["json"]["expiration"] == "2030-12-31"


class TestJustification:
    def test_custom_justification_appears_in_output(self, tmp_path):
        vuln = _make_vuln()
        results_file = tmp_path / "ash_aggregated_results.json"
        results_file.write_text(json.dumps(_make_aggregated_json([vuln])))

        result = mcp_suggest_suppression(
            finding_id=vuln.id,
            results_path=str(results_file),
            justification="Reviewed and accepted risk",
        )

        assert result["success"] is True
        assert result["json"]["reason"] == "Reviewed and accepted risk"

    def test_default_justification_is_present(self, tmp_path):
        vuln = _make_vuln()
        results_file = tmp_path / "ash_aggregated_results.json"
        results_file.write_text(json.dumps(_make_aggregated_json([vuln])))

        result = mcp_suggest_suppression(
            finding_id=vuln.id,
            results_path=str(results_file),
        )

        assert result["success"] is True
        assert "reason" in result["json"]
        assert result["json"]["reason"]  # non-empty


class TestFindingNotFound:
    def test_finding_not_found_returns_error(self, tmp_path):
        vuln = _make_vuln()
        results_file = tmp_path / "ash_aggregated_results.json"
        results_file.write_text(json.dumps(_make_aggregated_json([vuln])))

        result = mcp_suggest_suppression(
            finding_id="nonexistent-id-xyz",
            results_path=str(results_file),
        )

        assert result["success"] is False
        assert "nonexistent-id-xyz" in result["error"]

    def test_missing_results_file_returns_error(self, tmp_path):
        result = mcp_suggest_suppression(
            finding_id="some-id",
            results_path=str(tmp_path / "does_not_exist.json"),
        )

        assert result["success"] is False
        assert "error" in result


class TestSchemaResource:
    def test_resource_ash_schema_suppression_returns_schema(self):
        from automated_security_helper.cli.mcp_server import (
            _read_ash_suppression_schema,
        )

        content = _read_ash_suppression_schema()
        parsed = json.loads(content)
        assert any(
            k in parsed
            for k in ("$schema", "title", "properties", "$ref", "$defs", "type")
        )

    def test_schema_contains_path_and_rule_id_fields(self):
        from automated_security_helper.cli.mcp_server import (
            _read_ash_suppression_schema,
        )

        content = _read_ash_suppression_schema()
        parsed = json.loads(content)
        # Resolve top-level $ref if present
        props = parsed.get("properties", {})
        if not props and "$ref" in parsed:
            ref = parsed["$ref"]
            if ref.startswith("#/$defs/"):
                def_name = ref.split("/")[-1]
                props = parsed.get("$defs", {}).get(def_name, {}).get("properties", {})
        assert "path" in props
        assert "rule_id" in props
