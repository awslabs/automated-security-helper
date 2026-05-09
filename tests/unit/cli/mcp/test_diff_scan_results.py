# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for mcp_diff_scan_results."""

import json
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp_tools import mcp_diff_scan_results
from automated_security_helper.models.flat_vulnerability import FlatVulnerability


_SCANNER = "fixture"


def _make_vuln(
    short_id: str,
    severity: str = "HIGH",
    description: str = "desc",
) -> FlatVulnerability:
    """Build a FlatVulnerability whose loaded id will be ``fixture-<short_id>``."""
    return FlatVulnerability(
        id=f"{_SCANNER}-{short_id}",
        title="Test finding",
        description=description,
        severity=severity,
        scanner=_SCANNER,
        scanner_type="SAST",
    )


def _loaded_id(short_id: str) -> str:
    """Return the id as it will appear after round-tripping through from_additional_report."""
    return f"{_SCANNER}-{_SCANNER}-{short_id}"


def _make_aggregated_json(vulns: list[FlatVulnerability]) -> dict:
    """Build a minimal ash_aggregated_results.json-compatible dict.

    Uses additional_reports so we can inject arbitrary FlatVulnerability-shaped
    dicts without needing a full SARIF structure.
    from_additional_report prepends scanner_name to the entry id, so each
    entry's ``id`` field is stored as-is (the full vuln.id) and the loaded id
    becomes ``{scanner}-{vuln.id}``.
    """
    findings = [
        {
            "id": v.id,
            "title": v.title,
            "description": v.description,
            "severity": v.severity,
            "type": v.scanner_type,
            "rule_id": v.rule_id,
            "file_path": v.file_path,
        }
        for v in vulns
    ]
    return {
        "metadata": {
            "scan_id": "test-scan",
            "scan_timestamp": "2026-01-01T00:00:00+00:00",
            "summary_stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "suppressed": 0},
        },
        "sarif": {"version": "2.1.0", "runs": []},
        "additional_reports": {_SCANNER: findings} if vulns else {},
        "scanner_results": {},
    }


def _write_results(path: Path, vulns: list[FlatVulnerability]) -> None:
    path.write_text(json.dumps(_make_aggregated_json(vulns)))


class TestDiffScanResultsIdentical:
    def test_identical_inputs_return_empty_diff(self, tmp_path):
        vuln = _make_vuln("B101-abc12345", "HIGH")
        f = tmp_path / "results.json"
        _write_results(f, [vuln])

        result = mcp_diff_scan_results(str(f), str(f))

        assert result["new"] == []
        assert result["resolved"] == []
        assert result["severity_changed"] == []


class TestDiffScanResultsNew:
    def test_new_finding_in_after(self, tmp_path):
        before_vuln = _make_vuln("B101-aaa00001", "HIGH")
        after_vuln_existing = _make_vuln("B101-aaa00001", "HIGH")
        after_vuln_new = _make_vuln("B102-bbb00002", "MEDIUM")

        before_f = tmp_path / "before.json"
        after_f = tmp_path / "after.json"
        _write_results(before_f, [before_vuln])
        _write_results(after_f, [after_vuln_existing, after_vuln_new])

        result = mcp_diff_scan_results(str(before_f), str(after_f))

        new_ids = [v["id"] for v in result["new"]]
        assert _loaded_id("B102-bbb00002") in new_ids
        assert result["resolved"] == []
        assert result["severity_changed"] == []


class TestDiffScanResultsResolved:
    def test_resolved_finding_absent_in_after(self, tmp_path):
        vuln_a = _make_vuln("B101-aaa00001", "HIGH")
        vuln_b = _make_vuln("B201-ccc00003", "CRITICAL")

        before_f = tmp_path / "before.json"
        after_f = tmp_path / "after.json"
        _write_results(before_f, [vuln_a, vuln_b])
        _write_results(after_f, [vuln_a])

        result = mcp_diff_scan_results(str(before_f), str(after_f))

        resolved_ids = [v["id"] for v in result["resolved"]]
        assert _loaded_id("B201-ccc00003") in resolved_ids
        assert result["new"] == []
        assert result["severity_changed"] == []


class TestDiffScanResultsSeverityChanged:
    def test_severity_change_detected(self, tmp_path):
        before_vuln = _make_vuln("B101-aaa00001", severity="HIGH")
        after_vuln = _make_vuln("B101-aaa00001", severity="CRITICAL")

        before_f = tmp_path / "before.json"
        after_f = tmp_path / "after.json"
        _write_results(before_f, [before_vuln])
        _write_results(after_f, [after_vuln])

        result = mcp_diff_scan_results(str(before_f), str(after_f))

        assert result["new"] == []
        assert result["resolved"] == []
        assert len(result["severity_changed"]) == 1
        change = result["severity_changed"][0]
        assert change["id"] == _loaded_id("B101-aaa00001")
        assert change["before_severity"] == "HIGH"
        assert change["after_severity"] == "CRITICAL"

    def test_same_severity_not_in_severity_changed(self, tmp_path):
        before_vuln = _make_vuln("B101-aaa00001", severity="HIGH")
        after_vuln = _make_vuln("B101-aaa00001", severity="HIGH")

        before_f = tmp_path / "before.json"
        after_f = tmp_path / "after.json"
        _write_results(before_f, [before_vuln])
        _write_results(after_f, [after_vuln])

        result = mcp_diff_scan_results(str(before_f), str(after_f))

        assert result["severity_changed"] == []


class TestDiffScanResultsMissingFile:
    def test_missing_before_file_returns_error(self, tmp_path):
        after_f = tmp_path / "after.json"
        _write_results(after_f, [])

        result = mcp_diff_scan_results(str(tmp_path / "nonexistent.json"), str(after_f))

        assert result.get("success") is False
        assert "error" in result

    def test_missing_after_file_returns_error(self, tmp_path):
        before_f = tmp_path / "before.json"
        _write_results(before_f, [])

        result = mcp_diff_scan_results(str(before_f), str(tmp_path / "nonexistent.json"))

        assert result.get("success") is False
        assert "error" in result
