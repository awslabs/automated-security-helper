# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for mcp_explain_finding."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp_tools import mcp_explain_finding
from automated_security_helper.models.flat_vulnerability import FlatVulnerability


def _make_vuln(**kwargs) -> FlatVulnerability:
    defaults = dict(
        id="bandit-B601-deadbeef",
        title="B601",
        description="SQL injection risk",
        severity="HIGH",
        scanner="bandit",
        scanner_type="SAST",
        rule_id="B601",
    )
    defaults.update(kwargs)
    return FlatVulnerability(**defaults)


def _patch_flat_list(vulns):
    """Patch mcp_explain_finding's internal flat-list loader with a fixed list."""
    return patch(
        "automated_security_helper.cli.mcp_tools._load_flat_vulns_for_explain",
        return_value=vulns,
    )


class TestKnownFindingReturnsExpectedFields:
    def test_all_keys_present(self, tmp_path):
        vuln = _make_vuln(
            cwe_id="CWE-89",
            cve_id=None,
            references=json.dumps(["https://example.com/ref1"]),
            raw_data=json.dumps({"ruleId": "B601", "level": "error"}),
        )
        with _patch_flat_list([vuln]):
            result = mcp_explain_finding(
                finding_id="bandit-B601-deadbeef",
                results_path=str(tmp_path),
            )

        assert result["success"] is True
        data = result["finding"]
        assert data["title"] == "B601"
        assert data["description"] == "SQL injection risk"
        assert data["severity"] == "HIGH"
        assert data["cwe_id"] == "CWE-89"
        assert data["cve_id"] is None
        assert data["scanner"] == "bandit"
        assert isinstance(data["scanner_metadata"], dict)
        assert "severity_rationale" in data
        assert isinstance(data["references"], list)

    def test_scanner_metadata_from_raw_data(self, tmp_path):
        raw = {"ruleId": "B601", "level": "error", "extra": "value"}
        vuln = _make_vuln(raw_data=json.dumps(raw))
        with _patch_flat_list([vuln]):
            result = mcp_explain_finding(
                finding_id="bandit-B601-deadbeef",
                results_path=str(tmp_path),
            )
        assert result["finding"]["scanner_metadata"] == raw


class TestMissingFindingReturnsError:
    def test_unknown_id_returns_error(self, tmp_path):
        vuln = _make_vuln()
        with _patch_flat_list([vuln]):
            result = mcp_explain_finding(
                finding_id="does-not-exist",
                results_path=str(tmp_path),
            )
        assert result.get("success") is False
        assert "does-not-exist" in result.get("error", "")

    def test_empty_list_returns_error(self, tmp_path):
        with _patch_flat_list([]):
            result = mcp_explain_finding(
                finding_id="any-id",
                results_path=str(tmp_path),
            )
        assert result.get("success") is False


class TestSeverityRationale:
    @pytest.mark.parametrize(
        "severity,expected_fragment",
        [
            ("CRITICAL", "above any threshold"),
            ("HIGH", "above MEDIUM threshold"),
            ("MEDIUM", "above LOW threshold"),
            ("LOW", "below MEDIUM threshold"),
            ("INFO", "below default threshold"),
        ],
    )
    def test_rationale_text(self, tmp_path, severity, expected_fragment):
        vuln = _make_vuln(severity=severity)
        with _patch_flat_list([vuln]):
            result = mcp_explain_finding(
                finding_id="bandit-B601-deadbeef",
                results_path=str(tmp_path),
            )
        rationale = result["finding"]["severity_rationale"]
        assert expected_fragment in rationale, (
            f"Expected '{expected_fragment}' in rationale '{rationale}'"
        )


class TestReferencesListParsed:
    def test_references_json_string_decoded_to_list(self, tmp_path):
        refs = ["https://example.com/1", "https://example.com/2"]
        vuln = _make_vuln(references=json.dumps(refs))
        with _patch_flat_list([vuln]):
            result = mcp_explain_finding(
                finding_id="bandit-B601-deadbeef",
                results_path=str(tmp_path),
            )
        assert result["finding"]["references"] == refs

    def test_none_references_returns_empty_list(self, tmp_path):
        vuln = _make_vuln(references=None)
        with _patch_flat_list([vuln]):
            result = mcp_explain_finding(
                finding_id="bandit-B601-deadbeef",
                results_path=str(tmp_path),
            )
        assert result["finding"]["references"] == []

    def test_multiple_references_all_returned(self, tmp_path):
        refs = ["https://a.com", "https://b.com", "https://c.com"]
        vuln = _make_vuln(references=json.dumps(refs))
        with _patch_flat_list([vuln]):
            result = mcp_explain_finding(
                finding_id="bandit-B601-deadbeef",
                results_path=str(tmp_path),
            )
        assert len(result["finding"]["references"]) == 3


class TestCweAndCvePulledWhenPresent:
    def test_cwe_id_returned(self, tmp_path):
        vuln = _make_vuln(cwe_id="CWE-79")
        with _patch_flat_list([vuln]):
            result = mcp_explain_finding(
                finding_id="bandit-B601-deadbeef",
                results_path=str(tmp_path),
            )
        assert result["finding"]["cwe_id"] == "CWE-79"

    def test_cve_id_returned(self, tmp_path):
        vuln = _make_vuln(cve_id="CVE-2024-1234")
        with _patch_flat_list([vuln]):
            result = mcp_explain_finding(
                finding_id="bandit-B601-deadbeef",
                results_path=str(tmp_path),
            )
        assert result["finding"]["cve_id"] == "CVE-2024-1234"

    def test_both_none_when_not_present(self, tmp_path):
        vuln = _make_vuln(cwe_id=None, cve_id=None)
        with _patch_flat_list([vuln]):
            result = mcp_explain_finding(
                finding_id="bandit-B601-deadbeef",
                results_path=str(tmp_path),
            )
        assert result["finding"]["cwe_id"] is None
        assert result["finding"]["cve_id"] is None
