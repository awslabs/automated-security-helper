# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for FlatVulnerability.from_sarif_result, from_additional_report,
and the extracted helper functions.

These tests pin down the behavior of the factory classmethods that replace
the inline SARIF-to-FlatVulnerability conversion in
AshAggregatedResults.to_flat_vulnerabilities().
"""

import json

from automated_security_helper.models.flat_vulnerability import (
    FlatVulnerability,
    _extract_location_info,
    _extract_scanner_name_from_result,
    _resolve_severity,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Suppression,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactContent,
)


def _make_result(
    rule_id: str = "RULE001",
    level: str = "error",
    text: str = "finding text",
    file_uri: str | None = "src/app.py",
    start_line: int | None = 10,
    end_line: int | None = 15,
    snippet: str | None = None,
    tags: list[str] | None = None,
    issue_severity: str | None = None,
    scanner_name: str | None = None,
    suppressions: list[Suppression] | None = None,
) -> Result:
    """Helper to build a SARIF Result with configurable fields."""
    locations: list[Location] = []
    if file_uri is not None:
        region = None
        if start_line is not None:
            region_kwargs: dict = {"startLine": start_line}
            if end_line is not None:
                region_kwargs["endLine"] = end_line
            if snippet is not None:
                region_kwargs["snippet"] = ArtifactContent(text=snippet)
            region = Region(**region_kwargs)
        locations.append(
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri=file_uri),
                        region=region,
                    )
                )
            )
        )

    props_data: dict = {}
    if tags is not None:
        props_data["tags"] = tags
    if issue_severity is not None:
        props_data["issue_severity"] = issue_severity
    if scanner_name is not None:
        props_data["scanner_name"] = scanner_name
    properties = PropertyBag(**props_data) if props_data else None

    kwargs: dict = {
        "ruleId": rule_id,
        "level": level,
        "message": Message(root=Message1(text=text)),
    }
    if locations:
        kwargs["locations"] = locations
    if properties is not None:
        kwargs["properties"] = properties
    if suppressions is not None:
        kwargs["suppressions"] = suppressions

    return Result(**kwargs)


class TestFromSarifResultLocation:
    """Location extraction in FlatVulnerability.from_sarif_result()."""

    def test_extracts_file_path_from_artifact_location(self):
        result = _make_result(file_uri="src/app.py", start_line=10, end_line=15)
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.file_path == "src/app.py"

    def test_extracts_line_start_and_end_from_region(self):
        result = _make_result(file_uri="src/app.py", start_line=10, end_line=15)
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.line_start == 10
        assert vuln.line_end == 15

    def test_handles_missing_location_gracefully(self):
        result = _make_result(file_uri=None)
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.file_path is None
        assert vuln.line_start is None
        assert vuln.line_end is None

    def test_strips_file_scheme_prefix(self):
        result = _make_result(file_uri="file:///absolute/path/app.py")
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.file_path is not None
        assert not vuln.file_path.startswith("file://")

    def test_extracts_code_snippet_from_region_snippet(self):
        result = _make_result(
            file_uri="src/app.py",
            start_line=1,
            end_line=2,
            snippet="x = 1",
        )
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.code_snippet == "x = 1"


class TestFromSarifResultSeverity:
    """Severity resolution for FlatVulnerability.from_sarif_result()."""

    def test_issue_severity_property_takes_priority(self):
        result = _make_result(level="warning", issue_severity="HIGH")
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.severity == "HIGH"

    def test_issue_severity_critical_wins_over_level_warning(self):
        result = _make_result(level="warning", issue_severity="CRITICAL")
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.severity == "CRITICAL"

    def test_level_error_maps_without_issue_severity(self):
        # Preserves original to_flat_vulnerabilities() behavior: error -> HIGH
        # (see test_ash_aggregated_results_to_flat_vulnerabilities_with_sarif)
        result = _make_result(level="error")
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.severity == "HIGH"

    def test_level_warning_maps_to_medium(self):
        result = _make_result(level="warning")
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.severity == "MEDIUM"

    def test_level_note_maps_to_low(self):
        result = _make_result(level="note")
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.severity == "LOW"


class TestFromSarifResultIdentity:
    """rule_id, title, and description extraction."""

    def test_extracts_rule_id(self):
        result = _make_result(rule_id="B101")
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.rule_id == "B101"

    def test_title_comes_from_rule_id(self):
        result = _make_result(rule_id="B101", text="whatever")
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.title == "B101"

    def test_description_from_message_text(self):
        result = _make_result(text="assert used in production code")
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.description == "assert used in production code"


class TestFromSarifResultSuppression:
    """Suppression detection."""

    def test_non_empty_suppressions_sets_is_suppressed_true(self):
        supp = Suppression(kind="external", justification="known FP")
        result = _make_result(suppressions=[supp])
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.is_suppressed is True
        assert vuln.suppression_kind == "external"
        assert vuln.suppression_justification == "known FP"

    def test_no_suppressions_sets_is_suppressed_false(self):
        result = _make_result()
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.is_suppressed is False
        assert vuln.suppression_kind is None
        assert vuln.suppression_justification is None


class TestFromSarifResultScannerName:
    """Scanner name extraction precedence."""

    def test_prefers_properties_scanner_name_over_tool_name(self):
        result = _make_result(scanner_name="bandit-real")
        vuln = FlatVulnerability.from_sarif_result(
            result, "Unknown Tool", "SAST"
        )
        assert vuln.scanner == "bandit-real"

    def test_falls_back_to_tool_name_when_no_scanner_property(self):
        result = _make_result()
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.scanner == "bandit"

    def test_recovers_scanner_from_tags_when_tool_is_generic(self):
        # When driver name is the generic ASH label, scanner name may live in tags
        result = _make_result(tags=["semgrep", "security"])
        vuln = FlatVulnerability.from_sarif_result(
            result, "AWS Labs - Automated Security Helper", "SAST"
        )
        assert vuln.scanner == "semgrep"


class TestFromSarifResultTags:
    """Tag extraction."""

    def test_tags_are_json_encoded(self):
        result = _make_result(tags=["security", "cwe-798"])
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.tags is not None
        assert json.loads(vuln.tags) == ["security", "cwe-798"]

    def test_no_tags_leaves_field_none(self):
        result = _make_result()
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.tags is None


class TestFromSarifResultScannerType:
    """Scanner type is passed through."""

    def test_scanner_type_set_from_arg(self):
        result = _make_result()
        vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")
        assert vuln.scanner_type == "SAST"

    def test_scanner_type_accepts_other_values(self):
        result = _make_result()
        vuln = FlatVulnerability.from_sarif_result(result, "grype", "SCA")
        assert vuln.scanner_type == "SCA"


class TestFromAdditionalReport:
    """FlatVulnerability.from_additional_report()."""

    def test_builds_from_simple_dict(self):
        entry = {
            "id": "ABC123",
            "title": "Hardcoded password",
            "description": "A password string literal was found.",
            "severity": "high",
            "rule_id": "SEC-001",
            "file_path": "conf.py",
            "line_start": 5,
            "line_end": 5,
        }
        vuln = FlatVulnerability.from_additional_report(entry, "trivy")
        assert vuln.scanner == "trivy"
        assert vuln.title == "Hardcoded password"
        assert vuln.rule_id == "SEC-001"
        assert vuln.file_path == "conf.py"

    def test_severity_is_uppercased(self):
        entry = {"id": "X", "severity": "medium"}
        vuln = FlatVulnerability.from_additional_report(entry, "trivy")
        assert vuln.severity == "MEDIUM"

    def test_missing_severity_defaults_to_medium(self):
        entry = {"id": "X"}
        vuln = FlatVulnerability.from_additional_report(entry, "trivy")
        assert vuln.severity == "MEDIUM"

    def test_id_is_prefixed_with_scanner(self):
        entry = {"id": "V42"}
        vuln = FlatVulnerability.from_additional_report(entry, "trivy")
        assert vuln.id.startswith("trivy-")

    def test_optional_cve_cwe_fix_available(self):
        entry = {
            "id": "X",
            "cve_id": "CVE-2020-1234",
            "cwe_id": "CWE-79",
            "fix_available": True,
        }
        vuln = FlatVulnerability.from_additional_report(entry, "trivy")
        assert vuln.cve_id == "CVE-2020-1234"
        assert vuln.cwe_id == "CWE-79"
        assert vuln.fix_available is True


class TestExtractScannerNameHelper:
    """_extract_scanner_name_from_result() helper."""

    def test_prefers_properties_scanner_name(self):
        result = _make_result(scanner_name="semgrep")
        name = _extract_scanner_name_from_result(
            result, "fallback-tool", tags=None
        )
        assert name == "semgrep"

    def test_falls_back_to_run_tool_name(self):
        result = _make_result()
        name = _extract_scanner_name_from_result(
            result, "fallback-tool", tags=None
        )
        assert name == "fallback-tool"

    def test_handles_none_tags(self):
        result = _make_result()
        # Should not raise even when tags list is None
        name = _extract_scanner_name_from_result(result, "bandit", None)
        assert name == "bandit"


class TestExtractLocationInfoHelper:
    """_extract_location_info() helper returns (file_path, line_start, line_end, snippet)."""

    def test_returns_tuple_with_all_fields(self):
        result = _make_result(
            file_uri="src/x.py",
            start_line=3,
            end_line=4,
            snippet="print(1)",
        )
        info = _extract_location_info(result)
        # Implementation may return a 4-tuple (file, start, end, snippet) or a NamedTuple.
        assert info[0] == "src/x.py"
        assert info[1] == 3
        assert info[2] == 4

    def test_none_for_missing_location(self):
        result = _make_result(file_uri=None)
        info = _extract_location_info(result)
        assert info[0] is None
        assert info[1] is None
        assert info[2] is None


class TestResolveSeverityHelper:
    """_resolve_severity() helper."""

    def test_issue_severity_property_wins(self):
        result = _make_result(level="warning", issue_severity="HIGH")
        assert _resolve_severity(result) == "HIGH"

    def test_error_level_maps_to_high(self):
        result = _make_result(level="error")
        assert _resolve_severity(result) == "HIGH"

    def test_warning_level_maps_to_medium(self):
        result = _make_result(level="warning")
        assert _resolve_severity(result) == "MEDIUM"

    def test_note_level_maps_to_low(self):
        result = _make_result(level="note")
        assert _resolve_severity(result) == "LOW"


class TestLocationDisplayProperty:
    """FlatVulnerability.location_display property."""

    def test_returns_file_with_lines(self):
        vuln = FlatVulnerability(
            id="x",
            title="t",
            description="d",
            severity="HIGH",
            scanner="bandit",
            scanner_type="SAST",
            file_path="src/app.py",
            line_start=10,
            line_end=15,
        )
        assert vuln.location_display == "src/app.py:10-15"

    def test_returns_na_when_no_file_path(self):
        vuln = FlatVulnerability(
            id="x",
            title="t",
            description="d",
            severity="HIGH",
            scanner="bandit",
            scanner_type="SAST",
        )
        assert vuln.location_display == "N/A"


class TestIsActionableMethod:
    """FlatVulnerability.is_actionable(threshold)."""

    def _vuln(self, severity: str, suppressed: bool = False) -> FlatVulnerability:
        return FlatVulnerability(
            id="x",
            title="t",
            description="d",
            severity=severity,
            scanner="bandit",
            scanner_type="SAST",
            is_suppressed=suppressed,
        )

    def test_suppressed_never_actionable(self):
        v = self._vuln("CRITICAL", suppressed=True)
        assert v.is_actionable("CRITICAL") is False

    def test_critical_actionable_at_critical_threshold(self):
        v = self._vuln("CRITICAL")
        assert v.is_actionable("CRITICAL") is True

    def test_high_not_actionable_at_critical_threshold(self):
        v = self._vuln("HIGH")
        assert v.is_actionable("CRITICAL") is False

    def test_high_actionable_at_high_threshold(self):
        v = self._vuln("HIGH")
        assert v.is_actionable("HIGH") is True

    def test_case_insensitive_threshold(self):
        v = self._vuln("HIGH")
        assert v.is_actionable("high") is True
