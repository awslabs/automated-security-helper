# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for core/resource_management/result_filters.py."""

import copy
import pytest

from automated_security_helper.core.resource_management.result_filters import (
    apply_content_filters,
    filter_actionable_only,
    filter_minimal,
    filter_summary,
)


@pytest.fixture
def full_results():
    return {
        "success": True,
        "scan_id": "abc-123",
        "status": "completed",
        "is_complete": True,
        "completion_time": "2024-01-01T00:00:00Z",
        "summary_stats": {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "info": 5,
            "suppressed": 2,
            "total": 17,
            "actionable": 15,
            "passed": 3,
            "failed": 1,
            "missing": 0,
            "skipped": 0,
        },
        "raw_results": {
            "metadata": {
                "generated_at": "2024-01-01T00:00:00Z",
                "tool_version": "2.0.0",
                "summary_stats": {"duration": 42.5},
            },
            "scanner_results": {
                "bandit": {
                    "status": "PASSED",
                    "finding_count": 5,
                    "actionable_finding_count": 4,
                    "suppressed_finding_count": 1,
                    "duration": 2.1,
                    "severity_counts": {
                        "critical": 0,
                        "high": 1,
                        "medium": 2,
                        "low": 1,
                        "info": 1,
                        "suppressed": 1,
                    },
                },
                "semgrep": {
                    "status": "FAILED",
                    "finding_count": 3,
                    "actionable_finding_count": 3,
                    "suppressed_finding_count": 0,
                    "duration": 5.3,
                    "severity_counts": {
                        "critical": 1,
                        "high": 1,
                        "medium": 1,
                        "low": 0,
                        "info": 0,
                        "suppressed": 0,
                    },
                },
            },
            "additional_reports": {
                "bandit": {"report": "data"},
                "semgrep": {"report": "data"},
            },
            "sarif": {
                "runs": [
                    {
                        "results": [
                            {"ruleId": "B001", "suppressions": []},
                            {"ruleId": "B002", "suppressions": [{"kind": "inSource"}]},
                            {"ruleId": "S001"},
                        ]
                    }
                ]
            },
        },
        "scanner_reports": {
            "bandit": {"report": "bandit-data"},
            "semgrep": {"report": "semgrep-data"},
        },
    }


class TestFilterSummary:
    def test_extracts_metadata(self, full_results):
        result = filter_summary(full_results)
        assert result["metadata"]["ash_version"] == "2.0.0"
        assert result["metadata"]["scan_duration_seconds"] == 42.5
        assert result["metadata"]["generated_at"] == "2024-01-01T00:00:00Z"

    def test_extracts_findings_by_severity(self, full_results):
        result = filter_summary(full_results)
        by_sev = result["findings_summary"]["by_severity"]
        assert by_sev["critical"] == 1
        assert by_sev["high"] == 2
        assert by_sev["suppressed"] == 2
        assert by_sev["total"] == 17
        assert by_sev["actionable"] == 15

    def test_counts_completed_scanners(self, full_results):
        result = filter_summary(full_results)
        # bandit=PASSED, semgrep=FAILED — both count as completed
        assert result["scanner_summary"]["completed_scanners"] == 2
        assert result["scanner_summary"]["total_scanners"] == 2

    def test_scanner_severity_breakdown(self, full_results):
        result = filter_summary(full_results)
        bandit = result["scanner_summary"]["by_scanner"]["bandit"]
        assert bandit["status"] == "PASSED"
        assert bandit["findings_count"] == 5
        assert bandit["by_severity"]["high"] == 1

    def test_filter_tag(self, full_results):
        result = filter_summary(full_results)
        assert result["_filter"] == "summary"

    def test_no_raw_results_in_output(self, full_results):
        result = filter_summary(full_results)
        assert "raw_results" not in result

    def test_does_not_modify_original(self, full_results):
        original = copy.deepcopy(full_results)
        filter_summary(full_results)
        assert full_results == original


class TestFilterMinimal:
    def test_returns_status_fields(self, full_results):
        result = filter_minimal(full_results)
        assert result["success"] is True
        assert result["scan_id"] == "abc-123"
        assert result["status"] == "completed"
        assert result["is_complete"] is True
        assert result["completion_time"] == "2024-01-01T00:00:00Z"

    def test_includes_summary_stats(self, full_results):
        result = filter_minimal(full_results)
        assert result["summary_stats"]["total"] == 17

    def test_filter_tag(self, full_results):
        result = filter_minimal(full_results)
        assert result["_filter"] == "minimal"

    def test_no_raw_results(self, full_results):
        result = filter_minimal(full_results)
        assert "raw_results" not in result

    def test_does_not_modify_original(self, full_results):
        original = copy.deepcopy(full_results)
        filter_minimal(full_results)
        assert full_results == original


class TestFilterActionableOnly:
    def test_removes_suppressed_sarif_results(self, full_results):
        result = filter_actionable_only(full_results)
        runs = result["raw_results"]["sarif"]["runs"]
        for run in runs:
            for r in run["results"]:
                assert not (r.get("suppressions") and len(r["suppressions"]) > 0)

    def test_keeps_unsuppressed_results(self, full_results):
        result = filter_actionable_only(full_results)
        rule_ids = [
            r["ruleId"]
            for run in result["raw_results"]["sarif"]["runs"]
            for r in run["results"]
        ]
        assert "B001" in rule_ids
        assert "S001" in rule_ids
        assert "B002" not in rule_ids

    def test_zeros_suppressed_counts(self, full_results):
        result = filter_actionable_only(full_results)
        assert result["summary_stats"]["suppressed"] == 0

    def test_total_equals_actionable(self, full_results):
        result = filter_actionable_only(full_results)
        assert result["summary_stats"]["total"] == full_results["summary_stats"]["actionable"]

    def test_zeros_scanner_suppressed_counts(self, full_results):
        result = filter_actionable_only(full_results)
        bandit = result["raw_results"]["scanner_results"]["bandit"]
        assert bandit["suppressed_finding_count"] == 0
        assert bandit["severity_counts"]["suppressed"] == 0

    def test_does_not_modify_original(self, full_results):
        original = copy.deepcopy(full_results)
        filter_actionable_only(full_results)
        assert full_results == original

    def test_sets_content_filter_metadata(self, full_results):
        result = filter_actionable_only(full_results)
        assert result["_content_filters"]["actionable_only"] is True


class TestApplyContentFilters:
    def test_scanner_filter_keeps_only_specified(self, full_results):
        result = apply_content_filters(full_results, scanners="bandit")
        assert "bandit" in result["raw_results"]["scanner_results"]
        assert "semgrep" not in result["raw_results"]["scanner_results"]

    def test_scanner_filter_on_scanner_reports(self, full_results):
        result = apply_content_filters(full_results, scanners="semgrep")
        assert "semgrep" in result["scanner_reports"]
        assert "bandit" not in result["scanner_reports"]

    def test_scanner_filter_on_additional_reports(self, full_results):
        result = apply_content_filters(full_results, scanners="bandit")
        assert "bandit" in result["raw_results"]["additional_reports"]
        assert "semgrep" not in result["raw_results"]["additional_reports"]

    def test_severity_filter_zeros_excluded_levels(self, full_results):
        result = apply_content_filters(full_results, severities="critical,high")
        stats = result["summary_stats"]
        assert stats["critical"] == 1
        assert stats["high"] == 2
        assert stats["medium"] == 0
        assert stats["low"] == 0

    def test_severity_filter_preserves_non_severity_stats(self, full_results):
        result = apply_content_filters(full_results, severities="critical")
        assert result["summary_stats"]["total"] == full_results["summary_stats"]["total"]

    def test_combined_scanner_and_severity_filter(self, full_results):
        result = apply_content_filters(full_results, scanners="bandit", severities="high")
        scanner_data = result["raw_results"]["scanner_results"]["bandit"]
        assert "high" in scanner_data["severity_counts"]
        assert "medium" not in scanner_data["severity_counts"]

    def test_no_filters_returns_equivalent_data(self, full_results):
        result = apply_content_filters(full_results)
        assert result["raw_results"]["scanner_results"] == full_results["raw_results"]["scanner_results"]

    def test_does_not_modify_original(self, full_results):
        original = copy.deepcopy(full_results)
        apply_content_filters(full_results, scanners="bandit", severities="high")
        assert full_results == original

    def test_sets_filter_metadata(self, full_results):
        result = apply_content_filters(full_results, scanners="bandit", severities="high")
        assert result["_content_filters"]["scanners"] == ["bandit"]
        assert result["_content_filters"]["severities"] == ["high"]

    def test_case_insensitive_scanner_matching(self, full_results):
        result = apply_content_filters(full_results, scanners="BANDIT")
        assert "bandit" in result["raw_results"]["scanner_results"]

    def test_case_insensitive_severity_matching(self, full_results):
        result = apply_content_filters(full_results, severities="CRITICAL,HIGH")
        assert result["summary_stats"]["critical"] == 1
        assert result["summary_stats"]["medium"] == 0
