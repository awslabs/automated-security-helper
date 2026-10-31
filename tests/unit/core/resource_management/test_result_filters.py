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

pytestmark = pytest.mark.unit


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
            # What scan_tracking.get_scan_results puts beside the SARIF. ALL, so
            # that every unsuppressed result here is actionable whatever its level.
            "severity_thresholds": {"": "ALL"},
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
        assert (
            result["summary_stats"]["total"]
            == full_results["summary_stats"]["actionable"]
        )

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


def _judged(thresholds: dict) -> dict:
    """bandit HIGH, MEDIUM and LOW findings and a semgrep LOW, judged by *thresholds*."""

    def result(rule: str, scanner: str, severity: str) -> dict:
        return {
            "ruleId": rule,
            "level": "note",
            "properties": {"scanner_name": scanner, "issue_severity": severity},
        }

    return {
        "raw_results": {
            "sarif": {
                "runs": [
                    {
                        "results": [
                            result("B-HIGH", "bandit", "HIGH"),
                            result("B-MEDIUM", "bandit", "MEDIUM"),
                            result("B-LOW", "bandit", "LOW"),
                            result("S-LOW", "semgrep", "LOW"),
                        ]
                    }
                ]
            },
            "severity_thresholds": thresholds,
        }
    }


class TestFilterActionableOnlyJudgesByTheThreshold:
    """Actionable is unsuppressed AND at or above the threshold, as for exit 2.

    The MCP tool's own tests (tests/unit/cli/mcp/test_actionable_only_matches_the_exit_code.py)
    compare this with ``_compute_exit_code``; these pin the filter's reading of
    the thresholds map.
    """

    def test_below_the_threshold_is_dropped_and_at_it_is_kept(self):
        result = filter_actionable_only(_judged({"": "MEDIUM"}))
        assert _rule_ids(result) == ["B-HIGH", "B-MEDIUM"]

    def test_a_scanners_own_threshold_decides_its_results(self):
        result = filter_actionable_only(
            _judged({"": "MEDIUM", "bandit": "HIGH", "semgrep": "LOW"})
        )
        assert _rule_ids(result) == ["B-HIGH", "S-LOW"]

    def test_a_scanner_missing_from_the_map_is_judged_by_the_global(self):
        result = filter_actionable_only(_judged({"": "LOW", "bandit": "HIGH"}))
        assert _rule_ids(result) == ["B-HIGH", "S-LOW"]

    def test_sarif_without_its_thresholds_is_refused(self):
        """Keeping everything or nothing would each read as an answer."""
        results = _judged({})
        del results["raw_results"]["severity_thresholds"]

        with pytest.raises(ValueError, match="severity_thresholds"):
            filter_actionable_only(results)

    def test_results_without_sarif_need_no_thresholds(self, full_results):
        """summary and minimal never load the SARIF; only the counts change."""
        del full_results["raw_results"]["sarif"]
        del full_results["raw_results"]["severity_thresholds"]

        result = filter_actionable_only(full_results)

        assert result["summary_stats"]["suppressed"] == 0


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

    def test_severity_filter_preserves_the_scanner_outcome_stats(self, full_results):
        """The outcome counters are not per severity, so a severity filter
        leaves them; the total follows the selected buckets (see
        test_result_filters_summary_recount.py), which this used to pin the
        other way."""
        result = apply_content_filters(full_results, severities="critical")
        for counter in ("passed", "failed", "missing", "skipped"):
            assert (
                result["summary_stats"][counter]
                == full_results["summary_stats"][counter]
            )
        assert result["summary_stats"]["total"] == 1

    def test_combined_scanner_and_severity_filter(self, full_results):
        result = apply_content_filters(
            full_results, scanners="bandit", severities="high"
        )
        scanner_data = result["raw_results"]["scanner_results"]["bandit"]
        assert "high" in scanner_data["severity_counts"]
        assert "medium" not in scanner_data["severity_counts"]

    def test_no_filters_returns_equivalent_data(self, full_results):
        result = apply_content_filters(full_results)
        assert (
            result["raw_results"]["scanner_results"]
            == full_results["raw_results"]["scanner_results"]
        )

    def test_does_not_modify_original(self, full_results):
        original = copy.deepcopy(full_results)
        apply_content_filters(full_results, scanners="bandit", severities="high")
        assert full_results == original

    def test_sets_filter_metadata(self, full_results):
        result = apply_content_filters(
            full_results, scanners="bandit", severities="high"
        )
        assert result["_content_filters"]["scanners"] == ["bandit"]
        assert result["_content_filters"]["severities"] == ["high"]

    def test_case_insensitive_scanner_matching(self, full_results):
        result = apply_content_filters(full_results, scanners="BANDIT")
        assert "bandit" in result["raw_results"]["scanner_results"]

    def test_case_insensitive_severity_matching(self, full_results):
        result = apply_content_filters(full_results, severities="CRITICAL,HIGH")
        assert result["summary_stats"]["critical"] == 1
        assert result["summary_stats"]["medium"] == 0


# ---------------------------------------------------------------------------
# The shape a real scan produces
# ---------------------------------------------------------------------------
#
# Every fixture above hands the filters a FLAT summary_stats ({"critical": 1,
# ...}). A real scan never produces that: SummaryStats nests its per-severity
# tallies under "severity_counts", so filter_summary -- which backs the MCP
# get_scan_summary tool -- read zero for every severity on every real scan, and
# the flat fixture is exactly why no test noticed. These build the results dict
# the way get_scan_results does, from a serialized AshAggregatedResults.


def _real_scan_results(tmp_path):
    from automated_security_helper.core.resource_management.scan_tracking import (
        get_scan_results,
    )
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        SummaryStats,
    )

    model = AshAggregatedResults()
    model.metadata.summary_stats = SummaryStats(
        critical=2, high=3, medium=5, low=7, info=11, suppressed=13, actionable=10
    )
    (tmp_path / "ash_aggregated_results.json").write_text(
        model.model_dump_json(by_alias=True), encoding="utf-8"
    )
    results = get_scan_results(output_dir=tmp_path)
    # The premise: the counts really are nested in what the filters receive.
    assert "severity_counts" in results["summary_stats"]
    assert "critical" not in results["summary_stats"]
    return results


class TestFiltersReadTheSerializedSummaryStats:
    def test_filter_summary_reports_the_real_severity_counts(self, tmp_path):
        by_sev = filter_summary(_real_scan_results(tmp_path))["findings_summary"][
            "by_severity"
        ]
        assert by_sev["critical"] == 2
        assert by_sev["high"] == 3
        assert by_sev["medium"] == 5
        assert by_sev["low"] == 7
        assert by_sev["info"] == 11
        assert by_sev["suppressed"] == 13
        assert by_sev["actionable"] == 10

    def test_actionable_only_zeros_the_nested_suppressed_count(self, tmp_path):
        result = filter_actionable_only(_real_scan_results(tmp_path))
        assert result["summary_stats"]["severity_counts"]["suppressed"] == 0
        assert (
            filter_summary(result)["findings_summary"]["by_severity"]["suppressed"] == 0
        )

    def test_severity_filter_zeros_the_nested_unselected_counts(self, tmp_path):
        result = apply_content_filters(
            _real_scan_results(tmp_path), severities="critical,high"
        )
        counts = result["summary_stats"]["severity_counts"]
        assert counts["critical"] == 2
        assert counts["high"] == 3
        assert counts["medium"] == 0
        assert counts["low"] == 0
        assert counts["info"] == 0


def _sarif_results() -> dict:
    """Two HIGH bandit findings in the SARIF, one of them suppressed."""

    def result(rule: str, suppressed: bool) -> dict:
        entry = {
            "ruleId": rule,
            "level": "error",
            "properties": {"scanner_name": "bandit", "issue_severity": "HIGH"},
        }
        if suppressed:
            entry["suppressions"] = [{"kind": "external", "justification": "test"}]
        return entry

    return {
        "raw_results": {
            "sarif": {
                "runs": [{"results": [result("B602", False), result("B101", True)]}]
            }
        }
    }


def _rule_ids(filtered: dict) -> list:
    runs = filtered["raw_results"]["sarif"]["runs"]
    return sorted(r["ruleId"] for run in runs for r in run["results"])


class TestTheSeverityFilterPutsSuppressedFindingsInTheirOwnBucket:
    """A suppressed finding is counted under ``suppressed``, not under its severity.

    The SARIF filter follows the counts: ``severities="high"`` leaves out a
    suppressed HIGH finding and ``severities="suppressed"`` keeps it. Removing
    that rule from _sarif_result_selected passed every other test.
    """

    def test_a_severity_leaves_out_its_suppressed_findings(self):
        filtered = apply_content_filters(_sarif_results(), severities="high")
        assert _rule_ids(filtered) == ["B602"]

    def test_suppressed_selects_the_suppressed_findings(self):
        filtered = apply_content_filters(_sarif_results(), severities="suppressed")
        assert _rule_ids(filtered) == ["B101"]

    def test_both_select_both(self):
        filtered = apply_content_filters(_sarif_results(), severities="high,suppressed")
        assert _rule_ids(filtered) == ["B101", "B602"]
