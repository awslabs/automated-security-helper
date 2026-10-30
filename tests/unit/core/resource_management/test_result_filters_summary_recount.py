# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The summary a filtered view reports describes the view, not the whole scan.

Four mechanisms, each pinned against the behavior it replaced:

* ``filter_summary`` defaulted every count to 0 when the results carried no
  ``summary_stats`` (the workspace unified results file has none), so such a
  scan read exactly like a clean one.
* ``filter_actionable_only`` on results whose SARIF was asked for and is null
  returned an empty findings list with no error, beside a nonzero
  ``summary_stats.actionable``.
* A ``scanners`` filter narrowed ``scanner_results`` and the SARIF findings but
  left ``summary_stats``, ``actionable_findings`` and ``total_scanners`` at
  whole-scan values, so the summary reported the other scanners' findings.
* A ``severities`` filter zeroed the unselected severity counts but left
  ``summary_stats.total`` and ``actionable`` at whole-scan values.
"""

import pytest

from automated_security_helper.core.resource_management.result_filters import (
    add_findings_list,
    apply_content_filters,
    filter_actionable_only,
    filter_summary,
)

pytestmark = pytest.mark.unit


def _scanner(status, counts, actionable, suppressed=0):
    return {
        "status": status,
        "finding_count": sum(counts.values()),
        "actionable_finding_count": actionable,
        "suppressed_finding_count": suppressed,
        "severity_counts": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": suppressed,
            **counts,
        },
    }


def _results(with_summary_stats=True):
    scanner_results = {
        "bandit": _scanner("PASSED", {"high": 1, "low": 2}, actionable=1),
        "semgrep": _scanner("FAILED", {"critical": 1, "medium": 1}, actionable=2),
        "grype": _scanner("MISSING", {}, actionable=0),
    }
    results = {
        "success": True,
        "scan_id": "abc",
        "status": "completed",
        "is_complete": True,
        "actionable_findings": 3,
        "total_scanners": 2,
        "raw_results": {
            "metadata": {"generated_at": "2024-01-01T00:00:00"},
            "scanner_results": scanner_results,
        },
    }
    if with_summary_stats:
        results["summary_stats"] = {
            "severity_counts": {
                "critical": 1,
                "high": 1,
                "medium": 1,
                "low": 2,
                "info": 0,
                "suppressed": 0,
            },
            "total": 5,
            "actionable": 3,
            "passed": 1,
            "failed": 1,
            "missing": 1,
            "skipped": 0,
            "error": 0,
        }
    return results


class TestFilterSummaryWithoutSummaryStats:
    def test_counts_are_derived_from_the_scanners(self):
        summary = filter_summary(_results(with_summary_stats=False))

        by_severity = summary["findings_summary"]["by_severity"]
        assert by_severity["critical"] == 1
        assert by_severity["high"] == 1
        assert by_severity["medium"] == 1
        assert by_severity["low"] == 2
        assert by_severity["total"] == 5
        assert by_severity["actionable"] == 3
        scan_stats = summary["findings_summary"]["scan_stats"]
        assert scan_stats == {
            "passed": 1,
            "failed": 1,
            "missing": 1,
            "skipped": 0,
            "error": 0,
        }

    def test_the_outcome_counters_include_error_and_sum_to_the_scanner_count(self):
        """SummaryStats has five outcome counters; scan_stats used to carry four, so
        the counters did not sum to the scanner count when scanners ERRORed."""
        results = _results()
        results["summary_stats"]["error"] = 2
        results["summary_stats"]["missing"] = 0

        scan_stats = filter_summary(results)["findings_summary"]["scan_stats"]

        assert scan_stats["error"] == 2
        assert sum(scan_stats.values()) == 4

        results = _results(with_summary_stats=False)
        results["raw_results"]["scanner_results"]["trivy"] = _scanner(
            "ERROR", {}, actionable=0
        )

        scan_stats = filter_summary(results)["findings_summary"]["scan_stats"]

        assert scan_stats["error"] == 1
        assert sum(scan_stats.values()) == 4

    def test_nothing_to_count_from_reads_as_unknown_not_zero(self):
        results = _results(with_summary_stats=False)
        results["raw_results"]["scanner_results"] = {}

        summary = filter_summary(results)

        by_severity = summary["findings_summary"]["by_severity"]
        assert by_severity["critical"] is None
        assert by_severity["total"] is None
        assert summary["findings_summary"]["scan_stats"]["passed"] is None

    def test_recorded_summary_stats_still_win(self):
        results = _results()
        results["summary_stats"]["total"] = 7

        assert filter_summary(results)["findings_summary"]["by_severity"]["total"] == 7


class TestAMissingActionableCountIsUnknownNotZero:
    """A scanner entry with no actionable_finding_count used to be counted as 0
    actionable, which read as "nothing actionable" beside known totals."""

    @staticmethod
    def _without_actionable_counts(with_summary_stats):
        results = _results(with_summary_stats=with_summary_stats)
        for data in results["raw_results"]["scanner_results"].values():
            del data["actionable_finding_count"]
        return results

    def test_the_derived_summary_reports_none(self):
        summary = filter_summary(self._without_actionable_counts(False))

        by_severity = summary["findings_summary"]["by_severity"]
        assert by_severity["actionable"] is None
        assert by_severity["total"] == 5
        assert summary["findings_summary"]["scan_stats"]["passed"] == 1

    def test_the_scanners_recount_reports_none_not_the_whole_scans_value(self):
        filtered = apply_content_filters(
            self._without_actionable_counts(True), scanners="bandit"
        )

        assert filtered["summary_stats"]["actionable"] is None
        assert filtered["actionable_findings"] is None
        assert filtered["summary_stats"]["total"] == 3

    def test_a_count_some_scanners_carry_is_summed_over_those(self):
        results = self._without_actionable_counts(False)
        results["raw_results"]["scanner_results"]["semgrep"][
            "actionable_finding_count"
        ] = 2

        by_severity = filter_summary(results)["findings_summary"]["by_severity"]

        assert by_severity["actionable"] == 2


class TestActionableOnlyRefusesAnUnlistableCount:
    def test_null_sarif_with_actionable_findings_is_refused(self):
        results = _results()
        results["raw_results"]["sarif"] = None

        with pytest.raises(ValueError, match="no SARIF"):
            filter_actionable_only(results)

    def test_null_sarif_with_nothing_actionable_passes(self):
        results = _results()
        results["raw_results"]["sarif"] = None
        results["summary_stats"]["actionable"] = 0

        filtered = filter_actionable_only(results)

        assert filtered["summary_stats"]["total"] == 0
        listed = add_findings_list(filtered)
        assert listed["findings"] == []
        assert listed["findings_count"] == 0

    def test_absent_sarif_is_the_summary_path_and_passes(self):
        """The summary and minimal levels never load the SARIF."""
        filtered = filter_actionable_only(_results())

        assert filtered["summary_stats"]["total"] == 3


class TestAScannersFilterRecountsTheSummary:
    def test_the_summary_follows_the_kept_scanners(self):
        filtered = apply_content_filters(_results(), scanners="bandit")

        stats = filtered["summary_stats"]
        assert stats["severity_counts"] == {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 2,
            "info": 0,
            "suppressed": 0,
        }
        assert stats["total"] == 3
        assert stats["actionable"] == 1
        assert stats["passed"] == 1
        assert stats["failed"] == 0
        assert stats["missing"] == 0
        assert filtered["actionable_findings"] == 1
        assert filtered["total_scanners"] == 1

    def test_the_summary_view_of_the_filtered_results_agrees(self):
        summary = filter_summary(apply_content_filters(_results(), scanners="semgrep"))

        by_severity = summary["findings_summary"]["by_severity"]
        assert by_severity["critical"] == 1
        assert by_severity["high"] == 0
        assert by_severity["total"] == 2
        assert by_severity["actionable"] == 2
        assert summary["scanner_summary"]["total_scanners"] == 1

    def test_flat_summary_stats_are_recounted_too(self):
        results = _results()
        results["summary_stats"] = {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 2,
            "total": 5,
            "actionable": 3,
        }

        stats = apply_content_filters(results, scanners="bandit")["summary_stats"]

        assert stats["critical"] == 0
        assert stats["high"] == 1
        assert stats["low"] == 2
        assert stats["total"] == 3
        assert stats["actionable"] == 1


class TestASeveritiesFilterRecountsTheTotal:
    def test_the_total_is_the_selected_buckets(self):
        filtered = apply_content_filters(_results(), severities="critical,high")

        stats = filtered["summary_stats"]
        assert stats["severity_counts"]["critical"] == 1
        assert stats["severity_counts"]["high"] == 1
        assert stats["severity_counts"]["low"] == 0
        assert stats["total"] == 2

    def test_actionable_is_recounted_from_the_sarif_when_present(self):
        def result(rule, severity, scanner="bandit"):
            return {
                "ruleId": rule,
                "level": "note",
                "properties": {"scanner_name": scanner, "issue_severity": severity},
            }

        results = _results()
        results["raw_results"]["sarif"] = {
            "runs": [
                {
                    "results": [
                        result("B-HIGH", "HIGH"),
                        result("B-LOW", "LOW"),
                        result("S-CRIT", "CRITICAL", "semgrep"),
                    ]
                }
            ]
        }
        results["raw_results"]["severity_thresholds"] = {"": "MEDIUM"}

        filtered = apply_content_filters(results, severities="high,low")

        # HIGH is at the threshold and kept; LOW is kept by the filter but is
        # not actionable; the critical one is filtered out.
        assert filtered["summary_stats"]["actionable"] == 1
        assert filtered["actionable_findings"] == 1
        assert filtered["summary_stats"]["total"] == 3

    def test_actionable_stays_when_the_sarif_is_not_loaded(self):
        """Without the SARIF the per-severity split of the actionable count is
        not in the document; the recorded value is kept rather than guessed."""
        filtered = apply_content_filters(_results(), severities="low")

        assert filtered["summary_stats"]["actionable"] == 3


class TestActionableOnlyRecountsTheSeverityBuckets:
    """actionable_only made total the actionable count while the per-severity
    buckets kept counting findings below the threshold beside it."""

    @staticmethod
    def _with_sarif(threshold):
        def result(rule, severity, scanner="bandit"):
            return {
                "ruleId": rule,
                "level": "note",
                "properties": {"scanner_name": scanner, "issue_severity": severity},
            }

        results = _results()
        results["raw_results"]["sarif"] = {
            "runs": [
                {
                    "results": [
                        result("S-CRIT", "CRITICAL", "semgrep"),
                        result("B-HIGH", "HIGH"),
                        result("S-MED", "MEDIUM", "semgrep"),
                        result("B-LOW-1", "LOW"),
                        result("B-LOW-2", "LOW"),
                    ]
                }
            ]
        }
        results["raw_results"]["severity_thresholds"] = {"": threshold}
        results["summary_stats"]["actionable"] = 3
        return results

    def test_the_buckets_follow_the_kept_findings(self):
        filtered = filter_actionable_only(self._with_sarif("MEDIUM"))

        counts = filtered["summary_stats"]["severity_counts"]
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 0
        assert counts["suppressed"] == 0
        assert filtered["summary_stats"]["total"] == 3
        assert sum(counts.values()) == filtered["summary_stats"]["total"]

    def test_the_summary_view_of_the_actionable_results_agrees(self):
        summary = filter_summary(filter_actionable_only(self._with_sarif("HIGH")))

        by_severity = summary["findings_summary"]["by_severity"]
        assert by_severity["critical"] == 1
        assert by_severity["high"] == 1
        assert by_severity["medium"] == 0
        assert by_severity["low"] == 0

    def test_without_the_sarif_the_buckets_stay(self):
        """The summary level never loads the SARIF; the document carries no
        per-severity split of the actionable count, so nothing is guessed."""
        filtered = filter_actionable_only(_results())

        assert filtered["summary_stats"]["severity_counts"]["low"] == 2


class TestTotalFollowsOneRule:
    """SummaryStats.total is the non-suppressed findings and ``suppressed`` a
    count beside it. The scanners recount summed ``finding_count`` (which a
    per-target file written before the metrics pass counts suppressed findings
    into) and the severities recount summed all six buckets, so one scanner read
    as 2 findings under one filter and 1 under the other."""

    @staticmethod
    def _results_with_a_suppressed_finding():
        results = _results()
        results["raw_results"]["scanner_results"]["bandit"] = {
            "status": "PASSED",
            # A per-target file's count: the suppressed finding counted in.
            "finding_count": 2,
            "actionable_finding_count": 1,
            "suppressed_finding_count": 1,
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
                "suppressed": 1,
            },
        }
        results["summary_stats"]["severity_counts"]["low"] = 0
        results["summary_stats"]["severity_counts"]["suppressed"] = 1
        results["summary_stats"]["total"] = 3
        return results

    def test_the_scanners_recount_does_not_count_suppressed_findings(self):
        filtered = apply_content_filters(
            self._results_with_a_suppressed_finding(), scanners="bandit"
        )

        assert filtered["summary_stats"]["total"] == 1
        assert filtered["summary_stats"]["severity_counts"]["suppressed"] == 1

    def test_the_severities_recount_agrees_with_the_scanners_recount(self):
        results = self._results_with_a_suppressed_finding()

        by_scanner = apply_content_filters(results, scanners="bandit")
        by_both = apply_content_filters(
            results,
            scanners="bandit",
            severities="critical,high,medium,low,info,suppressed",
        )

        assert by_both["summary_stats"]["total"] == by_scanner["summary_stats"]["total"]
        assert by_both["summary_stats"]["total"] == 1

    def test_selecting_only_suppressed_lists_them_under_their_own_count(self):
        filtered = apply_content_filters(
            self._results_with_a_suppressed_finding(), severities="suppressed"
        )

        assert filtered["summary_stats"]["severity_counts"]["suppressed"] == 1
        assert filtered["summary_stats"]["total"] == 0

    def test_a_scanner_without_buckets_keeps_its_finding_count(self):
        results = _results(with_summary_stats=False)
        results["raw_results"]["scanner_results"] = {
            "bandit": {"status": "PASSED", "finding_count": 4}
        }

        by_severity = filter_summary(results)["findings_summary"]["by_severity"]

        assert by_severity["total"] == 4
