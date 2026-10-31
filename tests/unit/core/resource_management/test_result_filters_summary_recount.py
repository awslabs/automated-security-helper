# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The summary a filtered view reports describes the view, not the whole scan.

Four mechanisms, each pinned against the behavior it replaced:

* ``filter_summary`` defaulted every count to 0 when the results carried no
  ``summary_stats`` (the workspace unified results file has none), so such a
  scan read exactly like a clean one.
* ``filter_actionable_only`` on results whose SARIF was asked for and is null
  returned an empty findings list with no error, beside a nonzero
  ``summary_stats.actionable``; the view now says the findings cannot be
  listed (``findings_available`` False and a warning) and keeps the counts.
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
        # grype ERRORed instead of going MISSING: three scanners, three outcomes.
        results["summary_stats"]["error"] = 1
        results["summary_stats"]["missing"] = 0

        scan_stats = filter_summary(results)["findings_summary"]["scan_stats"]

        assert scan_stats["error"] == 1
        assert sum(scan_stats.values()) == 3

        results = _results(with_summary_stats=False)
        results["raw_results"]["scanner_results"]["trivy"] = _scanner(
            "ERROR", {}, actionable=0
        )

        scan_stats = filter_summary(results)["findings_summary"]["scan_stats"]

        assert scan_stats["error"] == 1
        assert sum(scan_stats.values()) == 4

    def test_an_entry_with_no_status_counts_as_passed_as_the_model_reads_it(self):
        """The results model reads an absent status as PASSED. Read as no
        outcome, the scanner was in no counter, so passed fell short of the
        scanners that ran."""
        results = _results(with_summary_stats=False)
        del results["raw_results"]["scanner_results"]["bandit"]["status"]

        scan_stats = filter_summary(results)["findings_summary"]["scan_stats"]

        assert scan_stats == {
            "passed": 1,
            "failed": 1,
            "missing": 1,
            "skipped": 0,
            "error": 0,
        }

    def test_a_status_that_is_not_a_word_counts_in_no_outcome(self):
        results = _results(with_summary_stats=False)
        results["raw_results"]["scanner_results"]["bandit"]["status"] = 5

        scan_stats = filter_summary(results)["findings_summary"]["scan_stats"]

        assert scan_stats["passed"] == 0
        assert sum(scan_stats.values()) == 2

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

    def test_a_count_a_scanner_that_ran_lacks_is_unknown_not_a_lower_bound(self):
        """semgrep carries 2 and bandit, which ran, carries nothing: the sum over
        the entries that carry it (2) is a lower bound, and used to be reported
        as the count."""
        results = self._without_actionable_counts(False)
        results["raw_results"]["scanner_results"]["semgrep"][
            "actionable_finding_count"
        ] = 2

        by_severity = filter_summary(results)["findings_summary"]["by_severity"]

        assert by_severity["actionable"] is None

    def test_a_count_only_scanners_that_did_not_run_lack_is_summed(self):
        results = _results(with_summary_stats=False)
        del results["raw_results"]["scanner_results"]["grype"][
            "actionable_finding_count"
        ]

        by_severity = filter_summary(results)["findings_summary"]["by_severity"]

        assert by_severity["actionable"] == 3


class TestACounterTheSummaryDoesNotCarryIsNone:
    """filter_summary's docstring says None means the document records no such
    count; a counter missing from a recorded summary_stats read 0.

    The two cases below differ on purpose: SummaryStats always writes its five
    outcome counters, so a missing one is a document that never recorded it
    (None), while it writes all six severity buckets too, and a recorded
    summary that lacks one has nothing in that bucket (0), the reading the
    producer's own ``severity_counts.get(bucket, 0)`` gives it.
    """

    def test_a_missing_outcome_counter_is_none(self):
        results = _results()
        del results["summary_stats"]["error"]

        scan_stats = filter_summary(results)["findings_summary"]["scan_stats"]

        assert scan_stats["error"] is None
        assert scan_stats["passed"] == 1

    def test_a_missing_bucket_of_a_recorded_summary_still_reads_zero(self):
        results = _results()
        del results["summary_stats"]["severity_counts"]["info"]

        by_severity = filter_summary(results)["findings_summary"]["by_severity"]

        assert by_severity["info"] == 0


class TestActionableOnlyRefusesAnUnlistableCount:
    def test_null_sarif_with_actionable_findings_marks_them_unlistable(self):
        """The summary is right (3 actionable) and only the list is missing, so
        the response says so instead of failing the whole call: it used to raise,
        and the server's handler turned the client's own results into a server
        fault with no category."""
        results = _results()
        results["raw_results"]["sarif"] = None

        filtered = filter_actionable_only(results)

        assert filtered["findings_available"] is False
        assert filtered["summary_stats"]["actionable"] == 3
        assert filtered["summary_stats"]["total"] == 3
        assert any("3 actionable" in w for w in filtered["warnings"])
        listed = add_findings_list(filtered)
        assert listed["findings"] == []
        assert listed["findings_available"] is False

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

    def test_total_scanners_counts_the_scanners_that_ran(self):
        """total_scanners is the scanners that PASSED or FAILED, as the
        producer counts it (the fixture says 2 for three entries, one MISSING).
        A recount of len(kept) and one that leaves MISSING out agree on every
        other test here, which keeps exactly one non-MISSING scanner."""
        filtered = apply_content_filters(_results(), scanners="bandit,grype")

        assert set(filtered["raw_results"]["scanner_results"]) == {"bandit", "grype"}
        assert filtered["total_scanners"] == 1
        assert filtered["summary_stats"]["missing"] == 1
        assert filtered["summary_stats"]["passed"] == 1

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


class TestScannersAndSeveritiesTogetherRecountOnce:
    """A severities recount that worked from the whole scan's stats would
    overwrite the scanners recount. semgrep alone holds one critical and one
    medium finding while the whole scan holds two critical-or-high, so this
    pair of filters tells the two behaviors apart (bandit with high would not:
    the whole scan's high is 1 too)."""

    def test_the_total_is_the_selected_buckets_of_the_kept_scanners(self):
        filtered = apply_content_filters(
            _results(), scanners="semgrep", severities="critical,high"
        )

        stats = filtered["summary_stats"]
        assert stats["severity_counts"]["critical"] == 1
        assert stats["severity_counts"]["high"] == 0
        assert stats["severity_counts"]["medium"] == 0
        assert stats["total"] == 1
        assert filtered["total_scanners"] == 1
        assert set(filtered["raw_results"]["scanner_results"]) == {"semgrep"}


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
                        result("B-LOW-2", "LOW"),
                        result("S-CRIT", "CRITICAL", "semgrep"),
                    ]
                }
            ]
        }
        results["raw_results"]["severity_thresholds"] = {"": "MEDIUM"}

        filtered = apply_content_filters(results, severities="high,low")

        # HIGH is at the threshold and kept; the two LOW ones are kept by the
        # filter but are not actionable; the critical one is filtered out. The
        # SARIF carries the same findings the summary counts (1 high, 2 low).
        assert filtered["summary_stats"]["actionable"] == 1
        assert filtered["actionable_findings"] == 1
        assert filtered["summary_stats"]["total"] == 3
        assert len(add_findings_list(filtered)["findings"]) == 3

    def test_actionable_is_unknown_when_the_sarif_is_not_loaded(self):
        """Without the SARIF the per-severity split of the actionable count is
        not in the document, so a partial selection cannot say how many of its
        findings are actionable: None, where the whole scan's 3 used to stay
        and reported the critical and high findings as the low view's."""
        filtered = apply_content_filters(_results(), severities="low")

        assert filtered["summary_stats"]["actionable"] is None
        assert filtered["actionable_findings"] is None

    def test_actionable_is_known_when_the_selection_decides_it(self):
        """Every counted bucket selected is the whole scan's count; only the
        suppressed bucket selected has nothing actionable in it."""
        every_bucket = apply_content_filters(
            _results(), severities="critical,high,medium,low,info"
        )
        suppressed_only = apply_content_filters(_results(), severities="suppressed")

        assert every_bucket["summary_stats"]["actionable"] == 3
        assert suppressed_only["summary_stats"]["actionable"] == 0
        assert suppressed_only["actionable_findings"] == 0


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


class TestActionableOnlySurvivesTheContentFilters:
    """The server applies filter_actionable_only, then apply_content_filters.
    The recounts overwrote the total that filter_actionable_only had set to the
    actionable count, and replaced _content_filters outright, so the flag was
    lost and an actionable-only view again reported findings it did not list."""

    def test_the_total_stays_the_actionable_count_under_a_scanners_filter(self):
        filtered = apply_content_filters(
            filter_actionable_only(_results()), scanners="bandit"
        )

        stats = filtered["summary_stats"]
        assert stats["actionable"] == 1
        assert stats["total"] == 1
        assert filtered["actionable_findings"] == 1
        assert filtered["_content_filters"] == {
            "actionable_only": True,
            "scanners": ["bandit"],
        }

    def test_the_total_stays_the_actionable_count_under_a_severities_filter(self):
        results = TestActionableOnlyRecountsTheSeverityBuckets._with_sarif("MEDIUM")

        filtered = apply_content_filters(
            filter_actionable_only(results), severities="critical,high"
        )

        stats = filtered["summary_stats"]
        assert stats["actionable"] == 2
        assert stats["total"] == 2
        assert filtered["_content_filters"]["actionable_only"] is True
        assert filtered["_content_filters"]["severities"] == ["critical", "high"]

    def test_without_actionable_only_the_total_is_the_views_findings(self):
        filtered = apply_content_filters(_results(), scanners="bandit")

        assert filtered["summary_stats"]["total"] == 3
        assert "actionable_only" not in filtered["_content_filters"]

    def test_the_buckets_follow_the_kept_findings_under_a_scanners_filter(self):
        """The scanners recount derives the summary from the per-scanner rows.
        Under actionable_only those rows carry the kept findings' buckets, so
        the recount agrees with the findings list: one actionable bandit
        finding at HIGH, not the whole scan's high 1 / low 2 / total 3."""
        results = TestActionableOnlyRecountsTheSeverityBuckets._with_sarif("MEDIUM")

        filtered = apply_content_filters(
            filter_actionable_only(results), scanners="bandit"
        )

        stats = filtered["summary_stats"]
        assert stats["severity_counts"] == {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
        }
        assert stats["total"] == 1
        assert stats["actionable"] == 1
        listed = [
            result["ruleId"]
            for run in filtered["raw_results"]["sarif"]["runs"]
            for result in run["results"]
        ]
        assert listed == ["B-HIGH"]


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
        # The four findings are in no bucket the row records, so the buckets
        # are unknown, not a confident 0 per severity beside a total of 4.
        assert by_severity["critical"] is None
        assert by_severity["high"] is None
        assert by_severity["suppressed"] is None

    @pytest.mark.parametrize(
        "severity_counts",
        [
            pytest.param({}, id="an-empty-bucket-object"),
            pytest.param({"high": "4"}, id="a-bucket-whose-value-is-not-a-count"),
            pytest.param({"weird": 4}, id="a-key-the-summary-has-no-bucket-for"),
        ],
    )
    def test_a_row_with_no_usable_bucket_keeps_its_finding_count(
        self, severity_counts
    ):
        results = _results(with_summary_stats=False)
        results["raw_results"]["scanner_results"] = {
            "bandit": {
                "status": "PASSED",
                "finding_count": 4,
                "severity_counts": severity_counts,
            }
        }

        by_severity = filter_summary(results)["findings_summary"]["by_severity"]

        # A breakdown that names no bucket records nothing beside a count of
        # 4: the row reads like one with no breakdown, not as a clean scan.
        assert by_severity["total"] == 4
        assert by_severity["high"] is None
        assert by_severity["suppressed"] is None

    def test_one_row_without_buckets_makes_the_derived_buckets_unknown(self):
        results = _results(with_summary_stats=False)
        results["raw_results"]["scanner_results"]["trivy"] = {
            "status": "PASSED",
            "finding_count": 2,
        }

        by_severity = filter_summary(results)["findings_summary"]["by_severity"]

        assert by_severity["total"] == 7
        assert by_severity["high"] is None

    def test_a_row_without_buckets_and_without_findings_keeps_the_buckets(self):
        results = _results(with_summary_stats=False)
        results["raw_results"]["scanner_results"]["trivy"] = {
            "status": "PASSED",
            "finding_count": 0,
        }

        by_severity = filter_summary(results)["findings_summary"]["by_severity"]

        assert by_severity["total"] == 5
        assert by_severity["high"] == 1


class TestARowWithoutBucketsLeavesTheFilteredBucketsUnknown:
    """``filter_summary`` reports unknown buckets for a row that counts findings
    and records no breakdown, but only for the summary it derives itself. The two
    recounts of the content filters (the ``scanners`` filter over a recorded
    summary, and the actionable-only derivation for a workspace file) wrote the
    zero buckets of such a row beside its positive total, so the view read "2
    findings, none of them critical, high, medium, low or info"."""

    @staticmethod
    def _results_with_a_row_that_only_counts():
        results = _results()
        results["raw_results"]["scanner_results"]["trivy"] = {
            "status": "PASSED",
            "finding_count": 2,
        }
        return results

    def test_a_scanners_filter_keeps_the_buckets_of_such_a_row_unknown(self):
        filtered = apply_content_filters(
            self._results_with_a_row_that_only_counts(), scanners="trivy"
        )
        by_severity = filter_summary(filtered)["findings_summary"]["by_severity"]

        assert by_severity["total"] == 2
        assert by_severity["critical"] is None
        assert by_severity["high"] is None
        assert by_severity["info"] is None
        assert by_severity["suppressed"] is None

    def test_one_such_row_among_the_kept_scanners_makes_every_bucket_unknown(self):
        filtered = apply_content_filters(
            self._results_with_a_row_that_only_counts(), scanners="bandit,trivy"
        )
        by_severity = filter_summary(filtered)["findings_summary"]["by_severity"]

        # bandit's three findings and trivy's two: the total is exact, and the
        # buckets bandit alone fills would be a lower bound shown as exact.
        assert by_severity["total"] == 5
        assert by_severity["high"] is None
        assert by_severity["low"] is None

    def test_a_scanners_filter_over_rows_with_buckets_keeps_them_known(self):
        # Control: green before and after the cure. It proves the cure did not
        # make every filtered bucket unknown.
        filtered = apply_content_filters(
            self._results_with_a_row_that_only_counts(), scanners="bandit"
        )
        by_severity = filter_summary(filtered)["findings_summary"]["by_severity"]

        assert by_severity["total"] == 3
        assert by_severity["high"] == 1
        assert by_severity["low"] == 2

    def test_an_actionable_view_of_a_workspace_file_keeps_them_unknown_too(self):
        results = self._results_with_a_row_that_only_counts()
        # The workspace unified results file carries no summary_stats: the
        # producer puts {} in its place, and the filter derives one from the rows.
        results["summary_stats"] = {}

        filtered = filter_actionable_only(results)
        buckets = filtered["summary_stats"]["severity_counts"]

        assert buckets["critical"] is None
        assert buckets["high"] is None
        # The view holds no suppressed finding whatever the rows said: known.
        assert buckets["suppressed"] == 0
