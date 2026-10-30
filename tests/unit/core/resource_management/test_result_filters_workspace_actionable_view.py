# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The actionable view of a workspace results document, and the filters' input errors.

The workspace unified results file carries no ``summary_stats`` and the producer
puts ``{}`` in its place. ``filter_actionable_only`` wrote ``suppressed`` and
``total`` into that empty dict, which made it non-empty, so ``filter_summary``
never derived the summary from the per-scanner rows and the view read every
bucket 0: a workspace scan with findings reported as clean. The summary is now
derived from the rows as the filter leaves them, and a count the rows do not
carry stays None.

Beside it, the smaller readings the same review found: a scanners filter that
keeps a scanner only the SARIF names read every count 0 beside a findings list
that was not empty; a row narrowed to the suppressed bucket counted its
suppressed findings as findings; and an unknown filter name raised a plain
ValueError the server reported as its own fault.
"""

import pytest

from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)
from automated_security_helper.core.resource_management.result_filters import (
    ResultFilterInputError,
    add_findings_list,
    apply_content_filters,
    filter_actionable_only,
    filter_summary,
)

pytestmark = pytest.mark.unit


def _row(status, counts, suppressed=0):
    """A workspace file's scanner row: counts, no actionable_finding_count."""
    return {
        "status": status,
        "finding_count": sum(counts.values()),
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


def _result(rule, severity, scanner):
    return {
        "ruleId": rule,
        "level": "note",
        "properties": {"scanner_name": scanner, "issue_severity": severity},
    }


def _workspace_results(with_sarif=True):
    """The producer's response for a workspace file: summary_stats is ``{}``."""
    results = {
        "success": True,
        "scan_id": "ws",
        "status": "completed",
        "is_complete": True,
        "summary_stats": {},
        "raw_results": {
            "metadata": {"generated_at": "2024-01-01T00:00:00"},
            "scanner_results": {
                "bandit": _row("PASSED", {"high": 1, "low": 2}),
                "semgrep": _row("FAILED", {"critical": 1, "medium": 1}),
                "grype": _row("MISSING", {}),
            },
        },
    }
    if with_sarif:
        results["raw_results"]["sarif"] = {
            "runs": [
                {
                    "results": [
                        _result("B-HIGH", "HIGH", "bandit"),
                        _result("B-LOW", "LOW", "bandit"),
                        _result("B-LOW-2", "LOW", "bandit"),
                        _result("S-CRIT", "CRITICAL", "semgrep"),
                        _result("S-MED", "MEDIUM", "semgrep"),
                    ]
                }
            ]
        }
        results["raw_results"]["severity_thresholds"] = {"": "MEDIUM"}
    return results


class TestAWorkspaceDocumentsActionableViewIsDerivedFromItsRows:
    def test_the_summary_follows_the_kept_findings(self):
        filtered = filter_actionable_only(_workspace_results())

        stats = filtered["summary_stats"]
        # HIGH, CRITICAL and MEDIUM are at or above the threshold; the two LOW
        # findings are not. 3 actionable, known from the kept findings.
        assert stats["severity_counts"] == {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 0,
            "info": 0,
            "suppressed": 0,
        }
        assert stats["actionable"] == 3
        assert stats["total"] == 3
        assert stats["passed"] == 1
        assert stats["failed"] == 1
        assert stats["missing"] == 1

    def test_the_summary_view_reports_the_derived_counts_not_zero(self):
        """The control the review found: before the fix every bucket read 0."""
        summary = filter_summary(filter_actionable_only(_workspace_results()))

        by_severity = summary["findings_summary"]["by_severity"]
        assert by_severity["critical"] == 1
        assert by_severity["high"] == 1
        assert by_severity["total"] == 3
        assert by_severity["actionable"] == 3
        assert summary["findings_summary"]["scan_stats"]["failed"] == 1

    def test_the_rows_carry_the_actionable_count_the_filter_learned(self):
        """A workspace row has no actionable_finding_count; under this filter
        every kept finding is actionable, so the count is known and written."""
        filtered = filter_actionable_only(_workspace_results())

        rows = filtered["raw_results"]["scanner_results"]
        assert rows["bandit"]["actionable_finding_count"] == 1
        assert rows["bandit"]["finding_count"] == 1
        assert rows["semgrep"]["actionable_finding_count"] == 2
        assert "actionable_finding_count" not in rows["grype"]

    def test_without_the_sarif_the_counts_the_rows_lack_stay_unknown(self):
        """The summary level never loads the SARIF; the rows say what was found
        but not what is actionable, so actionable and total read None, not 0."""
        filtered = filter_actionable_only(_workspace_results(with_sarif=False))

        stats = filtered["summary_stats"]
        assert stats["severity_counts"]["critical"] == 1
        assert stats["severity_counts"]["low"] == 2
        assert stats["actionable"] is None
        assert stats["total"] is None
        by_severity = filter_summary(filtered)["findings_summary"]["by_severity"]
        assert by_severity["low"] == 2
        assert by_severity["total"] is None

    def test_nothing_to_derive_from_leaves_the_summary_empty(self):
        results = _workspace_results(with_sarif=False)
        results["raw_results"]["scanner_results"] = {}

        filtered = filter_actionable_only(results)

        assert filtered["summary_stats"] == {}
        by_severity = filter_summary(filtered)["findings_summary"]["by_severity"]
        assert by_severity["total"] is None

    def test_rows_of_scanners_that_did_not_run_have_nothing_actionable(self):
        results = _workspace_results(with_sarif=False)
        results["raw_results"]["scanner_results"] = {
            "grype": _row("MISSING", {}),
            "trivy": _row("SKIPPED", {}),
        }

        by_severity = filter_summary(results)["findings_summary"]["by_severity"]

        assert by_severity["actionable"] == 0
        assert by_severity["total"] == 0


class TestAScannerOnlyTheSarifNamesIsCountedFromTheSarif:
    @staticmethod
    def _results():
        results = _workspace_results()
        results["summary_stats"] = {
            "severity_counts": {
                "critical": 1,
                "high": 2,
                "medium": 1,
                "low": 2,
                "info": 0,
                "suppressed": 0,
            },
            "total": 6,
            "actionable": 4,
            "passed": 1,
            "failed": 1,
            "missing": 1,
            "skipped": 0,
            "error": 0,
        }
        results["actionable_findings"] = 4
        results["total_scanners"] = 2
        # checkov has no row of its own: only the SARIF names it.
        results["raw_results"]["sarif"]["runs"][0]["results"] += [
            _result("C-HIGH", "HIGH", "checkov"),
            _result("C-LOW", "LOW", "checkov"),
        ]
        return results

    def test_the_summary_follows_the_kept_findings(self):
        filtered = apply_content_filters(self._results(), scanners="checkov")

        stats = filtered["summary_stats"]
        assert stats["severity_counts"]["high"] == 1
        assert stats["severity_counts"]["low"] == 1
        assert stats["severity_counts"]["critical"] == 0
        assert stats["total"] == 2
        assert stats["actionable"] == 1
        assert filtered["actionable_findings"] == 1
        assert filtered["total_scanners"] == 1
        assert len(add_findings_list(filtered)["findings"]) == 2

    def test_a_kept_row_still_decides_the_summary(self):
        filtered = apply_content_filters(self._results(), scanners="bandit")

        assert filtered["summary_stats"]["total"] == 3
        assert filtered["total_scanners"] == 1


class TestARowNarrowedToTheSuppressedBucketCountsNoFindings:
    def test_the_rows_count_follows_the_one_rule(self):
        results = _workspace_results(with_sarif=False)
        results["raw_results"]["scanner_results"]["bandit"] = _row(
            "PASSED", {"high": 1}, suppressed=1
        )

        filtered = apply_content_filters(
            results, scanners="bandit", severities="high,suppressed"
        )

        row = filtered["raw_results"]["scanner_results"]["bandit"]
        assert row["severity_counts"] == {"high": 1, "suppressed": 1}
        assert row["finding_count"] == 1


class TestAnUnknownFilterNameIsTheClientsInputError:
    def test_the_error_is_a_value_error_with_the_input_category(self):
        assert issubclass(ResultFilterInputError, ValueError)
        assert (
            ResultFilterInputError.error_category
            == ErrorCategory.INVALID_PARAMETER.value
        )

    def test_an_unknown_severity_raises_it(self):
        with pytest.raises(ResultFilterInputError, match="Unknown severity"):
            apply_content_filters(_workspace_results(), severities="urgent")

    def test_an_unknown_scanner_raises_it(self):
        with pytest.raises(ResultFilterInputError, match="Unknown scanner"):
            apply_content_filters(_workspace_results(), scanners="bandit,nope")
