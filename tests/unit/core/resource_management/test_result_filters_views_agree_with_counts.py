# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A filtered view's counts, coverage and filter record agree with what it shows.

Each test is pinned against the behavior it replaced:

* ``filter_summary`` and ``filter_minimal`` kept ``status`` "incomplete" and
  dropped ``coverage_complete`` and the gap lists.
* ``filter_actionable_only`` left each scanner's ``finding_count`` and severity
  buckets at whole-scan values beside a SARIF it had narrowed to the actionable
  findings; a ``severities`` filter left a scanner's ``finding_count`` beside
  buckets it had narrowed.
* ``apply_content_filters`` replaced the top-level ``summary_stats`` with a new
  dict and left the copy under ``raw_results.metadata`` unfiltered.
* ``apply_content_filters`` assigned ``_content_filters`` wholesale, dropping the
  ``actionable_only`` marker set before it ran.
* A whitespace-only or separator-only filter became a list of empty names that
  matched nothing; an unknown severity or scanner name matched nothing and
  returned a clean-looking view.
* ``add_findings_list`` returned an empty list for a document with no SARIF,
  the same answer as a scan with no actionable findings.
"""

import copy

import pytest

from automated_security_helper.core.resource_management.result_filters import (
    add_findings_list,
    apply_content_filters,
    filter_actionable_only,
    filter_minimal,
    filter_summary,
)

pytestmark = pytest.mark.unit


def _result(rule_id, scanner, severity):
    return {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": rule_id},
        "properties": {"scanner_name": scanner, "issue_severity": severity},
    }


def _results():
    return {
        "success": True,
        "scan_id": "abc",
        "status": "incomplete",
        "is_complete": True,
        "coverage_complete": False,
        "incomplete_scanners": ["grype"],
        "no_scanner_ran": False,
        "incomplete_converters": [],
        "unevaluated_rules": [],
        "stale_content_databases": [],
        "completion_time": "2024-01-01T00:00:00",
        "actionable_findings": 2,
        "total_scanners": 2,
        "summary_stats": {
            "severity_counts": {
                "critical": 0,
                "high": 2,
                "medium": 0,
                "low": 1,
                "info": 0,
                "suppressed": 0,
            },
            "total": 3,
            "actionable": 2,
            "passed": 1,
            "failed": 1,
            "missing": 1,
            "skipped": 0,
            "error": 0,
        },
        "scanner_reports": {"bandit": {}, "semgrep": {}},
        "raw_results": {
            "metadata": {
                "generated_at": "2024-01-01T00:00:00",
                "summary_stats": {"total": 3, "actionable": 2},
            },
            "scanner_results": {
                "bandit": {
                    "status": "FAILED",
                    "finding_count": 2,
                    "actionable_finding_count": 1,
                    "suppressed_finding_count": 0,
                    "severity_counts": {
                        "critical": 0,
                        "high": 1,
                        "medium": 0,
                        "low": 1,
                        "info": 0,
                        "suppressed": 0,
                    },
                },
                "semgrep": {
                    "status": "PASSED",
                    "finding_count": 1,
                    "actionable_finding_count": 1,
                    "suppressed_finding_count": 0,
                    "severity_counts": {
                        "critical": 0,
                        "high": 1,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                        "suppressed": 0,
                    },
                },
                "grype": {"status": "MISSING", "finding_count": 0},
            },
            "severity_thresholds": {"": "MEDIUM"},
            "sarif": {
                "runs": [
                    {
                        "results": [
                            _result("B101", "bandit", "HIGH"),
                            _result("B102", "bandit", "LOW"),
                            _result("S1", "semgrep", "HIGH"),
                        ]
                    }
                ]
            },
        },
    }


class TestSummaryViewsCarryCoverage:
    def test_filter_summary_carries_coverage_complete_and_the_gap_lists(self):
        summary = filter_summary(_results())

        assert summary["status"] == "incomplete"
        assert summary["coverage_complete"] is False
        assert summary["incomplete_scanners"] == ["grype"]
        assert summary["no_scanner_ran"] is False

    def test_filter_minimal_carries_coverage_complete_and_the_gap_lists(self):
        minimal = filter_minimal(_results())

        assert minimal["status"] == "incomplete"
        assert minimal["coverage_complete"] is False
        assert minimal["incomplete_scanners"] == ["grype"]

    def test_a_document_without_coverage_fields_adds_none(self):
        results = {"scan_id": "x", "status": "completed"}

        assert "coverage_complete" not in filter_summary(results)
        assert "coverage_complete" not in filter_minimal(results)


class TestPerScannerCountsFollowTheView:
    def test_actionable_only_recounts_each_scanner_from_its_kept_findings(self):
        filtered = filter_actionable_only(_results())

        bandit = filtered["raw_results"]["scanner_results"]["bandit"]
        assert bandit["finding_count"] == 1
        assert bandit["actionable_finding_count"] == 1
        assert bandit["severity_counts"]["high"] == 1
        assert bandit["severity_counts"]["low"] == 0
        # A scanner the SARIF never named keeps its row.
        assert filtered["raw_results"]["scanner_results"]["grype"]["finding_count"] == 0

    def test_a_severity_filter_recounts_each_scanner_from_the_kept_buckets(self):
        filtered = apply_content_filters(_results(), severities="high")

        bandit = filtered["raw_results"]["scanner_results"]["bandit"]
        assert bandit["severity_counts"] == {"high": 1}
        assert bandit["finding_count"] == 1


class TestTheSummaryUnderMetadataFollowsTheTopLevel:
    def test_a_scanner_filter_rewrites_the_metadata_copy_too(self):
        filtered = apply_content_filters(_results(), scanners="bandit")

        top = filtered["summary_stats"]
        under_metadata = filtered["raw_results"]["metadata"]["summary_stats"]
        assert top["total"] == 2
        assert under_metadata["total"] == top["total"]
        assert under_metadata is top


class TestTheFilterRecordAccumulates:
    def test_the_actionable_only_marker_survives_the_content_filters(self):
        filtered = apply_content_filters(
            filter_actionable_only(_results()), scanners="bandit"
        )

        assert filtered["_content_filters"] == {
            "actionable_only": True,
            "scanners": ["bandit"],
        }


class TestFilterNamesAreChecked:
    def test_a_blank_filter_is_no_filter(self):
        results = _results()

        filtered = apply_content_filters(results, scanners="  ,  ", severities=" ")

        assert (
            filtered["raw_results"]["scanner_results"]
            == results["raw_results"]["scanner_results"]
        )
        assert filtered["summary_stats"] == results["summary_stats"]
        assert filtered["_content_filters"] == {}

    def test_an_unknown_severity_is_refused(self):
        with pytest.raises(ValueError) as excinfo:
            apply_content_filters(_results(), severities="critcal")

        assert "critcal" in str(excinfo.value)
        assert "critical" in str(excinfo.value)

    def test_an_unknown_scanner_is_refused_with_the_known_ones_named(self):
        with pytest.raises(ValueError) as excinfo:
            apply_content_filters(_results(), scanners="bandti")

        assert "bandti" in str(excinfo.value)
        assert "bandit" in str(excinfo.value)

    def test_a_document_that_names_no_scanners_is_not_checked(self):
        results = {"scan_id": "x", "summary_stats": {"total": 0}}

        filtered = apply_content_filters(results, scanners="anything")

        assert filtered["_content_filters"] == {"scanners": ["anything"]}

    def test_known_names_still_pass(self):
        filtered = apply_content_filters(
            _results(), scanners="Bandit", severities="HIGH"
        )

        assert list(filtered["raw_results"]["scanner_results"]) == ["bandit"]


class TestFindingsAvailability:
    def test_a_document_without_sarif_says_its_findings_cannot_be_listed(self):
        results = add_findings_list({"raw_results": {"sarif": None}})

        assert results["findings"] == []
        assert results["findings_count"] == 0
        assert results["findings_available"] is False

    def test_a_document_with_sarif_says_they_can(self):
        results = add_findings_list(copy.deepcopy(_results()))

        assert results["findings_available"] is True
        assert results["findings_count"] == 3
