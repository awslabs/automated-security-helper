# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The in-progress and completed progress views on the files ASH writes.

Three mechanisms, each pinned against the behavior it replaced:

* ``get_scan_progress_info`` bound ``scanners_completed`` and
  ``findings_summary`` only inside ``if results:``, so an aggregated file that
  parsed to an empty object raised UnboundLocalError at the return.
* A per-scanner ``ASH.ScanResults.json`` that was empty, truncated or mid-write
  was reported as a scanner that PASSED with 0 findings: its unreadable text
  yielded no findings and no recorded status, and COMPLETED was the default.
* The in-progress view counted findings from each file's findings array, which
  the per-target file ASH writes does not have, so every finished scanner read
  as 0 findings until the aggregated file existed.
"""

import json

import pytest

from automated_security_helper.core.resource_management.scan_tracking import (
    MCScannerStatus,
    create_scan_progress_from_files,
    get_scan_progress_info,
    get_scanner_progress,
)

pytestmark = pytest.mark.unit

_RESULTS_FILE = "ASH.ScanResults.json"


def _write_result(output_dir, scanner, target, text):
    path = output_dir / "scanners" / scanner / target / _RESULTS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TestAnEmptyAggregatedDocumentDoesNotRaise:
    def test_an_empty_object_reads_as_results_not_yet_written(self, tmp_path):
        out = tmp_path / "ash_output"
        out.mkdir()
        (out / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")

        info = get_scan_progress_info(out)

        # A JSON object with neither scanner_results nor sarif is not a results
        # document yet, which create_scan_progress_from_files calls
        # results_pending; it is not a completed scan with no scanners.
        assert info["status"] == "in_progress"
        assert info["is_complete"] is False
        assert info["results_pending"] is True
        assert info["scanners_completed"] == []
        assert info["total_scanners"] == 0
        assert info["findings_count"] == 0
        assert sum(info["findings_summary"].values()) == 0

    @pytest.mark.parametrize("text", ["[]", "null"])
    def test_a_non_object_document_is_an_error_not_a_crash(self, tmp_path, text):
        out = tmp_path / "ash_output"
        out.mkdir()
        (out / "ash_aggregated_results.json").write_text(text, encoding="utf-8")

        info = get_scan_progress_info(out)

        assert info["status"] == "error"
        assert info["is_complete"] is True


class TestAnUnreadableScannerFileIsNotAPass:
    @pytest.mark.parametrize(
        "text",
        ["", '{"scanner_name": "bandit", "finding_count": 3, "sta', '"a string"'],
        ids=["empty", "truncated", "not-an-object"],
    )
    def test_the_scanner_reads_as_still_running(self, tmp_path, text):
        out = tmp_path / "ash_output"
        _write_result(out, "bandit", "source", text)

        progress = create_scan_progress_from_files("scan-1", out)

        scanner = progress.scanners["bandit"]["source"]
        assert scanner.status is MCScannerStatus.RUNNING
        assert scanner.finding_count == 0
        assert progress.completed_scanners == 0
        assert progress.finished_scanners == 0
        assert progress.scanner_status_counts["running"] == 1

    def test_a_readable_file_still_reads_as_finished(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_result(
            out,
            "bandit",
            "source",
            json.dumps(
                {"scanner_name": "bandit", "finding_count": 0, "status": "PASSED"}
            ),
        )

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.scanners["bandit"]["source"].status is MCScannerStatus.COMPLETED
        assert progress.completed_scanners == 1


class TestTheInProgressViewCountsWhatScannersRecorded:
    def test_recorded_counts_reach_findings_count_and_summary(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_result(
            out,
            "detect-secrets",
            "source",
            json.dumps(
                {
                    "scanner_name": "detect-secrets",
                    "finding_count": 3,
                    "severity_counts": {"high": 2, "low": 1},
                    "status": "FAILED",
                }
            ),
        )
        _write_result(
            out,
            "bandit",
            "source",
            json.dumps({"findings": [{"severity": "MEDIUM"}]}),
        )

        progress = get_scanner_progress(out)
        info = get_scan_progress_info(out)

        assert progress["detect-secrets"]["finding_count"] == 3
        assert progress["detect-secrets"]["severity_counts"]["high"] == 2
        assert progress["detect-secrets"]["findings"] == []
        assert progress["bandit"]["finding_count"] == 1
        assert info["status"] == "in_progress"
        assert info["findings_count"] == 4
        assert info["findings_summary"]["high"] == 2
        assert info["findings_summary"]["low"] == 1
        assert info["findings_summary"]["medium"] == 1
        # The findings list still holds only the findings that were listed.
        assert len(info["findings"]) == 1

    def test_a_metadata_file_with_no_counts_reads_as_zero(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_result(out, "bandit", "source", json.dumps({"scanner_name": "bandit"}))

        info = get_scan_progress_info(out)

        assert info["findings_count"] == 0
        assert sum(info["findings_summary"].values()) == 0
