# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The progress poll reads what the files hold and does not fail on what a scan does to them.

Each group is pinned against the behavior it replaced:

* ``find_scanner_result_files`` listed ``scanners/`` and the directories under it
  with a bare ``iterdir``, so a directory that was removed, set aside or made
  unreadable after the check that it was a directory failed the whole poll.
* ``ScanProgress`` counted (scanner, target) pairs as scanners, so a scanner with
  source and converted results was two of them while a scan ran and one once the
  aggregated file existed.
* The aggregated document was read more strictly than its model: a SARIF run whose
  ``results`` is null, a ``finding_count`` of null and an ``scanner_results``
  entry with no ``status`` each failed or mis-graded the whole view. Its SARIF
  results were attributed to the run's tool, which is ASH's for every scanner, so
  no scanner matched; its scanners got the time of the poll as an end time and no
  duration.
* ``summarize_scanner_statuses`` raised on a results file that is not UTF-8, read
  the file with a plain read that fails during an atomic replace on Windows,
  compared the status case-sensitively, read the string ``"false"`` as true, and
  gave a ``MISSING`` scanner whose dependencies were satisfied the bare reason
  ``skipped``.
* ``get_scan_progress_info`` raised on null containers, called a file with neither
  ``scanner_results`` nor ``sarif`` a completed scan, read SARIF results for a
  ``severity`` key they do not have, returned the summary stats where the running
  view returns severity buckets, and read the results put back after a scan that
  ended without any as this scan's.
* ``get_scan_results_with_error_handling`` looked for the put-back marker only
  before it read the results.
"""

import errno
import json
import os
from pathlib import Path

import pytest

from automated_security_helper.core.previous_results import RESTORED_MARKER_NAME
from automated_security_helper.core.resource_management import scan_tracking
from automated_security_helper.core.resource_management.scan_tracking import (
    MCScannerStatus,
    ScannerProgress,
    ScanProgress,
    create_scan_progress_from_files,
    find_scanner_result_files,
    get_scan_progress_info,
    get_scan_results_with_error_handling,
    summarize_scanner_statuses,
)

pytestmark = pytest.mark.unit

_RESULTS_FILE = "ASH.ScanResults.json"


def _write_scanner_file(output_dir, scanner, target, document):
    path = output_dir / "scanners" / scanner / target / _RESULTS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _write_aggregated(output_dir, document):
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ash_aggregated_results.json").write_text(
        json.dumps(document), encoding="utf-8"
    )


def _scanner(name, target, status):
    progress = ScannerProgress(name, target)
    progress.status = status
    return progress


def _fail_listing(monkeypatch, directory_name, error):
    """Make ``Path.iterdir`` raise ``error`` for any directory named ``directory_name``."""
    real_iterdir = Path.iterdir

    def iterdir(self):
        if self.name == directory_name:
            raise error
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", iterdir)


class TestAListingThatFailsDoesNotFailThePoll:
    def test_an_unreadable_scanner_directory_is_skipped_and_the_rest_are_read(
        self, tmp_path, monkeypatch
    ):
        out = tmp_path / "ash_output"
        _write_scanner_file(out, "bandit", "source", {"scanner_name": "bandit"})
        _write_scanner_file(out, "semgrep", "source", {"scanner_name": "semgrep"})
        _fail_listing(monkeypatch, "semgrep", PermissionError(errno.EACCES, "denied"))

        found = find_scanner_result_files(out)

        assert set(found) == {"bandit"}

    def test_a_scanner_directory_removed_before_its_listing_is_skipped(
        self, tmp_path, monkeypatch
    ):
        out = tmp_path / "ash_output"
        _write_scanner_file(out, "bandit", "source", {"scanner_name": "bandit"})
        _write_scanner_file(out, "bandit", "converted", {"scanner_name": "bandit"})
        _write_scanner_file(out, "semgrep", "source", {"scanner_name": "semgrep"})
        _fail_listing(monkeypatch, "bandit", FileNotFoundError(errno.ENOENT, "gone"))

        found = find_scanner_result_files(out)

        assert set(found) == {"semgrep"}

    def test_a_scanners_directory_that_cannot_be_listed_reads_as_no_results(
        self, tmp_path, monkeypatch
    ):
        out = tmp_path / "ash_output"
        _write_scanner_file(out, "bandit", "source", {"scanner_name": "bandit"})
        _fail_listing(monkeypatch, "scanners", FileNotFoundError(errno.ENOENT, "gone"))

        assert find_scanner_result_files(out) == {}

    def test_the_running_view_reports_the_scanners_it_could_list(
        self, tmp_path, monkeypatch
    ):
        out = tmp_path / "ash_output"
        _write_scanner_file(out, "bandit", "source", {"scanner_name": "bandit"})
        _write_scanner_file(out, "semgrep", "source", {"scanner_name": "semgrep"})
        _fail_listing(monkeypatch, "semgrep", PermissionError(errno.EACCES, "denied"))

        info = get_scan_progress_info(out)

        assert info["status"] == "in_progress"
        assert info["scanners_completed"] == ["bandit"]


class TestScannersAreCountedOnceWhateverTheirTargets:
    def test_a_scanner_with_two_finished_targets_is_one_completed_scanner(self):
        scan = ScanProgress("scan-1")
        scan.add_scanner_progress(
            _scanner("trivy", "source", MCScannerStatus.COMPLETED)
        )
        scan.add_scanner_progress(
            _scanner("trivy", "converted", MCScannerStatus.COMPLETED)
        )

        assert scan.total_scanners == 1
        assert scan.completed_scanners == 1
        assert scan.finished_scanners == 1
        assert scan.scanner_status_counts["passed"] == 1

    def test_a_scanner_with_an_unfinished_target_has_not_finished(self):
        scan = ScanProgress("scan-1")
        scan.add_scanner_progress(
            _scanner("trivy", "source", MCScannerStatus.COMPLETED)
        )
        scan.add_scanner_progress(
            _scanner("trivy", "converted", MCScannerStatus.RUNNING)
        )

        assert scan.total_scanners == 1
        assert scan.completed_scanners == 0
        assert scan.finished_scanners == 0
        assert scan.scanner_status_counts["running"] == 1
        assert scan.scanner_status_counts["passed"] == 0

    def test_a_failed_target_makes_the_scanner_failed(self):
        scan = ScanProgress("scan-1")
        scan.add_scanner_progress(_scanner("trivy", "source", MCScannerStatus.FAILED))
        scan.add_scanner_progress(
            _scanner("trivy", "converted", MCScannerStatus.COMPLETED)
        )

        assert scan.completed_scanners == 0
        assert scan.finished_scanners == 1
        assert scan.scanner_status_counts["failed"] == 1
        assert scan.scanner_status_counts["passed"] == 0

    def test_the_counts_do_not_change_when_the_aggregated_file_replaces_the_target_files(
        self, tmp_path
    ):
        out = tmp_path / "ash_output"
        for target in ("source", "converted"):
            _write_scanner_file(
                out,
                "bandit",
                target,
                {"scanner_name": "bandit", "status": "PASSED", "finding_count": 0},
            )

        running = create_scan_progress_from_files("scan-1", out)
        _write_aggregated(
            out,
            {
                "scanner_results": {
                    "bandit": {"status": "PASSED", "finding_count": 0},
                }
            },
        )
        finished = create_scan_progress_from_files("scan-1", out)

        assert running.total_scanners == finished.total_scanners == 1
        assert running.completed_scanners == finished.completed_scanners == 1
        assert running.finished_scanners == finished.finished_scanners == 1


class TestTheAggregatedDocumentIsReadAsLeniblyAsItsModel:
    def _bandit(self, **entry):
        return {"scanner_results": {"bandit": entry}}

    def test_a_run_whose_results_is_null_has_no_results_and_fails_nothing(
        self, tmp_path
    ):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {
                "sarif": {
                    "runs": [{"tool": {"driver": {"name": "ASH"}}, "results": None}]
                },
                "scanner_results": {
                    "bandit": {"status": "PASSED", "severity_counts": {}}
                },
            },
        )

        progress = create_scan_progress_from_files("scan-1", out)
        info = get_scan_progress_info(out)

        assert progress.status == "completed"
        assert progress.error_message is None
        assert info["status"] == "completed"
        assert info["findings_count"] == 0

    def test_a_null_finding_count_is_taken_from_the_breakdown(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            self._bandit(
                status="PASSED", finding_count=None, severity_counts={"high": 2}
            ),
        )

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.status == "completed"
        assert progress.error_message is None
        assert progress.scanners["bandit"]["source"].finding_count == 2
        assert progress.total_findings == 2

    def test_an_entry_with_no_status_reads_as_passed_as_the_model_reads_it(
        self, tmp_path
    ):
        out = tmp_path / "ash_output"
        _write_aggregated(out, self._bandit(finding_count=0, severity_counts={}))

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.scanners["bandit"]["source"].status == MCScannerStatus.COMPLETED
        assert progress.completed_scanners == 1

    def test_a_null_breakdown_is_no_breakdown(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out, self._bandit(status="FAILED", finding_count=1, severity_counts=None)
        )

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.status == "completed"
        assert progress.scanners["bandit"]["source"].finding_count == 1
        assert progress.severity_counts["unknown"] == 1

    def test_sarif_results_are_attributed_to_the_scanner_they_name(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {
                "sarif": {
                    "runs": [
                        {
                            # ASH writes one run for every scanner.
                            "tool": {"driver": {"name": "ASH"}},
                            "results": [
                                {
                                    "ruleId": "B105",
                                    "level": "error",
                                    "properties": {"scanner_name": "bandit"},
                                }
                            ],
                        }
                    ]
                },
                "scanner_results": {"bandit": {"status": "FAILED"}},
            },
        )

        progress = create_scan_progress_from_files("scan-1", out)

        source = progress.scanners["bandit"]["source"]
        assert source.finding_count == 1
        assert source.severity_counts["critical"] == 1

    def test_a_suppressed_sarif_result_is_in_its_bucket_and_not_in_the_count(
        self, tmp_path
    ):
        """Two bandit results, one with a suppression in effect. The completed
        view grades the suppressed one as ``suppressed`` and leaves it out of
        the count; the registry's progress counted it in the count and under
        its severity, so the same scan read 2 critical in one view and 1
        critical beside 1 suppressed in the other."""
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {
                "sarif": {
                    "runs": [
                        {
                            "tool": {"driver": {"name": "ASH"}},
                            "results": [
                                {
                                    "ruleId": "B105",
                                    "level": "error",
                                    "properties": {"scanner_name": "bandit"},
                                },
                                {
                                    "ruleId": "B106",
                                    "level": "error",
                                    "properties": {"scanner_name": "bandit"},
                                    "suppressions": [{"kind": "inSource"}],
                                },
                            ],
                        }
                    ]
                },
                "scanner_results": {"bandit": {"status": "FAILED"}},
            },
        )

        progress = create_scan_progress_from_files("scan-1", out)
        info = get_scan_progress_info(out)

        source = progress.scanners["bandit"]["source"]
        assert source.finding_count == 1
        assert source.severity_counts["critical"] == 1
        assert source.severity_counts["suppressed"] == 1
        assert progress.total_findings == info["findings_count"] == 1
        assert info["findings_summary"]["critical"] == 1
        assert info["findings_summary"]["suppressed"] == 1

    def test_a_recorded_count_beyond_the_matched_results_keeps_the_rest_unknown(
        self, tmp_path
    ):
        """Three findings recorded, one SARIF result naming the scanner. The
        per-target path keeps the recorded 3 and grades the two the results do
        not show as unknown; the registry's poll replaced the 3 with the 1 the
        results gave, so the scan's total fell when its file was aggregated."""
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {
                "sarif": {
                    "runs": [
                        {
                            "tool": {"driver": {"name": "ASH"}},
                            "results": [
                                {
                                    "ruleId": "B105",
                                    "level": "error",
                                    "properties": {"scanner_name": "bandit"},
                                }
                            ],
                        }
                    ]
                },
                "scanner_results": {"bandit": {"status": "FAILED", "finding_count": 3}},
            },
        )

        progress = create_scan_progress_from_files("scan-1", out)

        source = progress.scanners["bandit"]["source"]
        assert source.finding_count == 3
        assert source.severity_counts["critical"] == 1
        assert source.severity_counts["unknown"] == 2
        assert progress.total_findings == 3

    def test_a_recorded_count_is_not_overwritten_by_results_that_matched_nothing(
        self, tmp_path
    ):
        out = tmp_path / "ash_output"
        _write_aggregated(out, self._bandit(status="FAILED", finding_count=3))

        progress = create_scan_progress_from_files("scan-1", out)

        source = progress.scanners["bandit"]["source"]
        assert source.finding_count == 3
        # In the total, so in a bucket: the catch-all one.
        assert source.severity_counts["unknown"] == 3
        assert progress.total_findings == 3
        assert sum(progress.severity_counts.values()) == 3

    def test_a_scanner_carries_the_duration_the_document_recorded(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            self._bandit(
                status="PASSED", finding_count=0, severity_counts={}, duration=2.5
            ),
        )

        progress = create_scan_progress_from_files("scan-1", out)

        source = progress.scanners["bandit"]["source"]
        assert source.duration == 2.5
        # The document records no end time for a scanner; the poll's is not one.
        assert source.end_time is None

    def test_a_scanner_that_did_not_run_has_no_duration(self, tmp_path):
        """The results model dumps its default 0.0 for a scanner that was
        missing or skipped, and 0.0 read as a measured run of no time."""
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {
                "scanner_results": {
                    "bandit": {"status": "MISSING", "duration": 0.0},
                    "semgrep": {"status": "SKIPPED", "duration": 0.0},
                    "checkov": {"status": "PASSED", "duration": 0.0},
                }
            },
        )

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.scanners["bandit"]["source"].duration is None
        assert progress.scanners["semgrep"]["source"].duration is None
        # A scanner that ran and was quick keeps the 0.0 it recorded.
        assert progress.scanners["checkov"]["source"].duration == 0.0


class TestTheSkippedScannerSummaryReadsTheDocumentAsTheModelDoes:
    def _write(self, output_dir, scanner_results):
        _write_aggregated(output_dir, {"scanner_results": scanner_results})

    def test_a_results_file_that_is_not_utf8_yields_the_empty_summary(self, tmp_path):
        (tmp_path / "ash_aggregated_results.json").write_bytes(b"\xff\xfe{ not text")

        summary = summarize_scanner_statuses(tmp_path)

        assert summary == {"scanner_statuses": {}, "skipped_scanners": []}

    def test_the_file_is_read_through_the_reader_that_retries_a_replace(
        self, tmp_path, monkeypatch
    ):
        self._write(tmp_path, {"semgrep": {"status": "MISSING"}})
        reads = []

        def reader(path):
            reads.append(Path(path).name)
            return Path(path).read_bytes().decode("utf-8")

        monkeypatch.setattr(scan_tracking, "_read_regular_file_text", reader)

        summary = summarize_scanner_statuses(tmp_path)

        assert reads == ["ash_aggregated_results.json"]
        assert [row["scanner"] for row in summary["skipped_scanners"]] == ["semgrep"]

    @pytest.mark.skipif(
        not hasattr(os, "O_NOFOLLOW"), reason="the platform has no O_NOFOLLOW"
    )
    def test_a_link_swapped_in_after_the_look_is_not_followed(
        self, tmp_path, monkeypatch
    ):
        """The look at the name and the read are two calls. The look is made to
        report a regular file while the name already holds a link to a document
        outside the output tree: the read by descriptor refuses the link, where
        a read by name returned the outside document's skipped scanners as this
        scan's."""
        outside = tmp_path / "outside.json"
        outside.write_text(
            json.dumps({"scanner_results": {"semgrep": {"status": "MISSING"}}}),
            encoding="utf-8",
        )
        output_dir = tmp_path / "ash_output"
        output_dir.mkdir()
        try:
            (output_dir / "ash_aggregated_results.json").symlink_to(outside)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f"symlinks cannot be made here: {error}")
        monkeypatch.setattr(
            scan_tracking, "is_regular_result_file", lambda *args, **kwargs: True
        )

        summary = summarize_scanner_statuses(output_dir)

        assert summary == {"scanner_statuses": {}, "skipped_scanners": []}

    def test_a_status_in_lower_case_is_read_as_its_member(self, tmp_path):
        self._write(
            tmp_path,
            {"semgrep": {"status": "missing", "dependencies_satisfied": False}},
        )

        summary = summarize_scanner_statuses(tmp_path)

        assert summary["skipped_scanners"] == [
            {
                "scanner": "semgrep",
                "status": "MISSING",
                "reason": "missing_dependencies",
            }
        ]

    def test_the_strings_false_and_true_are_read_as_booleans(self, tmp_path):
        self._write(
            tmp_path,
            {
                "checkov": {
                    "status": "SKIPPED",
                    "excluded": "false",
                    "dependencies_satisfied": "true",
                },
                "grype": {
                    "status": "MISSING",
                    "excluded": False,
                    "dependencies_satisfied": "false",
                },
            },
        )

        summary = summarize_scanner_statuses(tmp_path)

        reasons = {row["scanner"]: row["reason"] for row in summary["skipped_scanners"]}
        assert reasons == {"checkov": "skipped", "grype": "missing_dependencies"}
        assert summary["scanner_statuses"]["checkov"]["excluded"] is False

    def test_a_missing_scanner_with_its_dependencies_says_why_it_did_not_run(
        self, tmp_path
    ):
        self._write(
            tmp_path,
            {
                "bandit": {
                    "status": "MISSING",
                    "dependencies_satisfied": True,
                    "excluded": False,
                    "missing_reason": "left filtering with no status",
                }
            },
        )

        summary = summarize_scanner_statuses(tmp_path)

        assert summary["skipped_scanners"] == [
            {
                "scanner": "bandit",
                "status": "MISSING",
                "reason": "skipped",
                "detail": "left filtering with no status",
            }
        ]

    def test_a_skipped_scanner_with_no_recorded_reason_carries_no_detail(
        self, tmp_path
    ):
        self._write(tmp_path, {"bandit": {"status": "SKIPPED", "excluded": True}})

        summary = summarize_scanner_statuses(tmp_path)

        assert "detail" not in summary["skipped_scanners"][0]


class TestTheCompletedProgressInfoOnSparseDocuments:
    def test_null_containers_beside_a_sarif_do_not_raise(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {"sarif": {"runs": []}, "scanner_results": None, "metadata": None},
        )

        info = get_scan_progress_info(out)

        assert info["status"] == "completed"
        assert info["scanners_completed"] == []
        assert info["findings_count"] == 0
        assert info["summary_stats"] == {}

    def test_a_file_with_neither_results_nor_sarif_is_pending_not_completed(
        self, tmp_path
    ):
        out = tmp_path / "ash_output"
        _write_aggregated(out, {"metadata": {"generated_at": "2024-01-01T00:00:00"}})

        info = get_scan_progress_info(out)

        assert info["status"] == "in_progress"
        assert info["is_complete"] is False
        assert info["results_pending"] is True

    def test_the_summary_has_the_same_keys_running_and_completed(self, tmp_path):
        running = tmp_path / "running"
        _write_scanner_file(running, "bandit", "source", {"scanner_name": "bandit"})
        done = tmp_path / "done"
        _write_aggregated(
            done,
            {
                "metadata": {
                    "summary_stats": {
                        "severity_counts": {"high": 2, "suppressed": 1},
                        "total": 3,
                        "actionable": 2,
                    }
                },
                "scanner_results": {"bandit": {"status": "FAILED"}},
            },
        )

        in_progress = get_scan_progress_info(running)
        completed = get_scan_progress_info(done)

        assert set(completed["findings_summary"]) == set(
            in_progress["findings_summary"]
        )
        assert completed["findings_summary"]["high"] == 2
        assert completed["findings_summary"]["suppressed"] == 1
        # What the summary stats held beyond the buckets is still there.
        assert completed["summary_stats"]["actionable"] == 2

    def test_sarif_results_are_graded_and_a_suppressed_one_is_counted_as_suppressed(
        self, tmp_path
    ):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {
                "sarif": {
                    "runs": [
                        {
                            "results": [
                                {"ruleId": "B105", "level": "error"},
                                {
                                    "ruleId": "B303",
                                    "level": "error",
                                    "suppressions": [{"kind": "inSource"}],
                                },
                            ]
                        }
                    ]
                },
                "scanner_results": {"bandit": {"status": "FAILED"}},
            },
        )

        info = get_scan_progress_info(out)

        summary = info["findings_summary"]
        # findings_count is the non-suppressed count, SummaryStats' total, the
        # same quantity the running view reports; counted as every SARIF
        # result it read 2 here against 1 mid-scan for the same scanner.
        assert info["findings_count"] == 1
        assert summary["critical"] == 1
        assert summary["suppressed"] == 1
        assert summary["unknown"] == 0
        assert sum(summary.values()) == info["findings_count"] + summary["suppressed"]

    def test_the_completed_count_is_the_summary_stats_total_when_recorded(
        self, tmp_path
    ):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {
                "sarif": {
                    "runs": [
                        {
                            "results": [
                                {"ruleId": "B105", "level": "error"},
                                {
                                    "ruleId": "B303",
                                    "level": "error",
                                    "suppressions": [{"kind": "inSource"}],
                                },
                            ]
                        }
                    ]
                },
                "scanner_results": {"bandit": {"status": "FAILED"}},
                "metadata": {
                    "summary_stats": {
                        "total": 1,
                        "critical": 1,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                        "suppressed": 1,
                    }
                },
            },
        )

        info = get_scan_progress_info(out)

        assert info["findings_count"] == 1
        assert info["findings_summary"]["suppressed"] == 1


class TestTheAggregatedEntryIsReadAsThePerTargetFileIs:
    """One scanner, one reading of its counts, whichever file carries them.

    ``_add_aggregated_scanner_progress`` stored a scanner's ``severity_counts``
    as recorded and, for a null ``finding_count``, summed every bucket,
    suppressed included, where the per-target path reports the non-suppressed
    count; a bucket holding a string reached ``update_totals`` and its TypeError
    failed the whole document.
    """

    def test_a_null_count_beside_buckets_is_the_non_suppressed_sum(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {
                "scanner_results": {
                    "bandit": {
                        "status": "FAILED",
                        "finding_count": None,
                        "severity_counts": {"high": 1, "suppressed": 2},
                    }
                }
            },
        )

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.status == "completed"
        assert progress.scanners["bandit"]["source"].finding_count == 1
        assert progress.total_findings == 1
        assert progress.severity_counts["suppressed"] == 2

    def test_a_bucket_that_is_not_a_count_is_dropped_not_fatal(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {
                "scanner_results": {
                    "bandit": {
                        "status": "PASSED",
                        "finding_count": 1,
                        "severity_counts": {"high": "2", "low": 1},
                    }
                }
            },
        )

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.status == "completed"
        assert progress.error_message is None
        assert progress.severity_counts["low"] == 1
        assert progress.severity_counts["high"] == 0
        assert progress.total_findings == 1


class TestScannersCompletedReadsTheStatusAsTheRegistryViewDoes:
    """``get_scan_progress_info`` compared the recorded status as a string
    against two upper-case literals and read an absent one as UNKNOWN, while
    ``create_scan_progress_from_files`` reads it through
    ``scanner_status_from_results`` (absent is PASSED, case does not matter);
    ``{"bandit": {}}`` and ``{"status": "passed"}`` were one completed scanner
    in the registry's view and none here. ``summarize_scanner_statuses`` gave
    the raw status in ``scanner_statuses`` and the upper-cased one in
    ``skipped_scanners`` for the same scanner.
    """

    def test_an_absent_or_lower_case_status_is_a_completed_scanner(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {
                "scanner_results": {
                    "bandit": {},
                    "semgrep": {"status": "passed"},
                    "grype": {"status": "missing"},
                }
            },
        )

        info = get_scan_progress_info(out)

        assert info["status"] == "completed"
        assert info["scanners_completed"] == ["bandit", "semgrep"]
        assert info["total_scanners"] == 2

    def test_the_status_summary_reports_one_spelling(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {
                "scanner_results": {
                    "semgrep": {"status": "missing", "dependencies_satisfied": False}
                }
            },
        )

        summary = summarize_scanner_statuses(out)

        assert summary["scanner_statuses"]["semgrep"]["status"] == "MISSING"
        assert summary["skipped_scanners"][0]["status"] == "MISSING"


class TestPutBackResultsAreRefusedByTheProgressInfoToo:
    """``get_scan_progress_info`` checked ``holds_restored_results`` and only then
    parsed; a restore landing between the two returned the previous scan's
    results as completed. The restore writes its marker first and moves the
    previous results back after it, so the marker is there to see after the
    read: the same second look ``get_scan_results_with_error_handling`` takes."""

    def test_a_marker_written_after_the_first_check_is_seen(
        self, tmp_path, monkeypatch
    ):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {"scanner_results": {"bandit": {"status": "PASSED", "finding_count": 0}}},
        )
        real_parse = scan_tracking.parse_aggregated_results

        def parse_during_a_restore(output_dir):
            (Path(output_dir) / RESTORED_MARKER_NAME).write_text(
                "put back\n", encoding="utf-8"
            )
            return real_parse(output_dir)

        monkeypatch.setattr(
            scan_tracking, "parse_aggregated_results", parse_during_a_restore
        )

        info = get_scan_progress_info(out)

        assert info["status"] == "error"
        assert info["is_complete"] is False
        assert info["context"]["output_holds_previous_results"] is True

    def test_results_put_back_after_a_scan_that_ended_without_any_are_not_this_scans(
        self, tmp_path
    ):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {"scanner_results": {"bandit": {"status": "PASSED", "finding_count": 0}}},
        )
        (out / RESTORED_MARKER_NAME).write_text("put back\n", encoding="utf-8")

        info = get_scan_progress_info(out)

        assert info["status"] == "error"
        assert info["is_complete"] is False
        assert info["context"]["output_holds_previous_results"] is True
        assert info["context"]["error_category"] == "scan_incomplete"


class TestPutBackResultsAreRefusedWhenARestoreLandsDuringTheRead:
    def test_a_marker_written_after_the_first_check_refuses_the_results(
        self, tmp_path, monkeypatch
    ):
        out = tmp_path / "ash_output"
        _write_aggregated(
            out,
            {"scanner_results": {"bandit": {"status": "PASSED", "finding_count": 0}}},
        )

        def read_during_a_restore(output_dir, include_sarif=False):
            # The restore writes its marker, then moves the previous results back,
            # which is what this read returns.
            (Path(output_dir) / RESTORED_MARKER_NAME).write_text(
                "put back\n", encoding="utf-8"
            )
            return {"success": True, "status": "completed"}

        monkeypatch.setattr(scan_tracking, "get_scan_results", read_during_a_restore)

        response = get_scan_results_with_error_handling(out)

        assert response["success"] is False
        assert response["error_category"] == "scan_incomplete"
        assert response["context"]["output_holds_previous_results"] is True

    def test_results_with_no_marker_are_returned(self, tmp_path, monkeypatch):
        out = tmp_path / "ash_output"
        _write_aggregated(out, {"scanner_results": {}})
        monkeypatch.setattr(
            scan_tracking,
            "get_scan_results",
            lambda output_dir, include_sarif=False: {"success": True},
        )

        assert get_scan_results_with_error_handling(out) == {"success": True}
