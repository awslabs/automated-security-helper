# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the file-based progress view reads, and what it counts.

Five mechanisms, each pinned against the behavior it replaced:

* ``summarize_scanner_statuses`` and ``parse_aggregated_results`` read
  ``ash_aggregated_results.json`` after an ``exists()`` or no check at all, so
  the link-following and FIFO-blocking shapes below reached that file too.

* ``find_scanner_result_files`` confined the scanner and target directories to
  the output directory but took the ``ASH.ScanResults.json`` entry itself on
  ``exists()``. A link at that name was followed into another tree, and a FIFO
  there blocked the progress poll, which runs under the registry lock, until
  something wrote to it.
* A scanner was listed, and so counted as completed, as soon as its directory
  existed, before it had written any result file.
* ``get_scan_progress_info`` listed every ``scanner_results`` entry as a
  completed scanner, MISSING, SKIPPED and ERROR included.
* The per-target file ASH writes carries ``finding_count`` and
  ``severity_counts`` and no findings array, so the file-based view reported 0
  findings and all-zero severity counts for every finished scanner while a scan
  ran.
"""

import json
import os

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    create_scan_progress_from_files,
    find_scanner_result_files,
    get_completed_scanners,
    get_scan_progress_info,
    get_scanner_progress,
    is_regular_result_file,
    parse_aggregated_results,
    summarize_scanner_statuses,
)

pytestmark = pytest.mark.unit

_RESULTS_FILE = "ASH.ScanResults.json"


def _target_dir(output_dir, scanner, target):
    path = output_dir / "scanners" / scanner / target
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_result(output_dir, scanner, target, document):
    path = _target_dir(output_dir, scanner, target) / _RESULTS_FILE
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class TestOnlyARegularResultFileIsRead:
    def test_a_regular_file_is_read(self, tmp_path):
        out = tmp_path / "ash_output"
        path = _write_result(out, "bandit", "source", {"status": "PASSED"})

        assert is_regular_result_file(path) is True
        assert find_scanner_result_files(out) == {"bandit": {"source": path}}

    def test_a_link_at_the_results_name_is_not_followed(self, tmp_path):
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        out = tmp_path / "ash_output"
        other = tmp_path / "other-tree.json"
        other.write_text(json.dumps({"status": "FAILED"}), encoding="utf-8")
        link = _target_dir(out, "bandit", "source") / _RESULTS_FILE
        link.symlink_to(other)

        assert is_regular_result_file(link) is False
        assert find_scanner_result_files(out) == {}
        assert get_completed_scanners(out) == set()

    def test_a_fifo_at_the_results_name_is_not_opened(self, tmp_path):
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFOs are not available on this platform")
        out = tmp_path / "ash_output"
        fifo = _target_dir(out, "bandit", "source") / _RESULTS_FILE
        os.mkfifo(fifo)

        # Reading a FIFO with no writer blocks; a progress view that opened it
        # would never return, so this returning at all is the assertion.
        assert is_regular_result_file(fifo) is False
        assert find_scanner_result_files(out) == {}
        progress = create_scan_progress_from_files("scan-1", out)
        assert progress.total_scanners == 0

    def test_a_missing_file_is_not_regular(self, tmp_path):
        assert is_regular_result_file(tmp_path / "absent.json") is False


class TestTheAggregatedResultsFileGetsTheSameGuard:
    """summarize_scanner_statuses and parse_aggregated_results read
    ash_aggregated_results.json under the registry lock; a FIFO or a link at
    that name reached their read_text as it reached the per-scanner readers."""

    def test_a_link_at_the_aggregated_name_is_not_read(self, tmp_path):
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        out = tmp_path / "ash_output"
        out.mkdir()
        other = tmp_path / "other.json"
        other.write_text(
            json.dumps({"scanner_results": {"bandit": {"status": "PASSED"}}}),
            encoding="utf-8",
        )
        (out / "ash_aggregated_results.json").symlink_to(other)

        assert summarize_scanner_statuses(out)["scanner_statuses"] == {}
        with pytest.raises(MCPResourceError, match="not a regular file"):
            parse_aggregated_results(out)

    def test_a_fifo_at_the_aggregated_name_is_not_opened(self, tmp_path):
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFOs are not available on this platform")
        out = tmp_path / "ash_output"
        out.mkdir()
        os.mkfifo(out / "ash_aggregated_results.json")

        # Opening a FIFO with no writer blocks; returning at all is the assertion.
        assert summarize_scanner_statuses(out)["scanner_statuses"] == {}
        with pytest.raises(MCPResourceError, match="not a regular file"):
            parse_aggregated_results(out)

    def test_a_large_regular_aggregated_file_is_still_read(self, tmp_path):
        """The per-scanner size bound does not apply to the aggregated file."""
        out = tmp_path / "ash_output"
        out.mkdir()
        padding = "x" * (17 * 1024 * 1024)
        (out / "ash_aggregated_results.json").write_text(
            json.dumps(
                {"scanner_results": {"bandit": {"status": "PASSED"}}, "pad": padding}
            ),
            encoding="utf-8",
        )

        assert "bandit" in summarize_scanner_statuses(out)["scanner_statuses"]
        assert "bandit" in parse_aggregated_results(out)["scanner_results"]


class TestEachResultFileIsReadOnceThroughTheGuard:
    """The file-based progress view read every ASH.ScanResults.json three times
    under the registry lock: once through safe_read_json_file, which has neither
    the regular-file check nor the size bound, and twice through the guarded
    reader for the counts and the status. One guarded read now feeds all three."""

    def test_the_progress_view_reads_each_file_once_and_never_unguarded(
        self, tmp_path, monkeypatch
    ):
        import automated_security_helper.core.resource_management.scan_tracking as st
        from automated_security_helper.core.resource_management import error_handling

        out = tmp_path / "ash_output"
        _write_result(out, "bandit", "source", {"status": "PASSED", "finding_count": 2})
        _write_result(out, "semgrep", "converted", {"status": "FAILED"})
        guarded = []
        real_read = st._read_scanner_result_document
        monkeypatch.setattr(
            st,
            "_read_scanner_result_document",
            lambda path: guarded.append(path) or real_read(path),
        )
        unguarded = []
        real_safe_read = error_handling.safe_read_json_file
        monkeypatch.setattr(
            error_handling,
            "safe_read_json_file",
            lambda *a, **k: unguarded.append(a) or real_safe_read(*a, **k),
        )

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.total_scanners == 2
        assert sorted(p.name for p in guarded) == [_RESULTS_FILE, _RESULTS_FILE]
        assert len(guarded) == 2
        assert unguarded == []

    def test_the_per_scanner_view_reads_each_file_once_too(self, tmp_path, monkeypatch):
        import automated_security_helper.core.resource_management.scan_tracking as st

        out = tmp_path / "ash_output"
        _write_result(out, "bandit", "source", {"status": "PASSED", "finding_count": 2})
        reads = []
        real_read = st._read_scanner_result_document
        monkeypatch.setattr(
            st,
            "_read_scanner_result_document",
            lambda path: reads.append(path) or real_read(path),
        )

        view = get_scanner_progress(out)

        assert view["bandit"]["finding_count"] == 2
        assert len(reads) == 1


class TestCompletedScannersAreTheOnesThatRan:
    def test_missing_skipped_and_error_scanners_are_not_completed(self, tmp_path):
        out = tmp_path / "ash_output"
        out.mkdir()
        (out / "ash_aggregated_results.json").write_text(
            json.dumps(
                {
                    "scanner_results": {
                        "bandit": {"status": "PASSED"},
                        "semgrep": {"status": "FAILED"},
                        "grype": {"status": "MISSING"},
                        "checkov": {"status": "SKIPPED"},
                        "trivy": {"status": "ERROR"},
                    }
                }
            ),
            encoding="utf-8",
        )

        info = get_scan_progress_info(out)

        assert info["status"] == "completed"
        assert info["scanners_completed"] == ["bandit", "semgrep"]
        assert info["total_scanners"] == 2


class TestTheFileBasedViewCountsWhatTheScannerRecorded:
    def test_a_metadata_only_file_yields_its_recorded_counts(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_result(
            out,
            "detect-secrets",
            "source",
            {
                "scanner_name": "detect-secrets",
                "target_type": "source",
                "finding_count": 3,
                "severity_counts": {"critical": 1, "HIGH": 2},
                "status": "FAILED",
            },
        )

        progress = create_scan_progress_from_files("scan-1", out)

        scanner = progress.scanners["detect-secrets"]["source"]
        assert scanner.finding_count == 3
        assert scanner.severity_counts["critical"] == 1
        assert scanner.severity_counts["high"] == 2
        assert progress.total_findings == 3
        assert progress.severity_counts["critical"] == 1
        assert progress.severity_counts["high"] == 2
        assert scanner.status.value == "failed"

    def test_a_findings_array_still_decides_when_present(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_result(
            out,
            "bandit",
            "source",
            {
                "findings": [{"severity": "LOW"}],
                "finding_count": 9,
                "severity_counts": {"high": 9},
            },
        )

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.total_findings == 1
        assert progress.severity_counts["low"] == 1
        assert progress.severity_counts["high"] == 0

    def test_a_file_with_neither_counts_nor_findings_reads_as_zero(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_result(out, "bandit", "source", {"scanner_name": "bandit"})

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.total_findings == 0

    @pytest.mark.parametrize(
        ("document", "expected_total", "expected_counts"),
        [
            pytest.param(
                {"finding_count": "3", "severity_counts": {"high": 3}},
                0,
                {"high": 3},
                id="string-finding_count-is-not-a-count-the-buckets-still-are",
            ),
            pytest.param(
                {"finding_count": -1, "severity_counts": {"high": 2}},
                0,
                {"high": 2},
                id="negative-finding_count-is-not-a-count",
            ),
            pytest.param(
                {"finding_count": 4, "severity_counts": ["high", "high"]},
                4,
                {},
                id="non-dict-severity_counts-yields-no-buckets",
            ),
            pytest.param(
                {"finding_count": 2, "severity_counts": {"high": 1, "weird": 1}},
                2,
                {"high": 1, "unknown": 1},
                id="an-unknown-bucket-is-counted-as-unknown",
            ),
            pytest.param(
                {"finding_count": 7, "severity_counts": {"high": 1, "low": 1}},
                7,
                {"high": 1, "low": 1},
                id="a-mismatched-sum-keeps-finding_count-as-the-total",
            ),
            pytest.param(
                {"finding_count": 2, "severity_counts": {"high": -5, "low": 2}},
                2,
                {"low": 2},
                id="a-negative-bucket-is-dropped",
            ),
            pytest.param(
                {"finding_count": True, "severity_counts": {"high": True}},
                0,
                {},
                id="booleans-are-not-counts",
            ),
        ],
    )
    def test_malformed_counts_are_read_defensively(
        self, tmp_path, document, expected_total, expected_counts
    ):
        """What a metadata-only file may carry and what the view makes of it.
        A finding_count that is not a non-negative int is no count, and the
        total then falls back to the findings array (none here, so 0), never
        to this view's arithmetic over the buckets; a bucket whose value is not
        a non-negative int is dropped; a bucket name the model lacks lands in
        ``unknown``; and the recorded finding_count is the total even when the
        buckets do not sum to it (the scanner's record wins)."""
        out = tmp_path / "ash_output"
        _write_result(out, "bandit", "source", {"scanner_name": "bandit", **document})

        progress = create_scan_progress_from_files("scan-1", out)
        view = get_scanner_progress(out)["bandit"]

        assert progress.total_findings == expected_total
        assert view["finding_count"] == expected_total
        for bucket, value in expected_counts.items():
            assert progress.severity_counts[bucket] == value
            assert view["severity_counts"][bucket] == value
        assert sum(progress.severity_counts.values()) == sum(expected_counts.values())
