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
import threading
from unittest.mock import MagicMock

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


def _symlink_or_skip(link, target):
    """Make ``link`` point at ``target``, or skip where links cannot be made.

    ``hasattr(os, "symlink")`` is true on Windows, where creating one still
    fails without the privilege (OSError, winerror 1314); a platform limit is
    a skip, not a failure of the behavior under test.
    """
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks are not available on this platform")
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"this platform refuses to create a symlink: {e}")


def _returns_within(seconds, function):
    """Run ``function`` on a thread and return its result, or fail at the bound.

    The FIFO tests below assert that a reader returns at all; a regression that
    opens the FIFO blocks forever, and a hung test is a slower, less legible
    failure than a timed one.
    """
    outcome = {}

    def run():
        try:
            outcome["value"] = function()
        except BaseException as e:  # noqa: BLE001 -- re-raised on the test thread
            outcome["error"] = e

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        pytest.fail(f"did not return within {seconds}s: the FIFO was opened")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


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
        _symlink_or_skip(link, other)

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
        # would never return, so returning at all is the assertion, and the
        # bound turns a regression into a failure instead of a hang.
        assert _returns_within(5, lambda: is_regular_result_file(fifo)) is False
        assert _returns_within(5, lambda: find_scanner_result_files(out)) == {}
        progress = _returns_within(
            5, lambda: create_scan_progress_from_files("scan-1", out)
        )
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
        _symlink_or_skip(out / "ash_aggregated_results.json", other)

        assert summarize_scanner_statuses(out)["scanner_statuses"] == {}
        with pytest.raises(MCPResourceError, match="not a regular file"):
            parse_aggregated_results(out)

    def test_a_fifo_at_the_aggregated_name_is_not_opened(self, tmp_path):
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFOs are not available on this platform")
        out = tmp_path / "ash_output"
        out.mkdir()
        os.mkfifo(out / "ash_aggregated_results.json")

        # Opening a FIFO with no writer blocks; returning at all is the
        # assertion, bounded so a regression fails instead of hanging.
        statuses = _returns_within(5, lambda: summarize_scanner_statuses(out))
        assert statuses["scanner_statuses"] == {}
        with pytest.raises(MCPResourceError, match="not a regular file"):
            _returns_within(5, lambda: parse_aggregated_results(out))

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
        # The patch above reaches every call only while scan_tracking resolves
        # the name through error_handling at call time; a module-level
        # from-import would bind its own name and the patch would see nothing.
        assert not hasattr(st, "safe_read_json_file")

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


class TestTheCompletedProgressInfoReadsTheFileOnce:
    """get_scan_progress_info parsed ash_aggregated_results.json twice per call,
    its own parse and then load_aggregated_results_model's, with no lock, so a
    scan that replaced the file in between gave the counts of one document
    beside the coverage of the next."""

    def test_one_parse_per_call(self, tmp_path, monkeypatch):
        import automated_security_helper.core.resource_management.scan_tracking as st

        out = tmp_path / "ash_output"
        out.mkdir()
        (out / "ash_aggregated_results.json").write_text(
            json.dumps(
                {
                    "scanner_results": {
                        "bandit": {"status": "PASSED"},
                        "semgrep": {"status": "FAILED"},
                    }
                }
            ),
            encoding="utf-8",
        )
        real_parse = st.parse_aggregated_results
        parses = []
        monkeypatch.setattr(
            st,
            "parse_aggregated_results",
            lambda *args, **kwargs: parses.append(args) or real_parse(*args, **kwargs),
        )
        # Counted below the module's own parser too: a second parse made by
        # load_aggregated_results_model, or by any other reader of the file,
        # would escape the patch above and be counted here.
        from automated_security_helper.core.resource_management import error_handling

        reads = []
        real_safe_read = error_handling.safe_read_json_file
        monkeypatch.setattr(
            error_handling,
            "safe_read_json_file",
            lambda *a, **k: reads.append(a) or real_safe_read(*a, **k),
        )

        info = get_scan_progress_info(out)

        assert info["status"] == "completed"
        assert info["coverage_complete"] is True
        assert len(parses) == 1
        assert len(reads) == 1
        assert not hasattr(st, "safe_read_json_file")


class TestTheReadIsTheCheck:
    """The regular-file check and the read are one descriptor.

    ``is_regular_result_file`` looks at the name (lstat) and the read followed by
    name, so a link or a FIFO swapped in between the two was followed or waited
    on, and a file that grew after the look was read in full past the bound. The
    document is now read through ``_read_result_file_bytes``: the name is opened
    without following a link and without blocking, the descriptor is fstat-ed,
    and at most the bound plus one byte is read from it. The tests make the look
    report what it would have before the swap, so the read is what decides.
    """

    def test_a_link_swapped_in_after_the_look_is_not_followed(
        self, tmp_path, monkeypatch
    ):
        import automated_security_helper.core.resource_management.scan_tracking as st

        if not hasattr(os, "O_NOFOLLOW"):
            pytest.skip("the platform has no O_NOFOLLOW")
        out = tmp_path / "ash_output"
        other = tmp_path / "other-tree.json"
        other.write_text(json.dumps({"status": "FAILED"}), encoding="utf-8")
        link = _target_dir(out, "bandit", "source") / _RESULTS_FILE
        _symlink_or_skip(link, other)
        monkeypatch.setattr(st, "is_regular_result_file", lambda *a, **k: True)

        # Red before: the reopen by name followed the link and returned the
        # other tree's document as this scan's.
        assert st._read_scanner_result_document(link) is None

    def test_a_file_grown_past_the_bound_after_the_look_is_not_read(
        self, tmp_path, monkeypatch
    ):
        import automated_security_helper.core.resource_management.scan_tracking as st

        out = tmp_path / "ash_output"
        path = _write_result(out, "bandit", "source", {"status": "PASSED"})
        path.write_text(
            json.dumps({"status": "PASSED", "pad": "x" * 200}), encoding="utf-8"
        )
        monkeypatch.setattr(st, "_SCANNER_RESULT_FILE_MAX_BYTES", 64)
        monkeypatch.setattr(st, "is_regular_result_file", lambda *a, **k: True)

        # Red before: the look said the file was within the bound and the read
        # by name then read the whole grown file.
        assert st._read_scanner_result_document(path) is None

    def test_a_fifo_at_the_name_is_refused_without_waiting(self, tmp_path):
        import automated_security_helper.core.resource_management.scan_tracking as st

        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFOs are not available on this platform")
        fifo = tmp_path / _RESULTS_FILE
        os.mkfifo(fifo)

        # A read-only open of a FIFO with no writer blocks without O_NONBLOCK;
        # with it the open returns and the fstat refuses what it opened.
        assert (
            _returns_within(5, lambda: st._read_result_file_bytes(fifo, None)) is None
        )

    def test_the_control_a_regular_file_within_the_bound_is_read(self, tmp_path):
        import automated_security_helper.core.resource_management.scan_tracking as st

        out = tmp_path / "ash_output"
        path = _write_result(out, "bandit", "source", {"status": "PASSED"})

        assert st._read_scanner_result_document(path) == {"status": "PASSED"}
        assert st._read_result_file_bytes(path, None) == path.read_bytes()


class TestAnUnreadableTargetIsNotACompletedTarget:
    """One file, one reading in every view.

    A per-target file that is not a JSON object yet (empty, truncated,
    mid-write) is a scanner that has not finished writing:
    ``create_scan_progress_from_files`` reports it as running. The per-scanner
    view listed the same target as completed from the file's presence, and the
    running progress info listed the scanner in ``scanners_completed``: the
    "completed before it wrote anything" reading in the other views.
    """

    def test_a_truncated_file_is_no_completed_target_in_any_view(self, tmp_path):
        out = tmp_path / "ash_output"
        path = _write_result(out, "bandit", "source", {"status": "PASSED"})
        path.write_text('{"scanner_name": "bandit", "sta', encoding="utf-8")

        view = get_scanner_progress(out)
        info = get_scan_progress_info(out)
        progress = create_scan_progress_from_files("scan-1", out)

        assert view["bandit"]["targets_completed"] == []
        assert view["bandit"]["targets_count"] == 0
        assert get_completed_scanners(out) == set()
        assert info["scanners_completed"] == []
        assert info["total_scanners"] == 1
        assert progress.scanner_status_counts["running"] == 1

    def test_a_scanner_with_one_finished_target_is_completed_by_that_target(
        self, tmp_path
    ):
        out = tmp_path / "ash_output"
        _write_result(out, "bandit", "source", {"status": "PASSED", "finding_count": 1})
        pending = _write_result(out, "bandit", "converted", {"status": "PASSED"})
        pending.write_text("", encoding="utf-8")

        view = get_scanner_progress(out)
        info = get_scan_progress_info(out)

        assert view["bandit"]["targets_completed"] == ["source"]
        assert view["bandit"]["targets_count"] == 1
        assert view["bandit"]["finding_count"] == 1
        assert get_completed_scanners(out) == {"bandit"}
        assert info["scanners_completed"] == ["bandit"]

    def test_a_result_file_left_out_of_the_view_is_said_once(
        self, tmp_path, monkeypatch
    ):
        """A link (or a FIFO, or a file past the bound) at a result name is left
        out of every view; it used to be left out in silence, so the scanner
        vanished. It is said once per process, not once per poll."""
        import automated_security_helper.core.resource_management.scan_tracking as st

        out = tmp_path / "ash_output"
        other = tmp_path / "other-tree.json"
        other.write_text(json.dumps({"status": "FAILED"}), encoding="utf-8")
        link = _target_dir(out, "bandit", "source") / _RESULTS_FILE
        _symlink_or_skip(link, other)
        monkeypatch.setattr(st, "_REPORTED_IRREGULAR_RESULT_FILES", set())
        logger = MagicMock()
        monkeypatch.setattr(st, "_logger", logger)

        assert find_scanner_result_files(out) == {}
        assert find_scanner_result_files(out) == {}

        assert logger.warning.call_count == 1
        assert str(link) in logger.warning.call_args[0][0]


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

        # "completed" is the file-based view's word for "the aggregated file
        # exists and parsed"; whether the scanners that ran are all the
        # scanners that were selected is the coverage signal beside it, the
        # one get_scan_results and the registry's progress view carry. Without
        # it this scan read as completed with fewer scanners while
        # get_scan_results called the same directory incomplete.
        assert info["status"] == "completed"
        assert info["scanners_completed"] == ["bandit", "semgrep"]
        assert info["total_scanners"] == 2
        assert info["coverage_complete"] is False
        assert "grype" in [row["scanner"] for row in info["incomplete_scanners"]]

    def test_the_recorded_word_is_read_as_the_results_model_reads_it(self, tmp_path):
        """An absent status is PASSED and the case does not matter (the
        results model's reading); ERROR is still not a scanner that ran to an
        end, as the test above says and get_scan_results counts. Reading the
        word through the registry's status mapping counted ERROR as FAILED
        and so as completed."""
        out = tmp_path / "ash_output"
        out.mkdir()
        (out / "ash_aggregated_results.json").write_text(
            json.dumps(
                {
                    "scanner_results": {
                        "bandit": {},
                        "semgrep": {"status": "passed"},
                        "checkov": {"status": "Failed"},
                        "trivy": {"status": "ERROR"},
                        "grype": {"status": None},
                    }
                }
            ),
            encoding="utf-8",
        )

        info = get_scan_progress_info(out)

        assert info["scanners_completed"] == ["bandit", "semgrep", "checkov"]
        assert info["total_scanners"] == 3

    def test_a_scan_whose_scanners_all_ran_reads_as_covered(self, tmp_path):
        out = tmp_path / "ash_output"
        out.mkdir()
        (out / "ash_aggregated_results.json").write_text(
            json.dumps(
                {
                    "scanner_results": {
                        "bandit": {"status": "PASSED"},
                        "semgrep": {"status": "FAILED"},
                    }
                }
            ),
            encoding="utf-8",
        )

        info = get_scan_progress_info(out)

        assert info["status"] == "completed"
        assert info["coverage_complete"] is True
        assert info["incomplete_scanners"] == []

    def test_an_unassessable_document_leaves_coverage_unknown(self, tmp_path):
        """A document the results model does not accept is still reported;
        coverage is None, never a guess either way."""
        out = tmp_path / "ash_output"
        out.mkdir()
        (out / "ash_aggregated_results.json").write_text(
            json.dumps({"scanner_results": {"bandit": {"status": "NOT_A_STATUS"}}}),
            encoding="utf-8",
        )

        info = get_scan_progress_info(out)

        assert info["status"] == "completed"
        assert info["coverage_complete"] is None
        assert info["incomplete_scanners"] == []


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

    def test_recorded_counts_win_over_a_findings_array(self, tmp_path):
        """One rule for both progress paths: the aggregated path reads the
        document's counts and uses findings only when the counts are missing
        (test_scan_tracking_results.py); the per-target path used to do the
        opposite, so one scanner showed different totals mid-scan and after
        aggregation."""
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

        assert progress.total_findings == 9
        assert progress.severity_counts["high"] == 9
        assert progress.severity_counts["low"] == 0
        assert get_scanner_progress(out)["bandit"]["finding_count"] == 9

    def test_a_findings_array_fills_in_when_the_document_has_no_counts(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_result(out, "bandit", "source", {"findings": [{"severity": "LOW"}]})

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.total_findings == 1
        assert progress.severity_counts["low"] == 1
        assert get_scanner_progress(out)["bandit"]["finding_count"] == 1

    def test_a_file_with_neither_counts_nor_findings_reads_as_zero(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_result(out, "bandit", "source", {"scanner_name": "bandit"})

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.total_findings == 0

    def test_the_count_mid_scan_is_the_count_after_aggregation(self, tmp_path):
        """The per-target file ASH writes counts suppressed findings in
        finding_count (the executor's total + suppressed); the aggregated file's
        per-scanner finding_count is ScannerMetrics.total, which leaves them out.
        Read verbatim, the scan's total dropped from 3 to 1 the moment the
        aggregated file appeared. Both views now report the non-suppressed count
        with suppressed as a bucket beside it, as SummaryStats does."""
        document = {
            "scanner_name": "bandit",
            "finding_count": 3,
            "severity_counts": {"high": 1, "suppressed": 2},
            "status": "FAILED",
        }
        running = tmp_path / "running"
        _write_result(running, "bandit", "source", document)

        progress = create_scan_progress_from_files("scan-1", running)
        view = get_scanner_progress(running)["bandit"]
        info = get_scan_progress_info(running)

        assert progress.total_findings == 1
        assert progress.severity_counts["high"] == 1
        assert progress.severity_counts["suppressed"] == 2
        assert view["finding_count"] == 1
        assert view["severity_counts"]["suppressed"] == 2
        assert info["findings_count"] == 1
        assert info["findings_summary"]["suppressed"] == 2

        done = tmp_path / "done"
        done.mkdir()
        (done / "ash_aggregated_results.json").write_text(
            json.dumps(
                {
                    "metadata": {"summary_stats": {}},
                    "scanner_results": {
                        "bandit": {
                            "status": "FAILED",
                            "finding_count": 1,
                            "severity_counts": {"high": 1, "suppressed": 2},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        aggregated = create_scan_progress_from_files("scan-1", done)

        assert aggregated.total_findings == progress.total_findings
        assert aggregated.severity_counts == progress.severity_counts

    @pytest.mark.parametrize(
        ("document", "expected_total", "expected_counts"),
        [
            pytest.param(
                {"finding_count": 3, "severity_counts": {"high": 1, "suppressed": 2}},
                1,
                {"high": 1, "suppressed": 2},
                id="the-suppressed-bucket-is-not-in-the-total",
            ),
            pytest.param(
                {"finding_count": 1, "severity_counts": {"suppressed": 2}},
                0,
                {"suppressed": 2},
                id="a-count-below-its-suppressed-bucket-reads-as-zero",
            ),
            pytest.param(
                {"finding_count": "3", "severity_counts": {"high": 3}},
                3,
                {"high": 3},
                id="string-finding_count-is-not-a-count-the-buckets-are-summed",
            ),
            pytest.param(
                {"finding_count": -1, "severity_counts": {"high": 2}},
                2,
                {"high": 2},
                id="negative-finding_count-is-not-a-count",
            ),
            pytest.param(
                {"severity_counts": {"high": 2, "suppressed": 4}},
                2,
                {"high": 2, "suppressed": 4},
                id="no-count-sums-the-buckets-without-the-suppressed-one",
            ),
            pytest.param(
                {"finding_count": 4, "severity_counts": ["high", "high"]},
                4,
                {"unknown": 4},
                id="non-dict-severity_counts-counts-under-unknown",
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
                {"high": 1, "low": 1, "unknown": 5},
                id="a-mismatched-sum-keeps-finding_count-and-grades-the-rest-unknown",
            ),
            pytest.param(
                {"finding_count": 3, "severity_counts": {}},
                3,
                {"unknown": 3},
                id="an-empty-bucket-object-grades-the-count-unknown",
            ),
            pytest.param(
                {"finding_count": 5, "severity_counts": {"high": 1, "suppressed": 2}},
                3,
                {"high": 1, "suppressed": 2, "unknown": 2},
                id="the-rest-is-counted-without-the-suppressed-bucket",
            ),
            pytest.param(
                {"finding_count": 2, "severity_counts": {"high": -5, "low": 2}},
                2,
                {"low": 2},
                id="a-negative-bucket-is-dropped",
            ),
            pytest.param(
                {
                    "finding_count": 1,
                    "severity_counts": {"high": 1, "total": 1, "actionable": 1},
                },
                1,
                {"high": 1},
                id="the-total-and-actionable-keys-are-not-buckets",
            ),
            pytest.param(
                {"finding_count": True, "severity_counts": {"high": True}},
                0,
                {},
                id="booleans-are-not-counts",
            ),
            pytest.param(
                {
                    "severity_counts": {},
                    "findings": [
                        {"severity": "HIGH"},
                        {"severity": "HIGH"},
                        {"severity": "LOW"},
                    ],
                },
                3,
                {"high": 2, "low": 1},
                id="an-empty-bucket-object-without-a-count-reads-the-findings",
            ),
            pytest.param(
                {
                    "severity_counts": {"high": "3"},
                    "findings": [{"severity": "MEDIUM"}, {"severity": "LOW"}],
                },
                2,
                {"medium": 1, "low": 1},
                id="buckets-that-are-all-unusable-without-a-count-read-the-findings",
            ),
        ],
    )
    def test_malformed_counts_are_read_defensively(
        self, tmp_path, document, expected_total, expected_counts
    ):
        """What a metadata-only file may carry and what the view makes of it.
        A finding_count that is not a non-negative int is no count, and the
        total then is the non-suppressed sum of the recorded buckets (as the
        aggregated path reads the same scanner), else the findings array
        (none here, so 0); a bucket whose value is not
        a non-negative int is dropped; a bucket name the model lacks lands in
        ``unknown``; and the recorded finding_count is the total even when the
        buckets do not sum to it (the scanner's record wins), less its own
        suppressed bucket, which the aggregated total leaves out too, with
        the part of it no bucket accounts for graded ``unknown``. A
        recorded count beside NO usable buckets is graded by the findings
        array and the rest lands in ``unknown`` (the module's rule: never in
        the total and in no bucket), as the aggregated path counts the same
        shape; it used to give total 4 with every bucket 0."""
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
