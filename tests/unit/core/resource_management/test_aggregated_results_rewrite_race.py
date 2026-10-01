# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_scan_progress must not lose its scanners while the results file is rewritten.

WHY THIS EXISTS
---------------
``ash_aggregated_results.json`` is the scan's completion signal and the source of
``get_scan_progress``'s per-scanner section. It used to be written with a truncating
``open(path, "w")``, twice per scan: once by the SCAN phase, and again by
``_run_local_mode`` after the REPORT phase had already written ``ash.sarif`` and
``ash.flat.json``. A progress read landing inside either write found a file that
existed and did not parse. ``create_scan_progress_from_files`` treated that as a
failed parse, the registry overrode the status back to ``completed``, and the client
got ``status: completed`` with ``scanners: {}``.

That is what failed ``test_the_scan_examined_something_rather_than_skipping_every_scanner``
in the integration suite on one CI run and passed on every other run of the same
code: its fixture re-reads progress as soon as the two reports exist, which is exactly
when ``_run_local_mode`` truncates the aggregated file and rewrites 1 MB into it.
Measured before the fix with the reader below: 887 of 942 overlapping reads came back
completed-with-no-scanners.

HOW IT IS MEASURED
------------------
A reader thread calls the real ``ScanRegistry.check_scan_progress`` in a loop while the
main thread repeatedly runs the real writer. The file is padded to about 1 MB, the size
a real scan of a two-line tree produces, so each write takes long enough to overlap.
The overlap is asserted, not assumed: a run in which the reader never read during a
write would pass on the old code too, so ``MIN_OVERLAPPING_READS`` makes that a failure.
After the fix every read sees the old complete file or the new one, so this is
deterministic in the direction that matters: it cannot fail on correct code.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Callable, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.utils.atomic_write import write_text_atomically

SCANNER_NAMES = ("bandit", "detect-secrets", "semgrep")
PAD_BYTES = 1_000_000
MIN_OVERLAPPING_READS = 20
MAX_REWRITES = 400
TIME_BUDGET_SECONDS = 60.0


def _results() -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.scanner_results = {
        name: ScannerTargetStatusInfo(status=ScannerStatus.PASSED)
        for name in SCANNER_NAMES
    }
    model.additional_reports = {"pad": "x" * PAD_BYTES}
    return model


def _hammer(
    registry: ScanRegistry, scan_id: str, rewrite: Callable[[], None]
) -> Tuple[int, List[dict]]:
    """Rewrite repeatedly under a concurrent progress reader.

    Returns the number of reads that overlapped the rewrites and every read that
    reported a completed scan with no per-scanner entries.
    """
    stop = threading.Event()
    reads = [0]
    empty: List[dict] = []
    errors: List[BaseException] = []

    def reader() -> None:
        try:
            while not stop.is_set():
                progress = registry.check_scan_progress(scan_id)
                reads[0] += 1
                if progress["is_complete"] and not progress["scanners"]:
                    empty.append(progress)
        except BaseException as exc:  # surfaced below rather than lost in the thread
            errors.append(exc)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    deadline = time.monotonic() + TIME_BUDGET_SECONDS
    try:
        for _ in range(MAX_REWRITES):
            rewrite()
            if reads[0] >= MIN_OVERLAPPING_READS * 5 or time.monotonic() > deadline:
                break
    finally:
        stop.set()
        thread.join(timeout=30)
    if errors:
        raise errors[0]
    return reads[0], empty


def _registered_scan(tmp_path: Path) -> Tuple[ScanRegistry, str, Path]:
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    _results().save_model(output_dir)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(output_dir)
    )
    # Control: a settled file yields every scanner, so an empty read below is the
    # rewrite's doing and not a fixture that never had scanners in it.
    settled = registry.check_scan_progress(scan_id)
    assert settled["status"] == "completed"
    assert set(settled["scanners"]) == set(SCANNER_NAMES)
    return registry, scan_id, output_dir


def _assert_no_empty_reads(reads: int, empty: List[dict], writer: str) -> None:
    assert reads >= MIN_OVERLAPPING_READS, (
        f"Only {reads} progress reads overlapped the {writer} rewrites, too few for "
        "this test to have measured anything."
    )
    assert not empty, (
        f"{len(empty)} of {reads} progress reads taken while {writer} rewrote "
        "ash_aggregated_results.json reported a completed scan with no scanners. A "
        "reader saw the file between truncation and the end of the write. First: "
        f"status={empty[0]['status']!r} scanners={empty[0]['scanners']!r}"
    )


def test_progress_keeps_its_scanners_while_run_ash_scan_rewrites_the_results(
    tmp_path: Path,
) -> None:
    """The rewrite after the REPORT phase, which is the one the CI failure hit."""
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _run_local_mode,
    )

    registry, scan_id, output_dir = _registered_scan(tmp_path)
    opts = ScanOptions(source_dir=tmp_path, output_dir=output_dir)
    orchestrator = MagicMock()
    orchestrator.execute_scan.return_value = _results()
    orchestrator.config.fail_on_findings = True

    with patch(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
        return_value=orchestrator,
    ):
        reads, empty = _hammer(
            registry, scan_id, lambda: _run_local_mode(opts, MagicMock())
        )

    _assert_no_empty_reads(reads, empty, "_run_local_mode")


def test_progress_keeps_its_scanners_while_save_model_rewrites_the_results(
    tmp_path: Path,
) -> None:
    """The SCAN phase's write, the first moment the file exists at all."""
    registry, scan_id, output_dir = _registered_scan(tmp_path)
    model = _results()

    reads, empty = _hammer(registry, scan_id, lambda: model.save_model(output_dir))

    _assert_no_empty_reads(reads, empty, "save_model")


def test_an_atomic_write_leaves_no_staging_file_behind(tmp_path: Path) -> None:
    target = tmp_path / "ash_aggregated_results.json"
    target.write_text("old", encoding="utf-8")

    write_text_atomically(target, "new")

    assert target.read_text(encoding="utf-8") == "new"
    assert sorted(p.name for p in tmp_path.iterdir()) == [target.name]


def test_a_failed_atomic_write_keeps_the_old_file_and_removes_the_staging_file(
    tmp_path: Path,
) -> None:
    target = tmp_path / "ash_aggregated_results.json"
    target.write_text("old", encoding="utf-8")

    with patch(
        "automated_security_helper.utils.atomic_write.os.replace",
        side_effect=OSError("disk full"),
    ):
        with pytest.raises(OSError, match="disk full"):
            write_text_atomically(target, "new")

    assert target.read_text(encoding="utf-8") == "old"
    assert sorted(p.name for p in tmp_path.iterdir()) == [target.name]


class _SharingViolationOnOpen:
    """Fail the first ``failures`` opens of one file the way Windows does mid-replace.

    ``os.replace`` on Windows holds the file without read sharing while it swaps it,
    and a reader's open in that window raises ``PermissionError`` (errno 13). That is
    what the race tests above hit on the Windows legs. Both ``builtins.open`` and
    ``io.open`` are wrapped so the fault reaches the reader whichever one it calls.
    """

    def __init__(self, target: Path, failures: int) -> None:
        self.target = Path(target)
        self.remaining = failures
        self.opens_of_target = 0
        self._real_open = io.open

    def __call__(self, file, *args, **kwargs):
        if isinstance(file, (str, os.PathLike)) and Path(file) == self.target:
            self.opens_of_target += 1
            if self.remaining > 0:
                self.remaining -= 1
                raise PermissionError(13, "Permission denied", str(file))
        return self._real_open(file, *args, **kwargs)

    def installed(self):
        stack = contextlib.ExitStack()
        stack.enter_context(patch("builtins.open", self))
        stack.enter_context(patch("io.open", self))
        stack.enter_context(
            patch("automated_security_helper.utils.atomic_write.time.sleep")
        )
        return stack


def _results_file(tmp_path: Path) -> Path:
    target = tmp_path / "ash_aggregated_results.json"
    target.write_text(json.dumps({"scanner_results": {"bandit": {}}}), "utf-8")
    return target


def test_a_windows_read_that_lands_inside_a_replace_is_retried(tmp_path: Path) -> None:
    """The reader half of the race: a transient sharing violation is not a bad file."""
    from automated_security_helper.core.resource_management.error_handling import (
        safe_read_json_file,
    )

    target = _results_file(tmp_path)
    fault = _SharingViolationOnOpen(target, failures=3)

    with fault.installed(), patch.object(sys, "platform", "win32"):
        data, error = safe_read_json_file(target)

    assert error is None, error
    assert data == {"scanner_results": {"bandit": {}}}
    # Control: the fault fired three times, so the read was retried, not unaffected.
    assert fault.opens_of_target == 4


def test_a_windows_file_that_stays_unreadable_is_still_an_error(tmp_path: Path) -> None:
    """The retry is bounded, so a real permission problem is reported, only later."""
    from automated_security_helper.core.resource_management.error_handling import (
        safe_read_json_file,
    )
    from automated_security_helper.utils.atomic_write import _REPLACE_ATTEMPTS

    target = _results_file(tmp_path)
    fault = _SharingViolationOnOpen(target, failures=10_000)

    with fault.installed(), patch.object(sys, "platform", "win32"):
        data, error = safe_read_json_file(target)

    assert data is None
    assert error is not None and "Permission denied" in str(error)
    # A read error, not a parse error: the file was never read, so nothing about
    # its contents is known.
    assert error.context["error_category"] == "permission_denied"
    assert fault.opens_of_target == _REPLACE_ATTEMPTS


def test_a_posix_permission_error_is_not_retried(tmp_path: Path) -> None:
    from automated_security_helper.core.resource_management.error_handling import (
        safe_read_json_file,
    )

    target = _results_file(tmp_path)
    fault = _SharingViolationOnOpen(target, failures=1)

    with fault.installed(), patch.object(sys, "platform", "linux"):
        data, error = safe_read_json_file(target)

    assert data is None
    assert error is not None and "Permission denied" in str(error)
    # A read error, not a parse error: the file was never read, so nothing about
    # its contents is known.
    assert error.context["error_category"] == "permission_denied"
    assert fault.opens_of_target == 1


def test_an_atomic_write_gets_the_same_mode_as_a_plain_write(tmp_path: Path) -> None:
    """Not 0600. A container writes these files and a host user has to read them."""
    plain = tmp_path / "plain.json"
    plain.write_text("x", encoding="utf-8")
    atomic = tmp_path / "atomic.json"

    write_text_atomically(atomic, "x")

    assert atomic.stat().st_mode == plain.stat().st_mode
