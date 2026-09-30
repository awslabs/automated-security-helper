# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A readable results file means results exist. It does not mean the scan succeeded.

WHY THIS EXISTS
---------------
``check_scan_progress`` marked the registry entry completed whenever
``ash_aggregated_results.json`` parsed, whatever state the entry was in. A scan its
runner had marked FAILED or CANCELLED therefore came back ``completed``, and the
runner's reason was dropped from the answer. The runner's terminal status now stands,
and the file's scanners stay readable as partial results.

The runner also has to be able to close its entry at all. ``run_ash_scan`` ends with
``sys.exit`` on a non-zero verdict and on the errors it handles itself.
``SystemExit`` is not an ``Exception``, so it escaped ``_run_scan_async`` and left the
entry RUNNING for good: listed as active, blocking the next scan of that directory,
and never carrying the failure.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)

RESULTS_FILE = "ash_aggregated_results.json"
SCANNERS = ("bandit", "semgrep")
DOCUMENT = {
    "scanner_results": {
        name: {"status": "PASSED", "finding_count": 0} for name in SCANNERS
    }
}


def _registered_with_a_readable_file(tmp_path: Path):
    output_dir = tmp_path / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    (output_dir / RESULTS_FILE).write_text(json.dumps(DOCUMENT), encoding="utf-8")
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(output_dir)
    )
    return registry, scan_id


@pytest.mark.parametrize(
    "status,reason",
    [
        (MCScanStatus.FAILED, "scanner crashed"),
        (MCScanStatus.CANCELLED, None),
    ],
    ids=["failed", "cancelled"],
)
def test_a_readable_file_does_not_turn_a_closed_scan_into_a_completed_one(
    tmp_path, status, reason
):
    registry, scan_id = _registered_with_a_readable_file(tmp_path)
    registry.update_scan_status(scan_id, status, reason)

    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == status.value, (
        f"A scan its runner marked {status.value} was reported as "
        f"{progress['status']!r} because its results file parses."
    )
    assert registry.get_scan(scan_id).status is status
    assert progress["is_complete"] is True
    if reason is not None:
        assert progress["error_message"] == reason
    # The partial results stay readable.
    assert set(progress["scanners"]) == set(SCANNERS)


def test_an_unclaimed_entry_still_takes_its_status_from_the_file(tmp_path):
    """Control: the file-derived completion the integration suite pins is unchanged."""
    registry, scan_id = _registered_with_a_readable_file(tmp_path)

    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == "completed"
    assert set(progress["scanners"]) == set(SCANNERS)


@pytest.mark.parametrize(
    "code,expected",
    [(1, MCScanStatus.FAILED), (0, MCScanStatus.COMPLETED)],
    ids=["nonzero_exit", "zero_exit"],
)
def test_a_scan_ending_in_sys_exit_closes_its_entry(tmp_path, code, expected):
    from automated_security_helper.cli.mcp_tools import _run_scan_async

    (tmp_path / "out").mkdir()
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(tmp_path / "out")
    )

    with (
        patch(
            "automated_security_helper.cli.mcp_tools.get_scan_registry",
            return_value=registry,
        ),
        patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_scan",
            side_effect=SystemExit(code),
        ),
    ):
        asyncio.run(
            _run_scan_async(
                scan_id=scan_id,
                directory_path=str(tmp_path),
                output_dir=str(tmp_path / "out"),
                severity_threshold="MEDIUM",
            )
        )

    entry = registry.get_scan(scan_id)
    assert entry.status is expected
    assert not entry.is_active()
    if expected is MCScanStatus.FAILED:
        assert entry.error_message == f"ASH exited with code {code}"
