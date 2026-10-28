# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``finished_scanners`` counts every scanner that has finished, whatever its status.

Why this file exists
--------------------
``get_scan_progress`` returns ``completed_scanners`` and ``total_scanners``, and
the agent plugins tell clients to show the scan's progress from them.
``completed_scanners`` counts only scanners that reported PASSED (its meaning
since #640, which these tests keep), so shown as the progress, a scan in which a
scanner FAILED (found something), errored or was MISSING would never reach 100%:
a finished scan with findings would read as stuck.

``finished_scanners`` is the progress count: every scanner that has finished
(PASSED, FAILED, ERROR, MISSING or SKIPPED). ``scanner_status_counts`` breaks the
scanners down by status: ``passed`` is PASSED, ``failed`` is FAILED or ERROR,
``skipped`` is MISSING or SKIPPED, and ``running`` and ``pending`` are scanners
not finished yet. The plugins show ``finished_scanners / total_scanners``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    get_scan_registry,
)

STATUSES = {
    "bandit": "PASSED",
    "checkov": "FAILED",
    "grype": "ERROR",
    "semgrep": "MISSING",
    "syft": "SKIPPED",
}


@pytest.fixture(autouse=True)
def _allowed(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)


def _register(tmp_path: Path) -> tuple[str, Path]:
    source = tmp_path / "project"
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    scan_id = get_scan_registry().register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    get_scan_registry().update_scan_status(scan_id, MCScanStatus.RUNNING)
    return scan_id, output


async def _progress(scan_id: str) -> Dict[str, Any]:
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    progress = await mcp_server.get_scan_progress(ctx, scan_id)
    assert progress.get("success") is not False, progress
    return progress


@pytest.mark.asyncio
async def test_a_finished_scan_counts_every_scanner_as_finished_and_passed_ones_as_completed(
    tmp_path,
):
    scan_id, output = _register(tmp_path)
    (output / "ash_aggregated_results.json").write_text(
        json.dumps(
            {
                "scanner_results": {
                    name: {"status": status} for name, status in STATUSES.items()
                }
            }
        ),
        encoding="utf-8",
    )
    get_scan_registry().finish_scan(scan_id, MCScanStatus.COMPLETED)

    progress = await _progress(scan_id)

    assert (progress["finished_scanners"], progress["total_scanners"]) == (5, 5), (
        "a finished scan with a FAILED, an ERROR, a MISSING and a SKIPPED scanner "
        f"reports {progress['finished_scanners']} of {progress['total_scanners']} "
        "scanners finished"
    )
    # Unchanged: the scanners that ran and PASSED.
    assert progress["completed_scanners"] == 1
    assert progress["scanner_status_counts"] == {
        "passed": 1,
        "failed": 2,
        "skipped": 2,
        "running": 0,
        "pending": 0,
    }


@pytest.mark.asyncio
async def test_while_running_each_scanner_is_counted_by_the_status_it_wrote(tmp_path):
    """Before the aggregated file exists, each scanner's own results file says."""
    scan_id, output = _register(tmp_path)
    for name, status in (("bandit", "PASSED"), ("grype", "ERROR")):
        target = output / "scanners" / name / "source"
        target.mkdir(parents=True)
        (target / "ASH.ScanResults.json").write_text(
            json.dumps({"scanner_name": name, "status": status, "finding_count": 0}),
            encoding="utf-8",
        )

    progress = await _progress(scan_id)

    assert progress["status"] == "running"
    assert progress["finished_scanners"] == 2
    assert progress["completed_scanners"] == 1
    assert progress["scanner_status_counts"]["passed"] == 1
    assert progress["scanner_status_counts"]["failed"] == 1
