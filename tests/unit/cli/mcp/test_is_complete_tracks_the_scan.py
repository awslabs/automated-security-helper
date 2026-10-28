# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``is_complete`` says whether the scan has ended, from the scan's own state.

Why this file exists
--------------------
``run_ash_scan``'s description, its ``important.next_steps`` and the
``get_scan_progress`` usage pattern all tell a client to poll until
``is_complete`` is true. Computed as "the status is completed or incomplete, or a
results file exists on disk", it would never be true for a cancelled scan, or one
that failed before writing results, and a client following the server's own
advice would poll it forever. Whether a failed or cancelled scan reported it would
also depend on a file that can be a previous scan's.

``is_complete`` is true exactly when the scan has ended: completed,
incomplete, failed or cancelled, read from the registry entry and nothing else.
``results_available`` is the separate answer to "can get_scan_results read this
scan's results", true for completed and incomplete only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    get_scan_registry,
)


@pytest.fixture(autouse=True)
def _allowed(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)


def _scan(tmp_path: Path, name: str, stale_results: bool = False) -> str:
    source = tmp_path / name
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    if stale_results:
        # A previous scan's results, still on disk.
        (output / "ash_aggregated_results.json").write_text(
            json.dumps({"scanner_results": {"bandit": {"status": "PASSED"}}}),
            encoding="utf-8",
        )
    return get_scan_registry().register_scan(
        directory_path=str(source), output_directory=str(output)
    )


async def _progress(scan_id: str) -> Dict[str, Any]:
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    progress = await mcp_server.get_scan_progress(ctx, scan_id)
    assert progress.get("success") is not False, progress
    return progress


def _assert_state(progress: Dict[str, Any], status: str, ended: bool, readable: bool):
    assert (progress["status"], progress["is_complete"]) == (status, ended), (
        f"a {status} scan reports is_complete={progress['is_complete']}"
    )
    assert progress.get("results_available") is readable, progress


@pytest.mark.asyncio
class TestEveryEndedScanIsComplete:
    async def test_a_cancelled_scan(self, tmp_path):
        scan_id = _scan(tmp_path, "a")
        get_scan_registry().update_scan_status(scan_id, MCScanStatus.RUNNING)
        get_scan_registry().cancel_scan(scan_id)

        _assert_state(await _progress(scan_id), "cancelled", True, False)

    async def test_a_failed_scan_with_no_results(self, tmp_path):
        scan_id = _scan(tmp_path, "b")
        get_scan_registry().update_scan_status(scan_id, MCScanStatus.RUNNING)
        get_scan_registry().finish_scan(scan_id, MCScanStatus.FAILED, "crashed")

        _assert_state(await _progress(scan_id), "failed", True, False)

    async def test_a_failed_scan_beside_a_previous_scans_results(self, tmp_path):
        """The file on disk is not this scan's results."""
        scan_id = _scan(tmp_path, "c", stale_results=True)
        get_scan_registry().update_scan_status(scan_id, MCScanStatus.RUNNING)
        get_scan_registry().finish_scan(scan_id, MCScanStatus.FAILED, "crashed")

        _assert_state(await _progress(scan_id), "failed", True, False)

    async def test_a_completed_scan(self, tmp_path):
        scan_id = _scan(tmp_path, "d", stale_results=True)
        get_scan_registry().update_scan_status(scan_id, MCScanStatus.RUNNING)
        get_scan_registry().finish_scan(scan_id, MCScanStatus.COMPLETED)

        _assert_state(await _progress(scan_id), "completed", True, True)


@pytest.mark.asyncio
async def test_a_running_scan_is_not_complete_whatever_is_on_disk(tmp_path):
    scan_id = _scan(tmp_path, "e", stale_results=True)
    get_scan_registry().update_scan_status(scan_id, MCScanStatus.RUNNING)

    _assert_state(await _progress(scan_id), "running", False, False)


def test_the_poll_loop_the_server_documents_ends_on_every_ending():
    """The usage pattern in get_scan_progress's description stops on is_complete."""
    doc = mcp_server.get_scan_progress.__doc__ or ""
    assert "is_complete" in doc
    assert "cancelled" in doc
    assert "stays False" not in doc and "does not flip" not in doc


def test_the_scan_start_example_stops_on_is_complete():
    """run_ash_scan's example used to break on a hard-coded status tuple: a
    status added later would make a client that copied the example poll that
    scan forever. The example stops on is_complete, the one stop predicate its
    own prose and the start payload give. get_scan_progress's reason to poll
    is updates, not keeping anything alive: the scan continues server-side
    whether or not anything polls, and only the session that started it can
    read it."""
    doc = mcp_server.run_ash_scan.__doc__ or ""
    assert "if progress.get('is_complete')" in doc
    assert "('completed', 'incomplete', 'failed', 'cancelled')" not in doc
    progress_doc = mcp_server.get_scan_progress.__doc__ or ""
    assert "Keep the MCP connection alive" not in progress_doc
    assert "independently of the client connection" in progress_doc


@pytest.mark.asyncio
async def test_the_scan_start_guidance_stops_on_is_complete_for_every_ending(
    tmp_path, monkeypatch
):
    """The guidance a started scan returns uses the stop predicate this file pins.

    run_ash_scan's ``important`` payload tells the client when to stop polling,
    in ``connection_management`` and again in a ``next_steps`` item. Until now
    only the lifecycle snapshots held that text, so a reworded stop sentence
    moved snapshot cells without any unit cell saying which wording is the
    contract. This cell says it: both texts stop on ``is_complete`` -- true for
    every ending, cancelled included, per the cells above -- and both name all
    four endings, so neither can regress to a predicate a cancelled or failed
    scan never satisfies.
    """
    source = tmp_path / "guided"
    source.mkdir()
    monkeypatch.setattr(
        mcp_server,
        "mcp_scan_directory",
        AsyncMock(return_value={"success": True, "scan_id": "scan-under-test"}),
    )
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    ctx = MagicMock(spec=Context)
    ctx.headers = {}

    started = await mcp_server.run_ash_scan(ctx, source_dir=str(source))

    assert started.get("success") is True, started
    guidance = started["important"]
    endings = ("completed", "incomplete", "failed", "cancelled")

    connection = guidance["connection_management"]
    assert re.search(r"\bStop when is_complete is true\b", connection), connection
    for ending in endings:
        assert ending in connection, (ending, connection)

    stop_steps = [s for s in guidance["next_steps"] if "is_complete" in s]
    assert len(stop_steps) == 1, guidance["next_steps"]
    assert re.search(r"\bStop polling when is_complete is true\b", stop_steps[0]), (
        stop_steps[0]
    )
    for ending in endings:
        assert ending in stop_steps[0], (ending, stop_steps[0])

    for text in (connection, *guidance["next_steps"]):
        assert "stays False" not in text and "is_complete alone" not in text, text
