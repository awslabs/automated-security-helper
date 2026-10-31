# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A single scan decides whether to name process ids by the caller, as a workspace scan does.

A workspace scan names the tools a cancel could not end, and withholds their
process ids from a remote client, by ``caller_is_remote(session_id)``. The single
scan decided by ``transport_is_networked()`` alone, which is process-wide: a
caller with a real session id on a transport the operator did not mark as
networked was remote for the workspace tool and local for this one, so the entry
kept the server's process ids in its warning and ``get_scan_progress`` returned
them to that caller.

The runner is driven over a stand-in scan, as in the sibling test of the tools a
cancel could not end. Nothing is started: the scan is the stand-in defined here and
the output directory is the test's own tmp_path.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.cancellation import (
    current_cancel_event,
    raise_if_cancelled,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"
SETTLE_SECONDS = 30.0
TIMEOUT_REASON = "Scan exceeded the server's limit and was cancelled"


def _registered(tmp_path: Path, monkeypatch) -> tuple[ScanRegistry, str, Path]:
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    output_dir = tmp_path / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(output_dir)
    )
    return registry, scan_id, output_dir


async def _stop_one_tool_and_read_the_entry(
    tmp_path: Path, monkeypatch, session_id: Any
):
    registry, scan_id, output_dir = _registered(tmp_path, monkeypatch)
    monkeypatch.delenv(sandbox.ASH_MCP_TRANSPORT_ENV, raising=False)

    def a_scan_the_timer_stops(*args: Any, **kwargs: Any) -> None:
        assert registry.finish_scan(scan_id, MCScanStatus.FAILED, TIMEOUT_REASON)
        registry.get_scan(scan_id).cancel_event.set()
        event = current_cancel_event()
        assert event is not None, "control: the stand-in ran outside the scan's scope"
        event.note_could_not_stop("bandit", 4242)
        raise_if_cancelled()
        raise AssertionError("control: the scan was not stopped")

    with (
        patch.object(ras, "run_ash_scan", a_scan_the_timer_stops),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
    ):
        await mcp_tools._run_scan_async(
            scan_id=scan_id,
            directory_path=str(tmp_path),
            output_dir=str(output_dir),
            severity_threshold=None,
            session_id=session_id,
        )
        entry = registry.get_scan(scan_id)
        assert await asyncio.to_thread(entry.runner_done.wait, SETTLE_SECONDS), (
            "control: the scan's thread never settled"
        )
    return entry


@pytest.mark.asyncio
async def test_a_caller_with_a_session_id_is_not_told_the_process_id(
    tmp_path, monkeypatch
):
    entry = await _stop_one_tool_and_read_the_entry(
        tmp_path, monkeypatch, "a-client-session"
    )

    warnings = [w for w in entry.warnings if "bandit" in w]
    # RED at the base: the transport is not marked as networked, so the warning
    # named pid 4242 to a caller that is remote by its session id.
    assert warnings, entry.warnings
    assert all("4242" not in w for w in warnings), warnings
    # The entry keeps the pair, as for a remote caller on a network transport.
    assert entry.could_not_stop == (("bandit", 4242),)


@pytest.mark.asyncio
@pytest.mark.parametrize("session_id", [None, DEFAULT_SESSION_ID])
async def test_the_launching_process_is_still_told_the_process_id(
    tmp_path, monkeypatch, session_id
):
    """Control, green on both sides: the local caller names the pid."""
    entry = await _stop_one_tool_and_read_the_entry(tmp_path, monkeypatch, session_id)

    assert any("bandit" in w and "4242" in w for w in entry.warnings), entry.warnings
