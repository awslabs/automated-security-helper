# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_scan_progress answers only the session that started the scan.

cancel_scan and list_active_scans act on the calling session's scans only
(test_cancel_reaches_only_its_session.py), and a get_scan_progress that looked a
scan up by id alone would let a session holding another session's scan id read
its status, its directory and output paths, its warnings and its findings
counts. Another session's id answers exactly as an id that was never issued.
The progress monitor run_ash_scan starts reads the scan as the session that
started it, so it keeps reporting for a scan of a session other than the
default one.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp_tools import mcp_get_scan_progress
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    get_scan_registry,
)

pytestmark = pytest.mark.unit

NEVER_ISSUED = "00000000-0000-0000-0000-000000000000"


def _running_scan(tmp_path, session_id: str) -> str:
    output = tmp_path / session_id / "out"
    output.mkdir(parents=True)
    registry = get_scan_registry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path / session_id),
        output_directory=str(output),
        session_id=session_id,
    )
    registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
    return scan_id


def _ctx(session_id: str) -> MagicMock:
    ctx = MagicMock(spec=Context)
    ctx.headers = {"mcp-session-id": session_id}
    for level in ("info", "warning", "error", "debug"):
        setattr(ctx, level, AsyncMock())
    return ctx


@pytest.mark.asyncio
async def test_another_session_reads_nothing_of_the_scan(tmp_path):
    scan_id = _running_scan(tmp_path, "session-a")

    refused = await mcp_get_scan_progress(scan_id, session_id="session-b")
    never = await mcp_get_scan_progress(NEVER_ISSUED, session_id="session-b")

    assert refused.get("success") is False, refused
    assert refused.get("error_category") == never.get("error_category"), (
        refused,
        never,
    )
    assert "running" not in repr(refused.get("status", "")), refused
    assert str(tmp_path / "session-a") not in repr(refused), refused


@pytest.mark.asyncio
async def test_the_owning_session_reads_it(tmp_path):
    scan_id = _running_scan(tmp_path, "session-a")

    progress = await mcp_get_scan_progress(scan_id, session_id="session-a")

    assert progress.get("success") is not False, progress
    assert progress["status"] == "running", progress


@pytest.mark.asyncio
async def test_the_tool_scopes_by_the_request_session(tmp_path):
    scan_id = _running_scan(tmp_path, "session-a")

    refused = await mcp_server.get_scan_progress(_ctx("session-b"), scan_id)
    never = await mcp_server.get_scan_progress(_ctx("session-b"), NEVER_ISSUED)
    allowed = await mcp_server.get_scan_progress(_ctx("session-a"), scan_id)

    assert refused.get("success") is False, refused
    assert refused.get("error_category") == never.get("error_category")
    assert str(tmp_path / "session-a") not in repr(refused), refused
    assert allowed["status"] == "running", allowed


@pytest.mark.asyncio
async def test_the_progress_monitor_reads_its_own_sessions_scan(tmp_path):
    """run_ash_scan's monitor asks as the session that started the scan."""
    from automated_security_helper.cli.mcp import progress_monitor

    scan_id = _running_scan(tmp_path, "session-a")
    ctx = _ctx("session-a")

    info = await progress_monitor._fetch_initial_scan_info(
        ctx, scan_id, session_id="session-a"
    )

    assert info is not None, ctx.error.await_args_list
    directory, _, _ = info
    assert str(directory) == str(tmp_path / "session-a")
