# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancel stops only a scan of the calling session, and the list shows only its scans.

cancel_scan stops the scan, by setting its registry entry's cancel event
(test_cancel_scan_stops_the_scan.py). Each entry records the session that
started it, so no session can cancel or list another session's scans: each
entry's owner is the session id the other tools resolve from the
request), cancel_scan answers another session's id exactly as it answers an id
never issued, without closing the entry or setting its event, and
list_active_scans lists, and counts, the calling session's scans only.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp_tools import mcp_cancel_scan
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    get_scan_registry,
)


def _running_scan(tmp_path, session_id: str):
    output = tmp_path / session_id / "out"
    output.mkdir(parents=True)
    registry = get_scan_registry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path / session_id),
        output_directory=str(output),
        session_id=session_id,
    )
    registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
    return scan_id, registry.get_scan(scan_id)


def _ctx(session_id: str) -> MagicMock:
    ctx = MagicMock(spec=Context)
    ctx.headers = {"mcp-session-id": session_id}
    return ctx


@pytest.mark.asyncio
async def test_another_sessions_cancel_does_not_stop_the_scan(tmp_path):
    scan_id, entry = _running_scan(tmp_path, "session-a")

    refused = await mcp_cancel_scan(scan_id=scan_id, session_id="session-b")
    never_issued = await mcp_cancel_scan(
        scan_id="00000000-0000-0000-0000-000000000000", session_id="session-b"
    )

    assert refused.get("success") is not True, refused
    assert not entry.cancel_event.is_set(), "another session's cancel stopped the scan"
    assert entry.status is MCScanStatus.RUNNING
    assert refused.get("error_type") == never_issued.get("error_type"), (
        refused,
        never_issued,
    )
    assert refused.get("error_category") == never_issued.get("error_category")


@pytest.mark.asyncio
async def test_the_owning_sessions_cancel_stops_it(tmp_path):
    scan_id, entry = _running_scan(tmp_path, "session-a")

    cancelled = await mcp_cancel_scan(scan_id=scan_id, session_id="session-a")

    assert cancelled["success"] is True, cancelled
    assert entry.cancel_event.is_set()
    assert entry.status is MCScanStatus.CANCELLED


@pytest.mark.asyncio
async def test_the_tool_resolves_the_session_from_the_request(tmp_path):
    scan_id, entry = _running_scan(tmp_path, "session-a")

    refused = await mcp_server.cancel_scan(_ctx("session-b"), scan_id)
    assert refused.get("success") is not True, refused
    assert not entry.cancel_event.is_set()

    cancelled = await mcp_server.cancel_scan(_ctx("session-a"), scan_id)
    assert cancelled["success"] is True, cancelled


@pytest.mark.asyncio
async def test_list_active_scans_shows_only_the_callers_scans(tmp_path):
    mine, _ = _running_scan(tmp_path, "session-a")
    theirs, _ = _running_scan(tmp_path, "session-b")

    listed = await mcp_server.list_active_scans(_ctx("session-a"))

    ids = {scan["scan_id"] for scan in listed["active_scans"]}
    ids |= {scan["scan_id"] for scan in listed["all_scans"]}
    assert mine in ids
    assert theirs not in ids, "list_active_scans handed out another session's scan id"
    assert listed["stats"]["total_scans"] == 1
    assert listed["stats"]["active_scans"] == 1


def test_a_busy_directory_names_its_scan_only_to_the_owner(tmp_path):
    from automated_security_helper.core.resource_management.exceptions import (
        MCPResourceError,
    )

    scan_id, _ = _running_scan(tmp_path, "session-a")
    registry = get_scan_registry()
    directory = str(tmp_path / "session-a")
    output = str(tmp_path / "session-a" / "out")

    with pytest.raises(MCPResourceError) as other:
        registry.register_scan(
            directory_path=directory, output_directory=output, session_id="session-b"
        )
    with pytest.raises(MCPResourceError) as owner:
        registry.register_scan(
            directory_path=directory, output_directory=output, session_id="session-a"
        )

    assert "scan_id" not in other.value.context, other.value.context
    assert scan_id not in str(other.value)
    assert owner.value.context["scan_id"] == scan_id
