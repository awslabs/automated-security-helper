# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""run_ash_scan tells only the local client the server's working directory.

The module withholds the server's filesystem layout from a network caller: an
omitted source_dir never falls back to the working directory on a network
session, and check_installation names the ash executable's path only to the
local client. The scan tool's first log line named the working directory to
every caller anyway. It now does so for the local client alone, whose
directory it is.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
)
from automated_security_helper.cli.mcp.scan_target import ScanTargetResolution
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
    MCPResourceError,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_session_state(None)
    yield
    clear_profile_registry()
    clear_session_state(None)


def _info_lines(headers: Dict[str, str], tmp_path: Path) -> List[str]:
    """The info log lines run_ash_scan sends up to its target check."""
    ctx = MagicMock(spec=Context)
    ctx.headers = headers
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    refused = MCPResourceError(
        "not a permitted directory",
        context={"error_category": ErrorCategory.INVALID_PATH.value},
    )
    # The target check comes right after the line under test; refusing there
    # ends the call before anything is scanned.
    with patch.object(
        mcp_server,
        "resolve_scan_target",
        return_value=ScanTargetResolution(error=refused),
    ):
        asyncio.run(mcp_server.run_ash_scan(ctx, source_dir=str(tmp_path)))
    return [call.args[0] for call in ctx.info.await_args_list]


def test_a_remote_session_is_not_told_the_working_directory(tmp_path: Path) -> None:
    lines = _info_lines({"mcp-session-id": "remote-session"}, tmp_path)

    # Red before the fix: the first line read "run_ash_scan tool called in cwd: ...".
    assert "run_ash_scan tool called" in lines, lines
    assert not any(str(Path.cwd()) in line for line in lines), lines
    assert not any("cwd" in line for line in lines), lines


def test_the_local_client_is_still_told_the_working_directory(tmp_path: Path) -> None:
    """Control: no headers at all is the local client, whose directory it is."""
    lines = _info_lines({}, tmp_path)

    assert any(
        line.startswith("run_ash_scan tool called in cwd: ") and str(Path.cwd()) in line
        for line in lines
    ), lines
