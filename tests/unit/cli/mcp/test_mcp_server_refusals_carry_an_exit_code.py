# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every refusal the scan tools return carries an exit code and names its cause.

run_ash_scan promises the CLI's exit code on every refusal, but passed on two
of mcp_scan_directory's without one: a session whose delivered source is being
changed, and a session at its scan limit. The workspace tools took a profile
from a caller with no session the server issued and let the workspace module
fail on the missing session workspace, which it reported as an invalid config
(exit 3) with nothing naming the cause; the cause is the missing session, so
the tools refuse it as every session tool does.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
)
from automated_security_helper.cli.mcp.scan_target import ScanTargetResolution
from automated_security_helper.cli.mcp_tools import (
    REFUSED_INTERNAL_EXIT_CODE,
    REFUSED_USAGE_EXIT_CODE,
)
from automated_security_helper.core.constants import ASH_EXIT_CODES

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_session_state(None)
    yield
    clear_profile_registry()
    clear_session_state(None)


def _ctx(headers: Dict[str, str]) -> MagicMock:
    ctx = MagicMock(spec=Context)
    ctx.headers = headers
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


def _start_a_scan(tmp_path: Path, producer_answer: Dict[str, Any]) -> Dict[str, Any]:
    """Drive run_ash_scan to mcp_scan_directory, which answers ``producer_answer``."""
    ctx = _ctx({"mcp-session-id": "session-a"})
    with (
        patch.object(
            mcp_server,
            "resolve_scan_target",
            return_value=ScanTargetResolution(resolved=tmp_path),
        ),
        patch.object(mcp_server, "validate_output_tree", return_value=None),
        patch.object(mcp_server, "committed_entries_in_the_way", return_value=[]),
        patch.object(
            mcp_server, "mcp_scan_directory", AsyncMock(return_value=producer_answer)
        ),
        patch.object(mcp_server, "monitor_scan_progress", new=AsyncMock()),
    ):
        return asyncio.run(mcp_server.run_ash_scan(ctx, source_dir=str(tmp_path)))


def test_a_refusal_shaped_without_an_exit_code_gets_the_catch_all_code(
    tmp_path: Path,
) -> None:
    result = _start_a_scan(
        tmp_path,
        {
            "success": False,
            "operation": "scan_directory",
            "error_type": "source_delivery_busy",
            "error": "the delivered source of this session is being changed",
        },
    )

    assert result["success"] is False, result
    assert result["error_type"] == "source_delivery_busy", result
    # Red before the fix: the refusal carried no exit_code at all.
    assert result["exit_code"] == REFUSED_INTERNAL_EXIT_CODE, result
    assert result["exit_code_meaning"] == ASH_EXIT_CODES[REFUSED_INTERNAL_EXIT_CODE]


def test_a_refusal_that_names_its_exit_code_keeps_it(tmp_path: Path) -> None:
    """Control: a code the producer chose is passed on as given."""
    result = _start_a_scan(
        tmp_path,
        {
            "success": False,
            "error_type": "scan_target_not_permitted",
            "error": "outside the permitted roots",
            "exit_code": 4,
            "exit_code_meaning": ASH_EXIT_CODES[4],
        },
    )

    assert result["exit_code"] == 4, result


WORKSPACE_TOOLS = [
    ("resolve_ash_workspace", "mcp_resolve_workspace"),
    ("run_ash_workspace_scan", "mcp_scan_workspace"),
]


@pytest.mark.parametrize(
    "tool, backend", WORKSPACE_TOOLS, ids=[t for t, _ in WORKSPACE_TOOLS]
)
def test_an_unidentified_caller_naming_a_profile_is_refused_for_its_missing_session(
    tool: str, backend: str
) -> None:
    # Headers that name no session: a network caller the server did not identify.
    ctx = _ctx({"host": "example"})
    reached = AsyncMock(
        return_value={"success": False, "error": "config", "exit_code": 3}
    )

    with patch.object(mcp_server, backend, reached):
        result = asyncio.run(
            getattr(mcp_server, tool)(
                ctx, workspace_file="w.code-workspace", profile="strict"
            )
        )

    assert result["success"] is False, result
    # Red before the fix: the workspace module answered an exit-3 config error.
    assert result["error_type"] == "session_identity_required", result
    assert result["exit_code"] == REFUSED_USAGE_EXIT_CODE, result
    assert reached.await_count == 0, "the call reached the workspace module"
    assert ctx.error.await_count == 1


@pytest.mark.parametrize(
    "tool, backend", WORKSPACE_TOOLS, ids=[t for t, _ in WORKSPACE_TOOLS]
)
def test_a_caller_with_a_session_naming_a_profile_reaches_the_workspace_module(
    tool: str, backend: str
) -> None:
    """Control: the guard refuses only the caller with no session."""
    ctx = _ctx({"mcp-session-id": "session-b"})
    reached = AsyncMock(return_value={"success": True, "exit_code": 0, "scan_ids": {}})

    with patch.object(mcp_server, backend, reached):
        result = asyncio.run(
            getattr(mcp_server, tool)(
                ctx, workspace_file="w.code-workspace", profile="strict"
            )
        )

    assert result["success"] is True, result
    assert reached.await_count == 1


def test_an_unidentified_caller_naming_no_profile_reaches_the_workspace_module() -> (
    None
):
    """Control: the workspace tools need no session of their own."""
    ctx = _ctx({"host": "example"})
    reached = AsyncMock(return_value={"success": True, "exit_code": 0, "plan": ""})

    with patch.object(mcp_server, "mcp_resolve_workspace", reached):
        result = asyncio.run(
            mcp_server.resolve_ash_workspace(ctx, workspace_file="w.code-workspace")
        )

    assert result["success"] is True, result
    assert reached.await_count == 1
