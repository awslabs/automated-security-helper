# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failed log message to the client does not replace a tool's result.

``get_scan_results`` and ``get_scan_result_paths`` send their error log inside a
guard, so a client whose transport has closed still gets the structured result.
Every other tool awaited ``ctx.error`` bare in its refusal branches and its
``except`` arms: the send raised, and the exception left the tool instead of the
dict the client branches on. These tests give each tool family a context whose
``error`` raises, drive one refusal or failure path, and check that the tool
still returns its structured result.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
)
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)

SESSION = "ctx-send-session"
NOT_A_SESSION_ID = "a/b"
REFUSAL = {
    "success": False,
    "operation": "any",
    "error": "needs a session",
    "error_type": "session_identity_required",
}


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_session_state()
    yield
    clear_profile_registry()
    clear_session_state()


def _ctx(session: str = SESSION) -> MagicMock:
    """A context whose error log cannot be sent."""
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": session}
    for name in ("info", "debug", "warning", "report_progress"):
        setattr(ctx, name, AsyncMock())
    ctx.error = AsyncMock(side_effect=RuntimeError("client gone"))
    return ctx


def _call(tool: str, ctx: MagicMock, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    return asyncio.run(getattr(mcp_server, tool)(ctx, **kwargs))


SESSION_TOOLS = [
    ("run_ash_scan", {}),
    ("resolve_ash_workspace", {"workspace_file": "w.code-workspace"}),
    ("run_ash_workspace_scan", {"workspace_file": "w.code-workspace"}),
    ("get_scan_progress", {"scan_id": "s"}),
    ("get_scan_results", {}),
    ("get_scan_result_paths", {}),
    ("list_active_scans", {}),
    ("cancel_scan", {"scan_id": "s"}),
    ("set_source_git", {"url": "https://example.com/r.git"}),
    (
        "set_source_zip_chunk",
        {"upload_id": "u", "sequence": 0, "data_b64": "", "last": True},
    ),
    ("set_source_zip_finalize", {"upload_id": "u", "expected_sha256": "0" * 64}),
    ("clear_source", {}),
    ("select_profile", {"profile_name": "p"}),
]


@pytest.mark.parametrize(
    "tool, kwargs", SESSION_TOOLS, ids=[t for t, _ in SESSION_TOOLS]
)
def test_a_rejected_session_header_still_returns_its_error(
    tool: str, kwargs: Dict[str, Any]
) -> None:
    ctx = _ctx(NOT_A_SESSION_ID)

    result = _call(tool, ctx, kwargs)

    assert result["success"] is False, result
    assert result["error_type"] == "invalid_session_id", result
    assert ctx.error.await_count == 1


REFUSING_TOOLS = [
    ("run_ash_scan", {}),
    ("get_scan_progress", {"scan_id": "s"}),
    ("list_active_scans", {}),
    ("cancel_scan", {"scan_id": "s"}),
    ("set_source_git", {"url": "https://example.com/r.git"}),
    (
        "set_source_zip_chunk",
        {"upload_id": "u", "sequence": 0, "data_b64": "", "last": True},
    ),
    ("set_source_zip_finalize", {"upload_id": "u", "expected_sha256": "0" * 64}),
    ("clear_source", {}),
    ("select_profile", {"profile_name": "p"}),
]


@pytest.mark.parametrize(
    "tool, kwargs", REFUSING_TOOLS, ids=[t for t, _ in REFUSING_TOOLS]
)
def test_a_session_identity_refusal_is_returned_when_the_log_send_fails(
    tool: str, kwargs: Dict[str, Any]
) -> None:
    ctx = _ctx()

    with patch.object(mcp_server, "session_identity_refusal", return_value=REFUSAL):
        result = _call(tool, ctx, kwargs)

    assert result["success"] is False, result
    assert result["error_type"] == "session_identity_required", result
    assert ctx.error.await_count == 1


RAISING_BACKENDS = [
    ("run_ash_scan", {}, "session_identity_refusal"),
    ("resolve_ash_workspace", {"workspace_file": "w"}, "mcp_resolve_workspace"),
    ("run_ash_workspace_scan", {"workspace_file": "w"}, "mcp_scan_workspace"),
    ("get_scan_progress", {"scan_id": "s"}, "mcp_get_scan_progress"),
    ("list_active_scans", {}, "mcp_list_active_scans"),
    ("cancel_scan", {"scan_id": "s"}, "mcp_cancel_scan"),
    ("check_installation", {}, "mcp_check_installation"),
]


@pytest.mark.parametrize(
    "tool, kwargs, backend", RAISING_BACKENDS, ids=[t for t, _, _ in RAISING_BACKENDS]
)
def test_an_unexpected_error_is_returned_when_the_log_send_fails(
    tool: str, kwargs: Dict[str, Any], backend: str
) -> None:
    ctx = _ctx()

    with patch.object(mcp_server, backend, side_effect=ValueError("boom")):
        result = _call(tool, ctx, kwargs)

    assert result["success"] is False, result
    assert result["error_type"] == "ValueError", result
    assert "boom" in result["error"], result
    assert ctx.error.await_count == 1


FAILING_BACKENDS = [
    ("resolve_ash_workspace", {"workspace_file": "w"}, "mcp_resolve_workspace"),
    ("run_ash_workspace_scan", {"workspace_file": "w"}, "mcp_scan_workspace"),
    ("set_source_git", {"url": "https://example.com/r.git"}, "mcp_set_source_git"),
    (
        "set_source_zip_finalize",
        {"upload_id": "u", "expected_sha256": "0" * 64},
        "mcp_set_source_zip_finalize",
    ),
    ("clear_source", {}, "mcp_clear_source"),
    ("select_profile", {"profile_name": "p"}, "mcp_select_profile"),
]


@pytest.mark.parametrize(
    "tool, kwargs, backend", FAILING_BACKENDS, ids=[t for t, _, _ in FAILING_BACKENDS]
)
def test_a_failed_result_is_returned_when_the_log_send_fails(
    tool: str, kwargs: Dict[str, Any], backend: str
) -> None:
    ctx = _ctx()

    with patch.object(
        mcp_server, backend, return_value={"success": False, "error": "nope"}
    ):
        result = _call(tool, ctx, kwargs)

    assert result["success"] is False, result
    assert result["error"] == "nope", result
    assert ctx.error.await_count == 1


def test_a_refused_output_directory_is_returned_when_the_log_send_fails(
    tmp_path: Path,
) -> None:
    ctx = _ctx()
    refused = MCPResourceError(
        "not a permitted directory",
        context={"error_category": ErrorCategory.INVALID_PATH.value},
    )

    with patch.object(mcp_server, "validate_scan_target", return_value=refused):
        result = _call("get_scan_result_paths", ctx, {"output_dir": str(tmp_path)})

    assert result["success"] is False, result
    assert result["error_type"] == "scan_target_not_permitted", result
    assert ctx.error.await_count == 1


def test_control_a_working_log_send_is_awaited_once_with_the_error() -> None:
    """The cells above count one send; a context that can send gets exactly one."""
    ctx = _ctx(NOT_A_SESSION_ID)
    ctx.error = AsyncMock()

    result = _call("clear_source", ctx, {})

    assert result["error_type"] == "invalid_session_id", result
    assert ctx.error.await_count == 1
