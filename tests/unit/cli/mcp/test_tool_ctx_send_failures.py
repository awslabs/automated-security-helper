# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failed log message to the client does not replace a tool's result.

A client whose transport has closed makes every send to it raise, whatever the
level. The tools send their logs through one guard, so the dict a tool returns
is the same whether or not its sends arrive. These tests give each tool family a
context whose sends all raise, drive one refusal, success or failure path, and
check that the tool still returns its real result: a refusal stays a refusal, a
success stays a success, and a scan that has started reports its scan_id.
"""

from __future__ import annotations

import ast
import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_server, mcp_tools
from automated_security_helper.cli.mcp import progress_monitor
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
)
from automated_security_helper.cli.mcp.scan_target import ScanTargetResolution
from automated_security_helper.utils.log import ASH_LOGGER
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
    """A context whose every send fails, as on a closed transport."""
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": session}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock(side_effect=RuntimeError("client gone")))
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


def test_a_refused_scan_target_is_returned_when_every_send_fails(
    tmp_path: Path,
) -> None:
    ctx = _ctx()
    refused = MCPResourceError(
        "not a permitted directory",
        context={"error_category": ErrorCategory.INVALID_PATH.value},
    )

    with patch.object(
        mcp_server,
        "resolve_scan_target",
        return_value=ScanTargetResolution(error=refused),
    ):
        result = _call("run_ash_scan", ctx, {"source_dir": str(tmp_path)})

    assert result["success"] is False, result
    assert result["error_type"] == "scan_target_not_permitted", result
    assert ctx.error.await_count == 1


SUCCEEDING_BACKENDS = [
    ("resolve_ash_workspace", {"workspace_file": "w"}, "mcp_resolve_workspace"),
    ("run_ash_workspace_scan", {"workspace_file": "w"}, "mcp_scan_workspace"),
    ("list_active_scans", {}, "mcp_list_active_scans"),
    ("cancel_scan", {"scan_id": "s"}, "mcp_cancel_scan"),
    ("check_installation", {}, "mcp_check_installation"),
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
    "tool, kwargs, backend",
    SUCCEEDING_BACKENDS,
    ids=[t for t, _, _ in SUCCEEDING_BACKENDS],
)
def test_a_successful_result_is_returned_when_every_send_fails(
    tool: str, kwargs: Dict[str, Any], backend: str
) -> None:
    ctx = _ctx()

    with patch.object(
        mcp_server,
        backend,
        return_value={"success": True, "exit_code": 0, "scan_ids": {}},
    ):
        result = _call(tool, ctx, kwargs)

    assert result["success"] is True, result


def _start_a_scan(ctx: MagicMock, tmp_path: Path) -> Dict[str, Any]:
    with (
        patch.object(
            mcp_server,
            "resolve_scan_target",
            return_value=ScanTargetResolution(resolved=tmp_path),
        ),
        patch.object(mcp_server, "validate_output_tree", return_value=None),
        patch.object(
            mcp_server,
            "mcp_scan_directory",
            return_value={"success": True, "scan_id": "scan-1"},
        ),
        patch.object(mcp_server, "monitor_scan_progress", new=AsyncMock()),
    ):
        return _call("run_ash_scan", ctx, {"source_dir": str(tmp_path)})


def test_a_running_scan_reports_its_scan_id_when_every_send_fails(
    tmp_path: Path,
) -> None:
    result = _start_a_scan(_ctx(), tmp_path)

    assert result["success"] is True, result
    assert result["scan_id"] == "scan-1", result
    assert result["status"] == "running", result


def test_a_running_scan_reports_its_scan_id_when_only_the_started_send_fails(
    tmp_path: Path,
) -> None:
    ctx = _ctx()
    for name in ("debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())

    async def _info(message: str) -> None:
        if message.startswith("Scan started"):
            raise RuntimeError("client gone")

    ctx.info = AsyncMock(side_effect=_info)

    result = _start_a_scan(ctx, tmp_path)

    assert result["success"] is True, result
    assert result["scan_id"] == "scan-1", result


LOG_LEVELS = frozenset({"debug", "info", "warning", "error"})
CONTEXT_NAMES = frozenset({"ctx", "context"})
GUARD = "_tell_client"
#: The progress monitor's own guard: a send in its arguments is awaited inside
#: a try block that catches Exception.
SAFE_SEND = "_safe_send"
PROGRESS = "report_progress"


def _catches_exception(node: ast.Try) -> bool:
    return any(
        isinstance(h.type, ast.Name) and h.type.id == "Exception" for h in node.handlers
    )


def _sends_outside_the_guard(source: str) -> List[int]:
    """Line numbers of sends on a context that are not inside a guard.

    A send is a log call (debug, info, warning, error) or report_progress on a
    context. The guards are the body of ``_tell_client`` and the arguments of
    ``_safe_send``. A report_progress send may also sit in the body of a try that
    catches Exception, because it takes progress and a total rather than a
    message and so has no ``_tell_client`` form. A log call may not: the same
    shape around a log call hid a bare send before, so it must go through the
    guard.
    """
    lines: List[int] = []

    def visit(node: ast.AST, inside_guard: bool, progress_caught: bool) -> None:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == GUARD
        ):
            inside_guard = True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == SAFE_SEND
        ):
            inside_guard = True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in LOG_LEVELS | {PROGRESS}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in CONTEXT_NAMES
            and not inside_guard
            and not (node.func.attr == PROGRESS and progress_caught)
        ):
            lines.append(node.lineno)
        if isinstance(node, ast.Try) and _catches_exception(node):
            for child in node.body:
                visit(child, inside_guard, True)
            for child in [*node.handlers, *node.orelse, *node.finalbody]:
                visit(child, inside_guard, progress_caught)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, inside_guard, progress_caught)

    visit(ast.parse(source), False, False)
    return lines


def test_the_structural_check_flags_a_bare_send_and_passes_a_guarded_one() -> None:
    source = (
        "async def _tell_client(ctx, level, message):\n"
        "    await ctx.info(message)\n"
        "async def tool(ctx):\n"
        "    logger.info('not a client send')\n"
        "    await _tell_client(ctx, 'info', 'ok')\n"
        "    await ctx.warning('bare')\n"
    )

    assert _sends_outside_the_guard(source) == [6]


def test_the_structural_check_covers_progress_sends_and_the_monitor_guard() -> None:
    source = (
        "async def a(ctx):\n"
        "    await ctx.report_progress(progress=0.0)\n"
        "async def b(ctx):\n"
        "    try:\n"
        "        await ctx.report_progress(progress=0.0)\n"
        "    except Exception:\n"
        "        await ctx.report_progress(progress=1.0)\n"
        "async def c(ctx):\n"
        "    try:\n"
        "        await ctx.info('log call in a try is still bare')\n"
        "    except Exception:\n"
        "        pass\n"
        "async def d(ctx):\n"
        "    await _safe_send(True, lambda: ctx.error('guarded'), 'x')\n"
        "    await ctx.error('bare')\n"
    )

    assert _sends_outside_the_guard(source) == [2, 7, 10, 15]


@pytest.mark.parametrize(
    "module",
    [mcp_server, mcp_tools, progress_monitor],
    ids=["server", "tools", "progress_monitor"],
)
def test_no_client_send_sits_outside_the_guard(module: Any) -> None:
    path = Path(module.__file__)

    lines = _sends_outside_the_guard(path.read_text(encoding="utf-8"))

    assert not lines, (
        f"{path.name} sends to the client outside {GUARD} at line(s) "
        f"{', '.join(str(n) for n in lines)}"
    )


def test_a_failed_send_is_logged_with_the_exception_that_failed_it(caplog) -> None:
    ctx = _ctx()

    with caplog.at_level(logging.ERROR, logger=ASH_LOGGER.name):
        asyncio.run(mcp_server._tell_client(ctx, "info", "hello"))

    records = [
        r
        for r in caplog.records
        if "Failed to send info message to client" in r.getMessage()
    ]
    assert records, [r.getMessage() for r in caplog.records]
    assert records[0].exc_info is not None, records[0]
    assert "client gone" in str(records[0].exc_info[1]), records[0].exc_info


def test_control_a_working_log_send_is_awaited_once_with_the_error() -> None:
    """The cells above count one send; a context that can send gets exactly one."""
    ctx = _ctx(NOT_A_SESSION_ID)
    ctx.error = AsyncMock()

    result = _call("clear_source", ctx, {})

    assert result["error_type"] == "invalid_session_id", result
    assert ctx.error.await_count == 1


MONITOR_LOOKUPS = [
    ("lookup_fails", {"success": False, "error": "not found"}),
    ("directory_missing", {"success": True, "directory_path": ""}),
]


def _monitor_ctx(failing: str) -> MagicMock:
    """A context whose progress sends work and whose ``failing`` send raises."""
    ctx = MagicMock()
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    setattr(ctx, failing, AsyncMock(side_effect=RuntimeError("client gone")))
    return ctx


@pytest.mark.parametrize(
    "lookup", [row for _, row in MONITOR_LOOKUPS], ids=[i for i, _ in MONITOR_LOOKUPS]
)
def test_a_failed_lookup_report_is_one_failed_send_not_a_monitor_failure(
    lookup: Dict[str, Any],
) -> None:
    """The monitor reports a lookup failure once, and a failed send ends there.

    A send that raised used to land in the monitor's own handler, which sent a
    second error to the same dead client and logged the dead send as a monitor
    failure.
    """
    ctx = _monitor_ctx("error")

    with patch.object(
        progress_monitor, "mcp_get_scan_progress", AsyncMock(return_value=lookup)
    ):
        asyncio.run(progress_monitor.monitor_scan_progress(ctx, "scan-1"))

    assert ctx.error.await_count == 1


def test_a_failed_timeout_warning_is_not_a_monitor_failure(tmp_path: Path) -> None:
    ctx = _monitor_ctx("warning")
    found = {"success": True, "directory_path": str(tmp_path)}

    with (
        patch.object(
            progress_monitor, "mcp_get_scan_progress", AsyncMock(return_value=found)
        ),
        patch.object(progress_monitor, "_MAX_WAIT_SECONDS", -1),
    ):
        asyncio.run(progress_monitor.monitor_scan_progress(ctx, "scan-1"))

    assert ctx.warning.await_count == 1
    assert ctx.error.await_count == 0, ctx.error.await_args_list


def test_control_a_working_lookup_report_is_awaited_once_with_the_error() -> None:
    ctx = _monitor_ctx("debug")
    lookup = {"success": False, "error": "not found"}

    with patch.object(
        progress_monitor, "mcp_get_scan_progress", AsyncMock(return_value=lookup)
    ):
        asyncio.run(progress_monitor.monitor_scan_progress(ctx, "scan-1"))

    ctx.error.assert_awaited_once_with("Failed to get scan info: not found")
