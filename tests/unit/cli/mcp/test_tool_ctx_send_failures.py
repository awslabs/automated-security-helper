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
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_server, mcp_tools
from automated_security_helper.cli.mcp import progress_monitor, workspace
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

pytestmark = pytest.mark.unit

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
    clear_session_state(None)
    yield
    clear_profile_registry()
    clear_session_state(None)


class _ContextShape:
    """The attribute set of a real ``Context``, as these tools use it.

    The mocks are built against this shape rather than a bare ``MagicMock`` so
    a missing attribute raises. A bare mock answers every name, which is how a
    mistyped level slipped past these cells: ``getattr(ctx, "warn")`` answered
    with a child mock, and the ``TypeError`` from awaiting it was swallowed by
    the same handler as a failed send.
    """

    headers: Dict[str, str] = {}

    async def debug(self, message: str) -> None: ...

    async def info(self, message: str) -> None: ...

    async def warning(self, message: str) -> None: ...

    async def error(self, message: str) -> None: ...

    async def report_progress(
        self,
        progress: float,
        total: Optional[float] = None,
        message: Optional[str] = None,
    ) -> None: ...


def _ctx(session: str = SESSION) -> MagicMock:
    """A context whose every send fails, as on a closed transport."""
    ctx = MagicMock(spec=_ContextShape)
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


def _sends_outside_the_guard(source: str, *, exempt_tell_client: bool) -> List[int]:
    """Line numbers of sends on a context that are not inside a guard.

    A send is a log call (debug, info, warning, error) or report_progress on a
    context. The guards are the body of ``_tell_client`` and the arguments of
    ``_safe_send``. A report_progress send may also sit in the body of a try that
    catches Exception, because it takes progress and a total rather than a
    message and so has no ``_tell_client`` form. A log call may not: the same
    shape around a log call hid a bare send before, so it must go through the
    guard.

    ``exempt_tell_client`` is True only for the module that defines the guard,
    ``mcp_server``. In any other module a function named ``_tell_client`` is a
    wrapper, not the guard, and a bare send added to it would otherwise pass
    unseen.
    """
    lines: List[int] = []

    def visit(node: ast.AST, inside_guard: bool, progress_caught: bool) -> None:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == GUARD
            and exempt_tell_client
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

    assert _sends_outside_the_guard(source, exempt_tell_client=True) == [6]


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

    assert _sends_outside_the_guard(source, exempt_tell_client=True) == [2, 7, 10, 15]


def test_the_structural_check_scans_a_foreign_tell_client_like_any_function() -> None:
    """Only the server's ``_tell_client`` is the guard. The monitor used to have
    a wrapper of the same name that only forwarded the call, and the name alone
    exempted it: a bare send added to such a wrapper passed the scan."""
    source = (
        "async def _tell_client(ctx, level, message):\n"
        "    await ctx.error('bare send in a wrapper')\n"
    )

    assert _sends_outside_the_guard(source, exempt_tell_client=False) == [2]
    assert _sends_outside_the_guard(source, exempt_tell_client=True) == []


#: The modules the scan reads, with whether their ``_tell_client`` definition is
#: the server's guard. ``workspace`` is here because ``run_ash_workspace_scan``
#: hands ``ctx.report_progress`` into it.
SCANNED_MODULES = [
    (mcp_server, True),
    (mcp_tools, False),
    (progress_monitor, False),
    (workspace, False),
]


def test_the_scan_covers_the_workspace_module_and_exempts_only_the_server_guard() -> (
    None
):
    scanned = {module.__name__: is_guard for module, is_guard in SCANNED_MODULES}

    assert workspace.__name__ in scanned, scanned
    assert scanned == {
        mcp_server.__name__: True,
        mcp_tools.__name__: False,
        progress_monitor.__name__: False,
        workspace.__name__: False,
    }, scanned


@pytest.mark.parametrize(
    "module, is_guard_module",
    SCANNED_MODULES,
    ids=["server", "tools", "progress_monitor", "workspace"],
)
def test_no_client_send_sits_outside_the_guard(
    module: Any, is_guard_module: bool
) -> None:
    path = Path(module.__file__)

    lines = _sends_outside_the_guard(
        path.read_text(encoding="utf-8"), exempt_tell_client=is_guard_module
    )

    assert not lines, (
        f"{path.name} sends to the client outside {GUARD} at line(s) "
        f"{', '.join(str(n) for n in lines)}"
    )


@pytest.mark.parametrize("level", ["warn", "Warning"])
def test_a_mistyped_level_raises_instead_of_being_swallowed(level: str) -> None:
    """A level outside the context's log methods is a coding mistake, not a
    failed send: swallowed, the message silently never reaches the client and
    nothing names the mistake."""
    ctx = _ctx()

    with pytest.raises(ValueError, match=level):
        asyncio.run(mcp_server._tell_client(ctx, level, "hello"))


def test_a_failed_send_is_logged_with_the_exception_that_failed_it(caplog) -> None:
    """A closed transport is the guard's expected condition: one warning names
    the lost send, and the traceback sits at debug, as the monitor's
    ``_safe_send`` logs the same condition. An ERROR traceback per send put up
    to five tracebacks in one ``run_ash_scan`` against a dead client."""
    ctx = _ctx()

    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        asyncio.run(mcp_server._tell_client(ctx, "info", "hello"))

    warnings = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING
        and "Failed to send info message to client" in r.getMessage()
    ]
    assert warnings, [r.getMessage() for r in caplog.records]
    assert warnings[0].exc_info is None, warnings[0]
    tracebacks = [
        r
        for r in caplog.records
        if r.levelno == logging.DEBUG and r.exc_info is not None
    ]
    assert tracebacks, [r.getMessage() for r in caplog.records]
    assert "client gone" in str(tracebacks[0].exc_info[1]), tracebacks[0].exc_info


def test_a_failed_send_does_not_repeat_the_message_in_the_log(caplog) -> None:
    """Every message a tool hands the guard is already shown text, its controls
    escaped for the client, so a warning that repeated it showed it a second
    time, and each escape in it read as the text of one. The warning names the
    lost send by its level and size; the message's text stays out of the log."""
    ctx = _ctx()
    message = "a name holding an escape: a\\x1b[2Kb and 7 more"

    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        asyncio.run(mcp_server._tell_client(ctx, "warning", message))

    logged = [r.getMessage() for r in caplog.records]
    warnings = [
        text for r, text in zip(caplog.records, logged) if r.levelno == logging.WARNING
    ]
    assert warnings, logged
    assert all(message not in text for text in logged), logged
    assert all("a name holding an escape" not in text for text in logged), logged
    assert f"({len(message)} characters)" in warnings[0], warnings[0]
    assert "Failed to send warning message to client" in warnings[0], warnings[0]


def test_a_failed_send_of_a_non_str_message_still_warns(caplog) -> None:
    """The guard is given whatever a caller hands it, and the old text-bearing
    warning accepted any type. Sizing the message in the failure path must not
    raise over a message that is not a str (None here): the send is still
    named by its level and the text's length, as for any other message."""
    ctx = _ctx()

    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        asyncio.run(mcp_server._tell_client(ctx, "info", None))

    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, [r.getMessage() for r in caplog.records]
    assert "Failed to send info message to client (4 characters)" in warnings[0], (
        warnings[0]
    )


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
    ctx = MagicMock(spec=_ContextShape)
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    setattr(ctx, failing, AsyncMock(side_effect=RuntimeError("client gone")))
    return ctx


def test_the_monitor_module_does_not_import_the_server_module() -> None:
    """The monitor sits below the server. Importing ``mcp_server`` from here,
    even inside a function, loads the whole server (tool registration included)
    on the first send from code that never started one, and points the
    dependency the wrong way."""
    source = Path(progress_monitor.__file__).read_text(encoding="utf-8")

    offending = [
        node.lineno
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.Import, ast.ImportFrom))
        and (
            "mcp_server" in (getattr(node, "module", None) or "")
            or any("mcp_server" in alias.name for alias in node.names)
        )
    ]

    assert not offending, f"progress_monitor imports mcp_server at line(s) {offending}"


def test_a_dead_connection_skips_the_timeout_warning(tmp_path: Path) -> None:
    """The loop tracks ``connection_alive``; after the initial send has already
    failed, the timeout warning honors that instead of sending into a client
    the loop knows is gone."""
    ctx = _monitor_ctx("report_progress")
    found = {"success": True, "directory_path": str(tmp_path)}

    with (
        patch.object(
            progress_monitor, "mcp_get_scan_progress", AsyncMock(return_value=found)
        ),
        patch.object(progress_monitor, "_MAX_WAIT_SECONDS", -1),
    ):
        asyncio.run(progress_monitor.monitor_scan_progress(ctx, "scan-1"))

    assert ctx.warning.await_count == 0, ctx.warning.await_args_list


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
