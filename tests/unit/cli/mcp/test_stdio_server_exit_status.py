# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash mcp` over stdio exits 1 when the server fails, and 0 only when it should.

Why this file exists
--------------------
Were ``run_mcp_server`` to catch every exception and return, the process would
exit 0 whatever went wrong while it served. Were an exception group taken for
"the client disconnected" whenever its message contains "TaskGroup", which
every anyio task group failure's does ("unhandled errors in a TaskGroup"), a
crash inside the server would read as an ordinary disconnect, and a client or
supervisor watching the exit status could not tell the two apart.

Two endings exit 0: the client closing the connection (EOF), and the client
closing it while the server was reading or writing (a broken pipe or a closed
stream, possibly grouped). Ctrl-C exits 130, as on every transport: where the
server cannot watch for signals it reaches ``run_mcp_server`` as
KeyboardInterrupt, alone or grouped, and is raised on as one. Anything else
propagates, and ``mcp_command`` exits 1 with the error on stderr, also under
``--quiet``, which hides log output and not the reason the process stopped. The
subprocess tests in tests/integration/cli/test_mcp_stdio_server.py and
test_mcp_stdio_scan_lifecycle.py cover the EOF ending end to end, and
test_mcp_stdio_shutdown.py covers Ctrl-C.
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import anyio
import pytest
import typer

from automated_security_helper.cli.mcp import mcp_command
from automated_security_helper.cli import mcp_server

if sys.version_info < (3, 11):
    # What anyio raises there; the built-in group types arrived in 3.11.
    from exceptiongroup import BaseExceptionGroup, ExceptionGroup

_RUN = "automated_security_helper.cli.mcp_server.run_mcp_server"
_DEPS = "automated_security_helper.cli.mcp.validate_mcp_dependencies"


@pytest.fixture
def _no_inherited_log_handlers(monkeypatch):
    """The ASH logger as `ash mcp` starts with it: no handler yet.

    A test earlier in the same worker can leave a console handler on the shared
    "ash" logger that writes to stdout. `ash mcp` routes the logger to stderr
    when a scan sets it up (ASH_LOG_TO_STDERR), which cannot help a handler that
    already exists, so a stdout assertion would measure that earlier test.
    """
    from automated_security_helper.utils.log import ASH_LOGGER

    monkeypatch.setattr(ASH_LOGGER, "handlers", [])


def _serving_raises(error: BaseException):
    server = MagicMock()
    server.run_stdio_async = AsyncMock(side_effect=error)
    return patch.object(mcp_server, "mcp", server)


@pytest.mark.parametrize(
    "ending",
    [
        BrokenPipeError(),
        ConnectionResetError(),
        anyio.ClosedResourceError(),
        anyio.BrokenResourceError(),
        ExceptionGroup("unhandled errors in a TaskGroup", [BrokenPipeError()]),
    ],
    ids=[
        "broken-pipe",
        "connection-reset",
        "closed-stream",
        "broken-stream",
        "grouped-broken-pipe",
    ],
)
def test_the_endings_that_are_not_failures_return(ending):
    with _serving_raises(ending):
        # Caught so that taking a disconnect for a Ctrl-C fails this test. Let
        # through, the KeyboardInterrupt stops the test run itself: under xdist
        # it crashes the worker, and the tests queued on it never run.
        try:
            mcp_server.run_mcp_server()
        except KeyboardInterrupt:
            pytest.fail(
                f"run_mcp_server raised KeyboardInterrupt for {ending!r}: the "
                "client going away was taken for a Ctrl-C, so `ash mcp` would "
                "exit 130 instead of 0"
            )


@pytest.mark.parametrize(
    "interrupt",
    [
        KeyboardInterrupt(),
        BaseExceptionGroup("unhandled errors in a TaskGroup", [KeyboardInterrupt()]),
        BaseExceptionGroup(
            "unhandled errors in a TaskGroup", [KeyboardInterrupt(), BrokenPipeError()]
        ),
    ],
    ids=["ctrl-c", "grouped-ctrl-c", "grouped-with-a-disconnect"],
)
def test_ctrl_c_is_raised_as_keyboard_interrupt(interrupt):
    """So that `ash mcp` exits 130 for it, as it does on every transport."""
    with _serving_raises(interrupt):
        with pytest.raises(KeyboardInterrupt):
            mcp_server.run_mcp_server()


def test_ash_mcp_exits_130_on_ctrl_c(_no_inherited_log_handlers):
    ctx = MagicMock(spec=typer.Context)
    ctx.resilient_parsing = False
    with patch(_DEPS, return_value=True), _serving_raises(KeyboardInterrupt()):
        with pytest.raises(typer.Exit) as exited:
            mcp_command(ctx, quiet=True)

    assert exited.value.exit_code == 130


@pytest.mark.parametrize(
    "failure",
    [
        ValueError("a handler bug"),
        RuntimeError("ClosedResourceError in TaskGroup"),
        ExceptionGroup("unhandled errors in a TaskGroup", [ValueError("in a task")]),
        ExceptionGroup(
            "unhandled errors in a TaskGroup",
            [BrokenPipeError(), ValueError("beside a disconnect")],
        ),
    ],
    ids=["plain", "message-says-closed", "grouped", "grouped-with-a-disconnect"],
)
def test_a_failure_while_serving_is_raised(failure):
    """Decided by type: a message that merely names a disconnect is not one."""
    with _serving_raises(failure):
        with pytest.raises(type(failure)):
            mcp_server.run_mcp_server()


def test_the_stdio_flag_is_cleared_however_serving_ends():
    with _serving_raises(ValueError("boom")):
        with pytest.raises(ValueError):
            mcp_server.run_mcp_server()
    assert mcp_server._serving_stdio is False


@pytest.mark.parametrize("quiet", [False, True], ids=["default", "quiet"])
def test_ash_mcp_exits_1_with_the_error_on_stderr(
    quiet, capsys, _no_inherited_log_handlers
):
    ctx = MagicMock(spec=typer.Context)
    ctx.resilient_parsing = False
    with (
        patch(_DEPS, return_value=True),
        patch(_RUN, side_effect=ValueError("a handler bug")),
    ):
        with pytest.raises(typer.Exit) as exited:
            mcp_command(ctx, quiet=quiet)

    assert exited.value.exit_code == 1
    captured = capsys.readouterr()
    assert "a handler bug" in captured.err
    assert captured.out == ""


def test_ash_mcp_exits_0_when_the_client_leaves(capsys, _no_inherited_log_handlers):
    ctx = MagicMock(spec=typer.Context)
    ctx.resilient_parsing = False
    with patch(_DEPS, return_value=True), _serving_raises(BrokenPipeError()):
        mcp_command(ctx, quiet=True)

    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# The client leaving stops the scans, over stdio only
# ---------------------------------------------------------------------------


async def _a_running_scan(tmp_path):
    """A registered scan whose runner ends only when its cancel event is set."""
    import asyncio

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        get_scan_registry,
    )

    (tmp_path / "out").mkdir()
    registry = get_scan_registry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(tmp_path / "out")
    )
    registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
    entry = registry.get_scan(scan_id)

    async def runner():
        await asyncio.to_thread(entry.cancel_event.wait, 30)

    mcp_tools._start_scan_task(scan_id, runner())
    await asyncio.sleep(0)
    return scan_id, entry


@pytest.mark.asyncio
async def test_a_stdio_client_leaving_stops_its_scans(tmp_path, monkeypatch):
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
    )

    scan_id, entry = await _a_running_scan(tmp_path)
    monkeypatch.setattr(mcp_server, "_serving_stdio", True)

    async with mcp_server._lifespan(mcp_server.mcp):
        pass

    assert entry.cancel_event.is_set()
    assert entry.status is MCScanStatus.CANCELLED
    assert scan_id not in mcp_tools._scan_tasks.values(), "the runner did not end"


@pytest.mark.asyncio
async def test_other_clients_closing_leave_the_scans_running(tmp_path, monkeypatch):
    """The in-process client and the HTTP transports enter the same lifespan."""
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
    )

    _, entry = await _a_running_scan(tmp_path)
    monkeypatch.setattr(mcp_server, "_serving_stdio", False)

    async with mcp_server._lifespan(mcp_server.mcp):
        pass

    assert not entry.cancel_event.is_set()
    assert entry.status is MCScanStatus.RUNNING
    entry.cancel_event.set()


@pytest.mark.asyncio
async def test_an_mcp_scan_runs_without_the_live_progress_display(
    tmp_path, monkeypatch
):
    """The Rich live display redraws from its own thread and swaps sys.stdout."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )
    from automated_security_helper.interactions import run_ash_scan as module

    calls = []
    monkeypatch.setattr(module, "run_ash_scan", lambda **kwargs: calls.append(kwargs))
    (tmp_path / "out").mkdir()
    scan_id = get_scan_registry().register_scan(
        directory_path=str(tmp_path), output_directory=str(tmp_path / "out")
    )

    await mcp_tools._run_scan_async(
        scan_id=scan_id,
        directory_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        severity_threshold=None,
    )

    assert calls and calls[0]["progress"] is False, calls
