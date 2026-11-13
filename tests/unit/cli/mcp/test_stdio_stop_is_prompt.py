# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""When a stdio client leaves, its scans stop inside the window it gives.

The MCP SDK's stdio client sends SIGTERM two seconds after it closes a server's
stdin, and SIGKILL two seconds later. A server that gave each scanner's tool ten
seconds after SIGTERM and waited up to sixty seconds for its scans would leave a
tool that ignores SIGTERM still running when the client killed the server, and
the previous results still set aside. A stop because the process is going
away is prompt: the tool gets PROMPT_STOP_GRACE_SECONDS, and the server waits
at most STDIO_SCAN_STOP_TIMEOUT_SECONDS. A cancel_scan keeps the full
grace. tests/integration/cli/test_mcp_stdio_shutdown.py drives the same through
a real `ash mcp` process and the SDK's own client.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.cli import mcp_server, mcp_tools
from automated_security_helper.core.cancellation import CancelEvent
from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    holds_restored_results,
)
from automated_security_helper.core.resource_management.scan_registry import (
    get_scan_registry,
)
from automated_security_helper.utils import subprocess_utils
from tests.utils.processes import process_running

_ENGINE = (
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases"
)

IGNORES_SIGTERM = (
    "import os, pathlib, signal, sys, time\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
    "time.sleep(60)\n"
)


@pytest.mark.unit
def test_only_a_prompt_stop_shortens_the_grace():
    event = CancelEvent()
    assert subprocess_utils._stop_grace(event) == (
        subprocess_utils.SANDBOX_STOP_GRACE_SECONDS
    )
    event.stop_promptly = True
    assert subprocess_utils._stop_grace(event) == (
        subprocess_utils.PROMPT_STOP_GRACE_SECONDS
    )
    assert subprocess_utils._stop_grace(threading.Event()) == (
        subprocess_utils.SANDBOX_STOP_GRACE_SECONDS
    )


@pytest.mark.unit
def test_the_window_holds_the_stop():
    """The poll, the grace and the wait all fit before the client's SIGTERM."""
    assert (
        subprocess_utils.CANCEL_POLL_SECONDS
        + subprocess_utils.PROMPT_STOP_GRACE_SECONDS
        < mcp_server.STDIO_SCAN_STOP_TIMEOUT_SECONDS
        < 2.0
    )


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
@pytest.mark.integration
async def test_the_client_leaving_stops_a_tool_that_ignores_sigterm(
    tmp_path, monkeypatch
):
    from automated_security_helper.utils.subprocess_utils import run_command

    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "ash.sarif").write_text('{"previous": 1}', encoding="utf-8")
    pid_file = tmp_path / "tool.pid"

    def phases(*args, **kwargs):
        run_command([sys.executable, "-c", IGNORES_SIGTERM, str(pid_file)])
        raise AssertionError("not stopped")

    scan_id = get_scan_registry().register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    entry = get_scan_registry().get_scan(scan_id)
    monkeypatch.setattr(mcp_server, "_serving_stdio", True)
    with patch(_ENGINE, side_effect=phases):
        mcp_tools._start_scan_task(
            scan_id,
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(source),
                output_dir=str(output),
                severity_threshold=None,
            ),
        )
        import asyncio

        for _ in range(600):
            if await asyncio.to_thread(pid_file.exists):
                break
            await asyncio.sleep(0.05)
        started = time.monotonic()
        async with mcp_server._lifespan(mcp_server.mcp):
            pass
        took = time.monotonic() - started

    _assert_stopped_and_settled(entry, took, output, pid_file)


def _assert_stopped_and_settled(entry, took: float, output: Path, pid_file: Path):
    assert entry.runner_done.is_set(), (
        f"the scan was still stopping {took:.1f}s after the client left"
    )
    assert took < mcp_server.STDIO_SCAN_STOP_TIMEOUT_SECONDS + 0.5, took
    assert json.loads((output / "reports" / "ash.sarif").read_text()) == {"previous": 1}
    assert holds_restored_results(output)
    assert not (output / HELD_DIR_NAME).exists()
    # Not /proc alone: without one (macOS) a bare /proc read checks nothing.
    assert not process_running(int(pid_file.read_text())), (
        "the tool that ignores SIGTERM is still running"
    )
