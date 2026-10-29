# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``cancel_scan`` stops the scan it reports cancelled.

Why this file exists
--------------------
An MCP scan runs ``run_ash_scan`` in a thread of the server's own process.
``ScanRegistry.cancel_scan`` marked the entry cancelled and, finding no process
id to signal, logged a warning and returned True, so the tool answered
``"Scan cancelled successfully"`` while the thread ran every scanner to the end
and wrote its results and reports. Measured against a live server: cancelled at
21:31:02, results written at 21:31:10.

The scan launcher here is replaced by one that behaves like a scan for the
purpose: it starts a child process through ASH's own choke point
(``subprocess_utils.run_command``, which every scanner's tool goes through) and,
when that returns, writes a results file. Two moments are covered:

- cancelled while the child runs: the child is stopped, not left running, and
  the scan ends without writing anything;
- cancelled before the next child starts: that child never starts.

A cancel that only records the request leaves the child running for its full
duration, and the results file appears afterwards.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from tests.utils.tasks import drain as _drain

_LAUNCHER = "automated_security_helper.interactions.run_ash_scan.run_ash_scan"

#: How long the stand-in scanner's child runs when nothing stops it. Long enough
#: that a scan which ignores the cancel cannot finish inside STOPPED_WITHIN.
CHILD_SECONDS = 10.0

#: How soon after cancel_scan returns the scan must be over.
STOPPED_WITHIN = 5.0

#: The child: records its pid where the test can see it, then works for a while.
_CHILD = (
    "import os, pathlib, sys, time; "
    "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
    f"time.sleep({CHILD_SECONDS})"
)


@pytest.fixture(autouse=True)
def isolated_mcp_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp.sessions import (
        reset_default_registry_for_tests,
    )
    from automated_security_helper.core.resource_management import scan_registry

    monkeypatch.setattr(scan_registry, "_scan_registry", ScanRegistry())
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    reset_default_registry_for_tests()
    for name in ("ASH_MCP_ALLOWED_CONFIG_ROOTS", "ASH_MCP_TRANSPORT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "allowed"))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    (tmp_path / "allowed").mkdir()
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    yield
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    reset_default_registry_for_tests()


def _write_results(kwargs: Dict[str, Any]) -> None:
    output = Path(kwargs["output_dir"])
    output.mkdir(parents=True, exist_ok=True)
    (output / "ash_aggregated_results.json").write_text(
        json.dumps({"scanner_results": {}, "metadata": {}}), encoding="utf-8"
    )


def _run_child(pid_file: Path) -> None:
    from automated_security_helper.utils.subprocess_utils import run_command

    run_command([sys.executable, "-c", _CHILD, str(pid_file)])


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "allowed" / "project"
    project.mkdir(parents=True)
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    return project


def _ctx() -> MagicMock:
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    return ctx


async def _appears(path: Path, timeout: float) -> bool:
    """Whether ``path`` exists within ``timeout`` seconds."""
    deadline = time.monotonic() + timeout
    while not await asyncio.to_thread(path.exists):
        if time.monotonic() > deadline:
            return False
        await asyncio.sleep(0.05)
    return True


def _alive(pid: int) -> Optional[bool]:
    """Whether ``pid`` is a running process, or None where that cannot be asked."""
    if os.name != "posix":
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


async def _stop_and_measure(ctx, scan_id: str) -> float:
    """Cancel, then wait for the scan to end; seconds it ran on after the cancel."""
    cancelled = await mcp_server.cancel_scan(ctx, scan_id)
    assert cancelled["success"] is True, cancelled
    cancelled_at = time.monotonic()
    # Bounded so that a scan which ignores the cancel still ends the test, once
    # its child exits by itself, and fails on the assertions rather than hanging.
    await _drain(timeout=CHILD_SECONDS + 30)
    return time.monotonic() - cancelled_at


@pytest.mark.asyncio
async def test_cancelling_during_a_scanner_stops_its_child_and_the_scan(
    tmp_path, monkeypatch
):
    pid_file = tmp_path / "child.pid"

    def scan(**kwargs: Any):
        _run_child(pid_file)
        _write_results(kwargs)

    monkeypatch.setattr(_LAUNCHER, scan)
    project = _project(tmp_path)
    results_file = project / ".ash" / "ash_output" / "ash_aggregated_results.json"
    ctx = _ctx()

    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(project))
    assert begun["success"] is True, begun
    assert await _appears(pid_file, 30), "the stand-in scanner never started"
    child_pid = int(pid_file.read_text())

    ran_on_for = await _stop_and_measure(ctx, begun["scan_id"])

    after_cancel = {
        "seconds_the_scan_ran_on": round(ran_on_for, 1),
        "results_file_written": results_file.exists(),
        "child_still_running": _alive(child_pid),
    }
    assert (
        ran_on_for < STOPPED_WITHIN
        and not after_cancel["results_file_written"]
        and not after_cancel["child_still_running"]
    ), (
        f"cancel_scan reported success, and then: {after_cancel} (the stand-in "
        f"scanner runs {CHILD_SECONDS:.0f}s when nothing stops it)"
    )
    progress = await mcp_server.get_scan_progress(ctx, begun["scan_id"])
    assert progress["status"] == "cancelled", progress


@pytest.mark.asyncio
async def test_cancelling_between_scanners_starts_no_further_child(
    tmp_path, monkeypatch
):
    pid_file = tmp_path / "child.pid"
    between = threading.Event()
    proceed = threading.Event()

    def scan(**kwargs: Any):
        # The first scanner has finished; the next is about to start.
        between.set()
        proceed.wait(30)
        _run_child(pid_file)
        _write_results(kwargs)

    monkeypatch.setattr(_LAUNCHER, scan)
    project = _project(tmp_path)
    results_file = project / ".ash" / "ash_output" / "ash_aggregated_results.json"
    ctx = _ctx()

    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(project))
    assert begun["success"] is True, begun
    assert await asyncio.to_thread(between.wait, 30), "the scan never started"

    cancelled = await mcp_server.cancel_scan(ctx, begun["scan_id"])
    assert cancelled["success"] is True, cancelled
    proceed.set()
    await _drain(timeout=CHILD_SECONDS + 30)

    assert not pid_file.exists(), "a child started after the scan was cancelled"
    assert not results_file.exists(), "the cancelled scan wrote its results file"


@pytest.mark.asyncio
async def test_cancelling_a_finished_scan_reports_that_it_was_not_running(
    tmp_path, monkeypatch
):
    """Unchanged: only a running scan can be cancelled."""
    monkeypatch.setattr(_LAUNCHER, lambda **kwargs: None)
    ctx = _ctx()
    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(_project(tmp_path)))
    await _drain()

    result = await mcp_server.cancel_scan(ctx, begun["scan_id"])

    assert result["success"] is False, result
    assert result["status"] == "completed", result


def test_outside_a_scan_a_command_is_not_polled():
    """With no cancel scope, the CLI's spawns are not polled or stopped."""
    from automated_security_helper.utils.subprocess_utils import run_command

    result = run_command([sys.executable, "-c", "print('ok')"])

    assert result.returncode == 0
    assert result.stdout.strip() == "ok"
