# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancelled scan keeps its directory until its thread has stopped.

Why this file exists
--------------------
cancel_scan closes the registry entry as cancelled at once, and the scan's
thread then takes up to SANDBOX_STOP_GRACE_SECONDS (10 s) to stop its
scanner's child process, after which it puts the previous scan's results back
(core/previous_results.py). If register_scan refused a second scan of a directory
only while an entry was active, a scan started in that window would run beside
the one still stopping, and the restore would remove what the new scan had
written. The same window follows a scan stopped by scan_timeout_seconds, and a
runner task cancelled at server shutdown.

An entry with a runner occupies its directory until the runner's thread has
stopped (occupies_its_directory), and the refusal says the scan is still
stopping. It counts against max_concurrent_scans for that time too, since it is
still running on the host.
"""

from __future__ import annotations

import asyncio
import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    get_scan_registry,
)
from tests.utils.tasks import drain

_ENGINE = (
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases"
)


def _directory(tmp_path):
    source = tmp_path / "project"
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    return source, output


@pytest.mark.unit
def test_a_closed_entry_whose_runner_runs_still_occupies_the_directory(tmp_path):
    source, output = _directory(tmp_path)
    registry = get_scan_registry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    entry = registry.get_scan(scan_id)
    entry.has_runner = True
    registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
    registry.cancel_scan(scan_id)

    with pytest.raises(MCPResourceError, match="still stopping"):
        registry.register_scan(directory_path=str(source), output_directory=str(output))
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(MCPResourceError, match="max_concurrent_scans"):
        registry.register_scan(
            directory_path=str(other), output_directory=str(output), max_active=1
        )

    entry.runner_done.set()
    assert registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )


@pytest.mark.unit
def test_an_entry_without_a_runner_frees_the_directory_when_it_closes(tmp_path):
    """Workspace projects and direct registrations have no runner to wait for."""
    source, output = _directory(tmp_path)
    registry = get_scan_registry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
    registry.cancel_scan(scan_id)

    assert registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_a_rescan_right_after_a_cancel_waits_for_the_cancelled_one(
    tmp_path, monkeypatch
):
    from mcp.server.mcpserver import Context

    from automated_security_helper.cli import mcp_server
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    # The scanner below ignores SIGTERM, so it is stopped by the SIGKILL that
    # follows the grace period; a short one keeps the test quick and the
    # stopping window wide enough to start a second scan in.
    monkeypatch.setattr(subprocess_utils, "SANDBOX_STOP_GRACE_SECONDS", 2.0)
    source, output = _directory(tmp_path)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    previous = output / "reports" / "ash.sarif"
    previous.parent.mkdir()
    previous.write_text('{"previous": true}', encoding="utf-8")
    started = tmp_path / "started"

    def phases(*args, **kwargs):
        subprocess_utils.run_command(
            [
                sys.executable,
                "-c",
                (
                    "import pathlib, signal, sys, time\n"
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                    "pathlib.Path(sys.argv[1]).touch()\n"
                    "time.sleep(60)\n"
                ),
                str(started),
            ]
        )
        raise AssertionError("the scan was not stopped")

    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    with patch(_ENGINE, side_effect=phases):
        first = await mcp_server.run_ash_scan(ctx, source_dir=str(source))
        assert first["success"] is True, first
        for _ in range(600):
            if await asyncio.to_thread(started.exists):
                break
            await asyncio.sleep(0.05)
        cancelled = await mcp_server.cancel_scan(ctx, first["scan_id"])
        assert cancelled["success"] is True, cancelled

        second = await mcp_server.run_ash_scan(ctx, source_dir=str(source))
        assert second["success"] is False, (
            "a second scan started while the cancelled one was still stopping"
        )
        assert "still stopping" in json.dumps(second), second

        await drain(timeout=40)

    assert previous.read_text(encoding="utf-8") == '{"previous": true}'
    assert get_scan_registry().register_scan(
        directory_path=str(source), output_directory=str(output)
    ), "the directory stayed occupied after the cancelled scan stopped"
