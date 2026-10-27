# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan the registry refuses leaves the output directory exactly as it was.

If run_ash_scan's clean_output set the previous results aside before it asked the
registry for the directory, and on a refusal put them back, then when the refusal
is because another scan is running there, the "previous results" it moved would be
that scan's own partial output, and the restore would remove what the running scan
was writing; after a cancel, the refused call would also remove the marker the
stopping scan is about to rely on. The same goes for the MCP workspace scan with
its projects' outputs.

So nothing touches an output directory until the registry has given the scan
that directory. A refused call changes nothing there, and there is nothing to
put back.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    RESTORED_MARKER_NAME,
    holds_restored_results,
)
from automated_security_helper.utils.output_dir_links import OUTPUT_GITIGNORE
from tests.utils.tasks import drain

_ENGINE = (
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases"
)

PREVIOUS = {
    "reports/ash.sarif": '{"previous": "sarif"}',
    "reports/ash.summary.md": "# previous summary\n",
    "scanners/bandit/source/ASH.ScanResults.json": '{"status": "PASSED"}',
    "ash_aggregated_results.json": json.dumps(
        {"scanner_results": {"bandit": {"status": "PASSED", "finding_count": 0}}}
    ),
}


def _files(output: Path) -> Dict[str, str]:
    return {
        p.relative_to(output).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(output.rglob("*"))
        if p.is_file() and not p.name.startswith("ash.log")
    }


def _seed(root: Path, files) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _project(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    return source, source / ".ash" / "ash_output"


async def _wait_for(path: Path) -> None:
    for _ in range(600):
        if await asyncio.to_thread(path.exists):
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"{path} never appeared")


@pytest.fixture
def _server(tmp_path, monkeypatch):
    from automated_security_helper.cli import mcp_server

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    return mcp_server, ctx


@pytest.mark.asyncio
async def test_a_second_run_ash_scan_on_a_busy_directory(tmp_path, _server):
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.subprocess_utils import run_command

    mcp_server, ctx = _server
    source, output = _project(tmp_path)
    _seed(output, PREVIOUS)
    started = tmp_path / "started"
    release = tmp_path / "release"

    def phases(*args, **kwargs):
        _seed(output, {"scanners/detect-secrets/A-PARTIAL.json": "A's own output"})
        run_command(
            [
                sys.executable,
                "-c",
                (
                    "import pathlib, sys, time\n"
                    "pathlib.Path(sys.argv[1]).touch()\n"
                    "r = pathlib.Path(sys.argv[2])\n"
                    "for _ in range(400):\n"
                    "    if r.exists(): break\n"
                    "    time.sleep(0.05)\n"
                ),
                str(started),
                str(release),
            ]
        )
        return AshAggregatedResults()

    with patch(_ENGINE, side_effect=phases):
        first = await mcp_server.run_ash_scan(ctx, source_dir=str(source))
        assert first["success"] is True, first
        await _wait_for(started)
        before = await asyncio.to_thread(_files, output)
        second = await mcp_server.run_ash_scan(ctx, source_dir=str(source))
        during = await asyncio.to_thread(_files, output)
        release.touch()
        await drain(timeout=40)

    assert second["success"] is False, second
    assert before == during, "the refused call changed the running scan's directory"
    assert "scanners/detect-secrets/A-PARTIAL.json" in during
    progress = await mcp_server.get_scan_progress(ctx, first["scan_id"])
    assert progress["status"] == "completed", progress
    assert progress["output_holds_previous_results"] is False
    after = _files(output)
    assert not {k for k, v in after.items() if PREVIOUS.get(k) == v}, sorted(after)


@pytest.mark.asyncio
async def test_a_refused_rescan_right_after_a_cancel(tmp_path, _server, monkeypatch):
    """The stopping scan still puts the previous results back and marks them."""
    from automated_security_helper.utils import subprocess_utils

    mcp_server, ctx = _server
    monkeypatch.setattr(subprocess_utils, "SANDBOX_STOP_GRACE_SECONDS", 2.0)
    source, output = _project(tmp_path)
    _seed(output, PREVIOUS)
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
                    "time.sleep(30)\n"
                ),
                str(started),
            ]
        )
        raise AssertionError("not stopped")

    with patch(_ENGINE, side_effect=phases):
        first = await mcp_server.run_ash_scan(ctx, source_dir=str(source))
        await _wait_for(started)
        cancelled = await mcp_server.cancel_scan(ctx, first["scan_id"])
        assert cancelled["success"] is True, cancelled
        second = await mcp_server.run_ash_scan(ctx, source_dir=str(source))
        await drain(timeout=40)

    assert second["success"] is False
    assert "still stopping" in second["error"], second
    progress = await mcp_server.get_scan_progress(ctx, first["scan_id"])
    assert progress["status"] == "cancelled", progress
    assert progress["output_holds_previous_results"] is True, progress
    assert holds_restored_results(output)
    files = _files(output)
    files.pop(RESTORED_MARKER_NAME, None)
    # The first scan, which did start, wrote the output directory's .gitignore
    # before its scanners (ASHScanOrchestrator.ensure_directories); it is not a
    # previous result and the restore leaves it.
    files.pop(OUTPUT_GITIGNORE, None)
    assert files == PREVIOUS


@pytest.mark.asyncio
async def test_a_refused_workspace_scan_leaves_the_running_projects_output(
    tmp_path, monkeypatch
):
    from automated_security_helper.cli.mcp import workspace as workspace_module
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
    )

    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    registry = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", registry)

    root = tmp_path / "work"
    (root / "api").mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8"
    )
    out = tmp_path / "out"
    project_output = out / "projects" / "api"
    # A scan of the project is running, writing into that directory, with the
    # previous results it set aside beside its output.
    _seed(project_output, {"scanners/bandit/source/ASH.ScanResults.json": "running"})
    _seed(project_output / HELD_DIR_NAME, PREVIOUS)
    running = registry.register_scan(
        directory_path=str(root / "api"), output_directory=str(project_output)
    )
    registry.update_scan_status(running, MCScanStatus.RUNNING)
    before = _files(project_output)

    def execute_workspace(plan, settings, **kwargs):
        raise AssertionError("a refused workspace scan must not run")

    monkeypatch.setattr(workspace_module, "execute_workspace", execute_workspace)
    response = await workspace_module.mcp_scan_workspace(
        workspace_file=str(workspace_file), output_dir=str(out), clean_output=True
    )

    assert response["success"] is False, response
    assert _files(project_output) == before
    assert not holds_restored_results(project_output)


def test_restore_takes_no_mark_argument():
    """Every restore leaves the marker: no caller restores without it."""
    import inspect

    from automated_security_helper.core.previous_results import PreviousResults

    assert "mark" not in inspect.signature(PreviousResults.restore).parameters
