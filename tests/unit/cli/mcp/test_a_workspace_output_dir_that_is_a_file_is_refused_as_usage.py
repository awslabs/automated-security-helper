# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan refuses an output directory that is a file, exit 5.

A workspace scan writes its unified output into ``.ash/ash_output`` and each
project's into ``.ash/ash_output/projects/<key>``. Unrefused, a file at either of
those names would be reported two ways, both exit 1: at ``ash_output``, the
NotADirectoryError of creating the projects' directories below it; at a
project's directory, the registry's refusal, as an internal error. The scan
tools refuse the same file with ``Output directory is not a directory: <path>``,
``error_type`` ``output_dir_not_usable`` and exit code 5, the CLI's code for an
``--output-dir`` that is a file. The workspace tool does too, before any
project is registered or its directory created, and leaves the file as it was.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)

CONTENT = "a file\n"


@pytest.fixture(autouse=True)
def isolated_mcp_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp.sessions import (
        reset_default_registry_for_tests,
    )
    from automated_security_helper.core.resource_management import scan_registry

    registry = ScanRegistry()
    monkeypatch.setattr(scan_registry, "_scan_registry", registry)
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    reset_default_registry_for_tests()
    for name in ("ASH_MCP_ALLOWED_CONFIG_ROOTS", "ASH_MCP_TRANSPORT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "allowed"))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    (tmp_path / "allowed").mkdir()
    yield registry
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    reset_default_registry_for_tests()


@pytest.fixture
def executions(monkeypatch):
    """execute_workspace replaced by one that records it was reached, then fails."""
    reached = []

    def execute(plan, settings, **kwargs):
        reached.append(plan)
        raise RuntimeError("stand-in execution failed")

    monkeypatch.setattr(workspace_module, "execute_workspace", execute)
    return reached


def _ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.headers = None
    ctx.info = AsyncMock()
    ctx.debug = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.error = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _workspace(tmp_path: Path) -> Path:
    root = (tmp_path / "allowed" / "ws").resolve()
    for name in ("api", "web"):
        (root / name).mkdir(parents=True)
        (root / name / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    return workspace_file


#: Where the file is, below the workspace root.
FILES = {
    "the output directory": ".ash/ash_output",
    "a project's output directory": ".ash/ash_output/projects/api",
}


@pytest.mark.parametrize("where", sorted(FILES))
def test_a_file_where_the_output_goes_is_refused_as_usage(
    tmp_path, executions, isolated_mcp_state, where
):
    workspace_file = _workspace(tmp_path)
    blocker = workspace_file.parent / FILES[where]
    blocker.parent.mkdir(parents=True, exist_ok=True)
    blocker.write_text(CONTENT, encoding="utf-8")

    response = asyncio.run(
        mcp_server.run_ash_workspace_scan(_ctx(), workspace_file=str(workspace_file))
    )

    assert response["success"] is False, response
    assert response["error"] == f"Output directory is not a directory: {blocker}"
    assert response["error_type"] == "output_dir_not_usable", response
    assert response["exit_code"] == 5, response
    assert executions == [], "the workspace scan ran"
    assert isolated_mcp_state.list_scans() == [], "a project was registered"
    assert blocker.read_text(encoding="utf-8") == CONTENT
    assert not (workspace_file.parent / ".ash/ash_output/projects/web").exists()


def test_the_scan_tools_answer_the_same_file_alike(tmp_path, executions):
    """One file at .ash/ash_output, one answer, from both tools."""
    workspace_file = _workspace(tmp_path)
    blocker = workspace_file.parent / ".ash" / "ash_output"
    blocker.parent.mkdir(parents=True)
    blocker.write_text(CONTENT, encoding="utf-8")

    single = asyncio.run(
        mcp_server.run_ash_scan(_ctx(), source_dir=str(workspace_file.parent))
    )
    workspace = asyncio.run(
        mcp_server.run_ash_workspace_scan(_ctx(), workspace_file=str(workspace_file))
    )

    for field in ("error", "error_type", "error_category", "exit_code"):
        assert single[field] == workspace[field], (field, single, workspace)


def test_control_a_missing_output_directory_is_not_refused(tmp_path, executions):
    """No file in the way: the scan gets as far as running the projects."""
    workspace_file = _workspace(tmp_path)

    response = asyncio.run(
        mcp_server.run_ash_workspace_scan(_ctx(), workspace_file=str(workspace_file))
    )

    assert response.get("error_type") != "output_dir_not_usable", response
    assert len(executions) == 1, response
