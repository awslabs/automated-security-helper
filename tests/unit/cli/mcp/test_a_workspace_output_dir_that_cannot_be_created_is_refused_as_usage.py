# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan refuses an output directory that cannot be created, exit 5.

A workspace scan writes into ``.ash/ash_output`` and each project's output into
``.ash/ash_output/projects/<key>``. When ``.ash`` or ``projects`` is a file, the
projects' directories cannot be made under it; answering with the
NotADirectoryError of making them would be an internal error, exit 1. The call
refuses it before any project is registered, as the scan tools do: ``Output directory
cannot be created: <path> (Not a directory)``, ``error_type``
``output_dir_not_usable``, exit code 5. One that fails only when it is made,
under a ``projects`` that cannot be written, is refused the same way then, and
the projects' claims are given back.
"""

from __future__ import annotations

import asyncio
import json
import os
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
    profile_registry.clear_session_state()
    reset_default_registry_for_tests()
    for name in ("ASH_MCP_ALLOWED_CONFIG_ROOTS", "ASH_MCP_TRANSPORT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "allowed"))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    (tmp_path / "allowed").mkdir()
    yield registry
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()
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


def _scan(workspace_file: Path, **arguments) -> dict:
    return asyncio.run(
        mcp_server.run_ash_workspace_scan(
            _ctx(), workspace_file=str(workspace_file), **arguments
        )
    )


def _assert_refused(response: dict, text: str) -> None:
    assert response["success"] is False, response
    assert response["error"] == text, response
    assert response["error_type"] == "output_dir_not_usable", response
    assert response["exit_code"] == 5, response


#: Where the file is, below the workspace root, and the first output directory
#: that cannot be created because of it.
FILES = {
    ".ash": ".ash/ash_output",
    ".ash/ash_output/projects": ".ash/ash_output/projects/api",
}


@pytest.mark.parametrize("where", sorted(FILES))
def test_a_file_on_the_way_is_refused_before_any_project_is_registered(
    tmp_path, executions, isolated_mcp_state, where
):
    workspace_file = _workspace(tmp_path)
    root = workspace_file.parent
    blocker = root / where
    blocker.parent.mkdir(parents=True, exist_ok=True)
    blocker.write_text(CONTENT, encoding="utf-8")

    response = _scan(workspace_file)

    _assert_refused(
        response,
        f"Output directory cannot be created: {root / FILES[where]} (Not a directory)",
    )
    assert executions == [], "the workspace scan ran"
    assert isolated_mcp_state.list_scans() == [], "a project was registered"
    assert blocker.read_text(encoding="utf-8") == CONTENT


@pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0,
    reason="root, and Windows, create a directory in one without write permission",
)
def test_one_that_fails_when_it_is_made_is_refused_and_given_back(
    tmp_path, executions, isolated_mcp_state
):
    workspace_file = _workspace(tmp_path)
    projects = workspace_file.parent / ".ash" / "ash_output" / "projects"
    projects.mkdir(parents=True)
    projects.chmod(0o555)
    try:
        response = _scan(workspace_file)
    finally:
        projects.chmod(0o755)

    _assert_refused(
        response,
        f"Output directory cannot be created: {projects / 'api'} (Permission denied)",
    )
    assert executions == [], "the workspace scan ran"
    assert isolated_mcp_state.list_scans(active_only=True) == []
    assert list(projects.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="a symbolic link needs a privilege there")
def test_an_output_dir_that_is_a_link_to_nothing_is_refused(
    tmp_path, executions, isolated_mcp_state
):
    """It ended in the FileExistsError of making the projects' directories through
    it, exit 1, with the projects left registered. mkdir cannot make a directory
    where a link is, so it cannot be created, for the reason mkdir gives."""
    workspace_file = _workspace(tmp_path)
    output = workspace_file.parent / "out"
    output.symlink_to(workspace_file.parent / "nowhere")

    response = _scan(workspace_file, output_dir=str(output))

    _assert_refused(
        response, f"Output directory cannot be created: {output} (File exists)"
    )
    assert executions == [], "the workspace scan ran"
    assert isolated_mcp_state.list_scans() == [], "a project was registered"
    assert output.is_symlink() and not output.exists()


@pytest.mark.skipif(os.name == "nt", reason="a symbolic link needs a privilege there")
def test_a_link_to_nothing_on_the_way_to_the_output_dir_is_refused(
    tmp_path, executions, isolated_mcp_state
):
    """The link is a part of the path, not the path itself: mkdir -p fails on it
    with EEXIST all the same, so the output directory cannot be created."""
    workspace_file = _workspace(tmp_path)
    link = workspace_file.parent / "gone"
    link.symlink_to(workspace_file.parent / "nowhere")
    output = link / "out"

    response = _scan(workspace_file, output_dir=str(output))

    _assert_refused(
        response, f"Output directory cannot be created: {output} (File exists)"
    )
    assert executions == [], "the workspace scan ran"
    assert isolated_mcp_state.list_scans() == [], "a project was registered"
    assert link.is_symlink() and not link.exists()


@pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0,
    reason="root, and Windows, enter a directory without search permission",
)
def test_an_output_dir_that_cannot_be_entered_is_refused(
    tmp_path, executions, isolated_mcp_state
):
    """Mode 000: it ended in a PermissionError, exit 1."""
    workspace_file = _workspace(tmp_path)
    output = workspace_file.parent / "out"
    output.mkdir()
    output.chmod(0o000)
    try:
        response = _scan(workspace_file, output_dir=str(output))
    finally:
        output.chmod(0o755)

    _assert_refused(response, f"Output directory cannot be entered: {output}")
    assert executions == [], "the workspace scan ran"
    assert isolated_mcp_state.list_scans() == [], "a project was registered"
    assert list(output.iterdir()) == []


@pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0,
    reason="root, and Windows, write into a directory without write permission",
)
def test_one_that_is_there_but_cannot_be_written_is_refused(
    tmp_path, executions, isolated_mcp_state
):
    """The check makes and removes a file there, before any project is registered."""
    workspace_file = _workspace(tmp_path)
    output = workspace_file.parent / ".ash" / "ash_output"
    output.mkdir(parents=True)
    output.chmod(0o555)
    try:
        response = _scan(workspace_file)
        left = list(output.iterdir())
    finally:
        output.chmod(0o755)

    _assert_refused(
        response, f"Output directory cannot be written: {output} (Permission denied)"
    )
    assert executions == [], "the workspace scan ran"
    assert isolated_mcp_state.list_scans() == [], "a project was registered"
    assert left == []
