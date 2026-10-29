#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP workspace tool exits 3 for an output directory reached through a link.

Why this file exists
--------------------
``ash`` exits 3 for every output directory it refuses because of a link
(``OUTPUT_DIR_REFUSED_EXIT_CODE``). The workspace tool refuses the same links in
``_prepare_project_outputs`` by raising ``OutputDirLinkRefused``, but the
exception-to-exit-code table had no entry for it, so the tool reported exit 1
("scan errors") for a refusal the CLI reports as 3.

Each cell drives the real ``mcp_scan_workspace`` with a link in place and checks
both the exit code and that nothing was written through the link. The control
makes the execution stage fail with an unrelated error: it proves the tool got
past the output check on an ordinary tree and that an unrelated failure is still 1.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="symlinks need privileges on Windows"
)

LINK_REFUSED = int(WorkspaceExitCode.INVALID_PROJECT_CONFIG)


@pytest.fixture(autouse=True)
def _clear_policy_env(monkeypatch):
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _workspace(root: Path) -> Path:
    (root / "api").mkdir(parents=True, exist_ok=True)
    path = root / "dev.code-workspace"
    path.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    return path


def _host(root: Path) -> Path:
    host = root / "host"
    host.mkdir()
    return host


def _untouched(host: Path) -> bool:
    return list(host.iterdir()) == []


async def _scan(workspace: Path, **kwargs) -> Dict[str, Any]:
    return await workspace_module.mcp_scan_workspace(
        workspace_file=str(workspace), **kwargs
    )


def test_the_documented_value_is_three():
    assert LINK_REFUSED == 3
    assert ASH_EXIT_CODES[3] == "invalid config or refused input"


def test_the_exception_maps_to_three():
    error = OutputDirLinkRefused("the output directory is a symlink")
    assert workspace_module._exit_code_for(error) == LINK_REFUSED


@needs_symlinks
@pytest.mark.asyncio
async def test_a_linked_dot_ash_reports_three(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    workspace = _workspace(root)
    host = _host(tmp_path)
    (root / ".ash").symlink_to(host, target_is_directory=True)

    response = await _scan(workspace)

    assert response["success"] is False
    assert response["exit_code"] == LINK_REFUSED
    assert "symlink" in response["error"]
    assert _untouched(host)


@needs_symlinks
@pytest.mark.asyncio
@pytest.mark.parametrize("linked", ["projects", "projects/api"])
async def test_a_linked_dir_inside_a_named_output_dir_reports_three(tmp_path, linked):
    root = tmp_path / "ws"
    root.mkdir()
    workspace = _workspace(root)
    host = _host(tmp_path)
    output = tmp_path / "out"
    link = output / linked
    link.parent.mkdir(parents=True)
    link.symlink_to(host, target_is_directory=True)

    response = await _scan(workspace, output_dir=str(output))

    assert response["success"] is False
    assert response["exit_code"] == LINK_REFUSED
    assert _untouched(host)


@pytest.mark.asyncio
async def test_an_unrelated_failure_with_no_link_is_still_one(tmp_path, monkeypatch):
    """Must-not-flag: the output tree is fine, so the failure comes from execution."""
    root = tmp_path / "ws"
    root.mkdir()
    workspace = _workspace(root)

    def _boom(*args, **kwargs):
        raise RuntimeError("an ASH bug, not a link")

    from automated_security_helper.workspace import execution as execution_module

    monkeypatch.setattr(execution_module, "execute_workspace", _boom)
    monkeypatch.setattr(workspace_module, "execute_workspace", _boom, raising=False)

    response = await _scan(workspace, output_dir=str(tmp_path / "out"))

    assert response["success"] is False
    assert response["exit_code"] == int(WorkspaceExitCode.INTERNAL_ERROR)
    assert "an ASH bug, not a link" in response["error"]
