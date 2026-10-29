# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan refuses an output tree with a link in it, before it moves anything.

A single scan checks every component of ``.ash/ash_output`` for a link before it
writes (scan_target.validate_output_tree). The workspace scan has to as well: its
project outputs are ``<output>/projects/<key>``, under the workspace root by
default, and a scanned repository controls what sits there. With ``projects/api``
a link to a directory outside, an unchecked scan would set that directory's
results aside into ``outside/.ash_previous_results``, then put them back and
write its marker there when the scan failed: moves and writes in a directory
nobody named.

The scan checks the default tree from the workspace root (``.ash``,
``ash_output``, ``projects``, each project key) and a caller-named output
directory from itself (``projects`` and each key), and refuses with exit code 3,
as a single scan refuses a link in its output tree, before it registers, creates
or moves anything.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Dict

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)

pytestmark = pytest.mark.unit

PREVIOUS = {
    "reports/ash.sarif": '{"previous": "sarif"}',
    "ash_aggregated_results.json": '{"previous": "results"}',
}


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
    yield
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


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "allowed" / "ws"
    for name in ("api", "web"):
        (root / name).mkdir(parents=True)
        (root / name / "app.py").write_text("x = 1\n", encoding="utf-8")
    path = root / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    return path


def _outside(tmp_path: Path, below: str) -> Path:
    """A directory outside the workspace, holding previous results at ``below``."""
    outside = tmp_path / "outside"
    for rel, text in PREVIOUS.items():
        path = outside / below / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return outside


def _contents(directory: Path) -> Dict[str, str]:
    return {
        p.relative_to(directory).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(directory.rglob("*"))
        if p.is_file()
    }


def _plant(base: Path, linked: str, outside: Path) -> None:
    link = base / linked
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside, target_is_directory=True)


DEFAULT_TREE = {
    ".ash": "ash_output/projects/api",
    ".ash/ash_output": "projects/api",
    ".ash/ash_output/projects": "api",
    ".ash/ash_output/projects/api": "",
}


@pytest.mark.parametrize("linked", list(DEFAULT_TREE), ids=list(DEFAULT_TREE))
def test_a_link_in_the_default_output_tree_refuses_the_scan(
    tmp_path, executions, linked
):
    workspace_file = _workspace(tmp_path)
    outside = _outside(tmp_path, DEFAULT_TREE[linked])
    before = _contents(outside)
    _plant(workspace_file.parent, linked, outside)

    response = asyncio.run(
        workspace_module.mcp_scan_workspace(workspace_file=str(workspace_file))
    )

    assert _contents(outside) == before, (
        f"the scan moved or wrote files through the link {linked}: "
        f"{sorted(_contents(outside))}"
    )
    assert response["success"] is False, response
    assert response["exit_code"] == 3, response
    assert executions == [], "the scan ran with a linked output tree"


@pytest.mark.parametrize("linked", ["projects", "projects/api"])
def test_a_link_in_a_caller_named_output_tree_refuses_the_scan(
    tmp_path, executions, linked
):
    workspace_file = _workspace(tmp_path)
    output = tmp_path / "allowed" / "out"
    output.mkdir()
    outside = _outside(tmp_path, "api" if linked == "projects" else "")
    before = _contents(outside)
    _plant(output, linked, outside)

    response = asyncio.run(
        workspace_module.mcp_scan_workspace(
            workspace_file=str(workspace_file), output_dir=str(output)
        )
    )

    assert _contents(outside) == before, sorted(_contents(outside))
    assert response["success"] is False, response
    assert response["exit_code"] == 3, response
    assert executions == []


def test_a_tree_with_no_link_scans(tmp_path, executions):
    """The check refuses links only: a real tree reaches execution."""
    workspace_file = _workspace(tmp_path)

    response = asyncio.run(
        workspace_module.mcp_scan_workspace(workspace_file=str(workspace_file))
    )

    assert len(executions) == 1, response
