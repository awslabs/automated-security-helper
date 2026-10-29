# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A link in the output tree is refused with exit code 3, by both scan tools.

A single-directory scan and a workspace scan both write below ``.ash/ash_output``
by default, and both refuse a link at ``.ash`` or ``.ash/ash_output`` before they
write anything, through the same check (scan_target.validate_output_tree). The two
must report the refusal alike: exit code 4, the workspace scan's code for a
workspace definition, policy or confinement refusal, would send the client
to the workspace file or the allowed roots when neither is at fault, and no exit
code at all says less still.

A linked output path is a refused input, so both report exit code 3. For the
same tree with the same link, the two core functions return the same error,
error_type, error_category and context, and the two MCP tools the same exit_code
and error_category.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Dict
from unittest.mock import AsyncMock, MagicMock

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.cli.mcp_tools import mcp_scan_directory
from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)

pytestmark = pytest.mark.unit

#: The components both scans write through when no output directory is named.
SHARED_COMPONENTS = [".ash", ".ash/ash_output"]


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


def _ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.headers = None
    ctx.info = AsyncMock()
    ctx.debug = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.error = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _linked_tree(tmp_path: Path, linked: str) -> Path:
    """A workspace root, also a scan target, with ``linked`` a link to outside.

    Returns the workspace file. Its directory is the target the single-directory
    scan is given, so both scans meet the same link in the same tree.
    """
    root = tmp_path / "allowed" / "ws"
    for name in ("api", "web"):
        (root / name).mkdir(parents=True)
        (root / name / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("outside\n", encoding="utf-8")
    link = root / linked
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside, target_is_directory=True)
    return workspace_file


def _contents(directory: Path) -> Dict[str, str]:
    return {
        p.relative_to(directory).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(directory.rglob("*"))
        if p.is_file()
    }


@pytest.mark.parametrize("linked", SHARED_COMPONENTS)
def test_both_scans_refuse_the_same_link_with_exit_code_3(tmp_path, executions, linked):
    workspace_file = _linked_tree(tmp_path, linked)
    before = _contents(tmp_path / "outside")

    single = asyncio.run(mcp_scan_directory(directory_path=str(workspace_file.parent)))
    workspace = asyncio.run(
        workspace_module.mcp_scan_workspace(workspace_file=str(workspace_file))
    )

    assert single["success"] is False, single
    assert workspace["success"] is False, workspace
    assert single.get("exit_code") == 3, single
    assert workspace.get("exit_code") == 3, workspace
    for response in (single, workspace):
        assert response["exit_code_meaning"] == ASH_EXIT_CODES[3], response
    for field in ("error", "error_type", "error_category", "context"):
        assert single[field] == workspace[field], (field, single, workspace)
    assert single["context"]["output_component"] == linked, single
    assert executions == [], "the workspace scan ran with a linked output tree"
    assert _contents(tmp_path / "outside") == before


@pytest.mark.parametrize("linked", SHARED_COMPONENTS)
def test_both_tools_refuse_the_same_link_with_exit_code_3(tmp_path, executions, linked):
    workspace_file = _linked_tree(tmp_path, linked)

    single = asyncio.run(
        mcp_server.run_ash_scan(_ctx(), source_dir=str(workspace_file.parent))
    )
    workspace = asyncio.run(
        mcp_server.run_ash_workspace_scan(_ctx(), workspace_file=str(workspace_file))
    )

    assert single["success"] is False, single
    assert workspace["success"] is False, workspace
    assert single.get("exit_code") == 3, single
    assert workspace.get("exit_code") == 3, workspace
    for field in ("error", "error_category", "exit_code_meaning"):
        assert single[field] == workspace[field], (field, single, workspace)
    assert executions == []


def test_a_scan_target_with_a_broken_tool_ash_table_is_answered_not_raised(tmp_path):
    """A pin on the scan-start path: discovery reads the target's pyproject.toml
    to learn whether it configures ASH, and one that declares [tool.ash] but
    cannot be parsed fails that read with the same error class get_config's
    discovery fix handles. The scan-start config pre-check catches it where it
    is raised and answers a response, never a raise out of the tool, and no
    scan is registered or started for a config that cannot be loaded."""
    target = tmp_path / "allowed" / "project"
    target.mkdir(parents=True, exist_ok=True)
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    (target / "pyproject.toml").write_text(
        "[tool.ash]\nproject_name = [unclosed\n", encoding="utf-8"
    )

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )

    async def _scan_to_its_end():
        answer = await mcp_scan_directory(directory_path=str(target))
        # One await drives any backgrounded scan to its terminal state before
        # the loop closes; the start has already answered.
        await asyncio.gather(*mcp_tools._scan_tasks)
        return answer

    response = asyncio.run(_scan_to_its_end())

    # The start answers: the scan-start config pre-check in cli/mcp_tools.py
    # (its ASHConfigValidationError arm at the discovery read) refuses an
    # unloadable discovered config as a response before register_scan runs.
    # What this pins is the boundary: no raise reaches the caller, and the
    # refusal registers and starts nothing.
    assert isinstance(response, dict), response
    assert response.get("success") is False, response
    assert response.get("error_type") == "MCPResourceError", response
    assert "cannot be loaded" in response.get("error", ""), response
    assert "scan_id" not in response, response
    registered_here = [
        scan
        for scan in get_scan_registry().list_scans()
        if str(getattr(scan, "directory_path", "")) == str(target)
    ]
    assert registered_here == [], registered_here
    assert not mcp_tools._scan_tasks, mcp_tools._scan_tasks
