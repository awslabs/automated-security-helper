# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""MCP resolve_workspace refuses a workspace root config the scan would refuse.

The workspace root's config sets how a workspace scan executes, and
scan_workspace refuses one that cannot be loaded with exit 3. resolve_workspace
is the MCP dry run; it answered success for the same workspace, so a client that
planned first was told the scan it was about to start would run.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.sandbox import (
    ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ASH_MCP_TRANSPORT_ENV,
)

GOOD = "global_settings:\n  severity_threshold: MEDIUM\n"


@pytest.fixture
def workspace(tmp_path, monkeypatch) -> Path:
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, raising=False)
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    root = tmp_path / "ws"
    for key in ("api", "web"):
        (root / key / ".ash").mkdir(parents=True)
        (root / key / ".ash" / ".ash.yaml").write_text(GOOD, encoding="utf-8")
    definition = root / "team.code-workspace"
    definition.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    return definition


def _resolve(definition: Path):
    from automated_security_helper.cli.mcp.workspace import mcp_resolve_workspace

    return asyncio.run(mcp_resolve_workspace(str(definition)))


def test_a_root_config_that_does_not_parse_is_refused_with_exit_3(workspace):
    root_config = workspace.parent / ".ash" / ".ash.yaml"
    root_config.parent.mkdir()
    root_config.write_text("workspace:\n  max_parallel_projects: [\n", encoding="utf-8")

    result = _resolve(workspace)

    assert result["success"] is False, result
    assert result["exit_code"] == 3, result
    assert ".ash.yaml" in result["error"]


def test_control_a_workspace_whose_root_config_loads_is_planned(workspace):
    root_config = workspace.parent / ".ash" / ".ash.yaml"
    root_config.parent.mkdir()
    root_config.write_text("workspace:\n  max_parallel_projects: 2\n", encoding="utf-8")

    result = _resolve(workspace)

    assert result["success"] is True, result
    assert result["exit_code"] == 0
