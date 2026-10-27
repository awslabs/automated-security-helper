# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace project's own config is read only when the caller may read it.

Why this exists
---------------
The MCP workspace tools check the two config files a caller names (the workspace
definition and its policy) against the session's roots, and project confinement
checks every project directory. The config a project's directory holds needs a
check of its own: were resolution to find ``<project>/.ash/ash.yaml`` and load it
unchecked, a project config linked out of the permitted roots would be read, and
``resolve_workspace`` would return what it set (``display_label``,
``severity_threshold``) and the outside path itself as ``config_source``.

The session's gate (``sandbox.config_base_gate``) goes through resolution to
the project config's discovery and to its ``extends`` chain, as it does for a
single-directory scan, so such a config is refused before it is read, and the
refusal carries neither its contents nor its path.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict

import pytest

SESSION = "client-one"
MARKER = "OUTSIDE-THE-ROOTS-MARKER"


@pytest.fixture
def layout(tmp_path, monkeypatch) -> Dict[str, Path]:
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    root = tmp_path / "ws"
    project = root / "app"
    (project / ".ash").mkdir(parents=True)
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "app"}]}), encoding="utf-8"
    )
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    outside_config = outside / "ash.yaml"
    outside_config.write_text(
        f"project_name: {MARKER}\nglobal_settings:\n  severity_threshold: CRITICAL\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(root))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    return {
        "root": root,
        "project": project,
        "workspace_file": workspace_file,
        "outside": outside,
        "outside_config": outside_config,
    }


def _resolve(workspace_file: Path) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp.workspace import mcp_resolve_workspace

    return asyncio.run(
        mcp_resolve_workspace(workspace_file=str(workspace_file), session_id=SESSION)
    )


def _assert_carries_nothing_from_outside(
    response: Dict[str, Any], outside: Path, *, path_as_written: bool = False
):
    """Nothing the outside file holds, and not its path.

    ``path_as_written``: the in-tree config itself names the outside path (an
    ``extends`` entry), and a refusal names that entry as written, which is the
    client's own text; the outside file's contents still must not appear.
    """
    text = json.dumps(response, default=str)
    assert MARKER not in text, response
    assert "CRITICAL" not in text, response
    if not path_as_written:
        assert str(outside) not in text, response


def _assert_a_confinement_refusal(response: Dict[str, Any]) -> None:
    """Reported as a refused config is elsewhere: the same error_type, and the
    config code 3 that run_ash_scan gives it and the CLI exits with for a config
    whose chain leaves its root."""
    assert response["success"] is False, response
    assert response["error_type"] == "config_input_not_permitted", response
    assert response["exit_code"] == 3, response


def test_a_project_config_linked_out_of_the_roots_is_refused(layout) -> None:
    link = layout["project"] / ".ash" / "ash.yaml"
    link.symlink_to(layout["outside_config"])

    response = _resolve(layout["workspace_file"])

    _assert_a_confinement_refusal(response)
    _assert_carries_nothing_from_outside(response, layout["outside"])


def test_a_workspace_scan_refuses_it_before_any_project_starts(
    layout, monkeypatch
) -> None:
    from automated_security_helper.cli.mcp import workspace as mcp_workspace

    (layout["project"] / ".ash" / "ash.yaml").symlink_to(layout["outside_config"])
    started: list = []
    monkeypatch.setattr(
        mcp_workspace,
        "execute_workspace",
        lambda *args, **kwargs: started.append(True),
    )

    response = asyncio.run(
        mcp_workspace.mcp_scan_workspace(
            workspace_file=str(layout["workspace_file"]), session_id=SESSION
        )
    )

    _assert_a_confinement_refusal(response)
    _assert_carries_nothing_from_outside(response, layout["outside"])
    assert started == [], "a project started"


def test_a_project_config_linked_to_a_missing_outside_file_is_refused(layout) -> None:
    """Refused as a link to a present file is, so the answer does not say
    whether the outside path exists."""
    (layout["project"] / ".ash" / "ash.yaml").symlink_to(
        layout["outside"] / "not-there.yaml"
    )

    response = _resolve(layout["workspace_file"])

    _assert_a_confinement_refusal(response)
    _assert_carries_nothing_from_outside(response, layout["outside"])


def test_a_project_pyproject_linked_out_of_the_roots_is_refused(layout) -> None:
    """Discovery reads a pyproject.toml to see whether it configures ASH."""
    outside_pyproject = layout["outside"] / "pyproject.toml"
    outside_pyproject.write_text(
        f'[tool.ash]\nproject_name = "{MARKER}"\n', encoding="utf-8"
    )
    (layout["project"] / "pyproject.toml").symlink_to(outside_pyproject)

    response = _resolve(layout["workspace_file"])

    _assert_a_confinement_refusal(response)
    _assert_carries_nothing_from_outside(response, layout["outside"])


def test_a_project_config_extending_out_of_the_roots_is_refused(layout) -> None:
    """Also refused by the CLI's own confinement of a chain to
    its project; kept so the gate's route through resolution covers it."""
    config = layout["project"] / ".ash" / "ash.yaml"
    config.write_text(
        f"extends: {json.dumps(str(layout['outside_config']))}\n", encoding="utf-8"
    )

    response = _resolve(layout["workspace_file"])

    assert response["success"] is False, response
    _assert_carries_nothing_from_outside(
        response, layout["outside"], path_as_written=True
    )


def test_one_refusal_kind_one_code_across_the_tools(layout) -> None:
    """config_input_not_permitted carries the same code from every scan tool."""
    from unittest.mock import AsyncMock, MagicMock

    from automated_security_helper.cli.mcp_server import run_ash_scan

    (layout["project"] / ".ash" / "ash.yaml").symlink_to(layout["outside_config"])
    workspace = _resolve(layout["workspace_file"])
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": SESSION}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    scan = asyncio.run(
        run_ash_scan(
            ctx=ctx,
            source_dir=str(layout["project"]),
            config_path=str(layout["outside_config"]),
        )
    )

    assert scan["error_type"] == workspace["error_type"], (scan, workspace)
    assert scan["exit_code"] == workspace["exit_code"] == 3, (scan, workspace)


def test_control_an_in_tree_project_config_is_read(layout) -> None:
    config = layout["project"] / ".ash" / "ash.yaml"
    config.write_text(
        "project_name: in-tree\nglobal_settings:\n  severity_threshold: HIGH\n",
        encoding="utf-8",
    )

    response = _resolve(layout["workspace_file"])

    assert response["success"] is True, response
    (project,) = response["projects"]
    assert project["severity_threshold"] == "HIGH", project
    assert Path(project["config_source"]).resolve() == config.resolve(), project
