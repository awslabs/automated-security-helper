# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace tools tell an unwritable session workspace from a missing profile.

A session's bound profile whose file is gone is written to the session's
workspace again when a tool needs it. That can fail for two reasons with two
owners: the profile is no longer registered (the caller's config, exit 3), or
it is registered and the workspace cannot be written (the server's failure,
exit 1, the cause's category, a warning for the operator). ``run_ash_scan`` and
``get_config`` already answer them apart. ``resolve_workspace`` and
``scan_workspace`` caught both as a ``RuntimeError`` and answered a config
refusal, exit 3, so a workspace permission read as the caller's own fault and
left nothing in the log. These tests ask the workspace tools through their own
entry points, where before only the error's type was pinned.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Iterator

import pytest

from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

SESSION = "workspace-session"


@pytest.fixture
def bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Dict[str, Path]]:
    """A registered profile bound to SESSION with its copy removed, and a workspace."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    root = tmp_path / "ws"
    project = root / "app"
    project.mkdir(parents=True)
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "app"}]}), encoding="utf-8"
    )
    operator_dir = tmp_path / "operator-profiles"
    operator_dir.mkdir()
    profile = operator_dir / "strict.ash.yaml"
    profile.write_text("project_name: strict-profile\n", encoding="utf-8")

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", f"{root}{os.pathsep}{tmp_path}")
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    profile_registry.set_profile_registry(
        profile_registry.register_profiles([f"strict={profile}"])
    )
    selected = mcp_select_profile("strict", session_id=SESSION)
    assert selected["success"] is True, selected
    Path(selected["config_path"]).unlink()
    yield {"ws": workspace_file}
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()


def _cannot_write(monkeypatch: pytest.MonkeyPatch) -> None:
    """The profile stays registered; writing it to the workspace is refused."""
    from automated_security_helper.cli.mcp import profile_registry

    def refused(sid, config, patched):
        raise PermissionError(13, "Permission denied", "config")

    monkeypatch.setattr(profile_registry, "materialize_session_binding", refused)


def _ask(tool: str, workspace_file: Path) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp import workspace

    ask = getattr(workspace, tool)
    return asyncio.run(ask(workspace_file=str(workspace_file), session_id=SESSION))


@pytest.mark.parametrize("tool", ["mcp_resolve_workspace", "mcp_scan_workspace"])
def test_an_unwritable_workspace_is_the_servers_failure(
    bound, monkeypatch, caplog, tool
) -> None:
    """Red at the base: exit 3, the config refusal, and nothing in the log."""
    _cannot_write(monkeypatch)

    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        response = _ask(tool, bound["ws"])

    assert response["success"] is False, response
    assert response["exit_code"] == 1, response
    assert response["error_type"] == "bound_profile_unavailable", response
    assert response["error_category"] == "permission_denied", response
    assert "Permission denied" in response["error"], response
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("could not be written" in text for text in warnings), warnings


@pytest.mark.parametrize("tool", ["mcp_resolve_workspace", "mcp_scan_workspace"])
def test_a_profile_no_longer_registered_stays_the_config_refusal(bound, tool) -> None:
    """The control: the other cause keeps its answer, exit 3, so the split above
    is by cause and not a blanket change of the arm."""
    from automated_security_helper.cli.mcp import profile_registry

    profile_registry.clear_profile_registry()

    response = _ask(tool, bound["ws"])

    assert response["success"] is False, response
    assert response["exit_code"] == 3, response
    assert "select_profile" in response["error"], response
