# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace project's config that is a symlink is judged by the link, at plan and scan time.

A workspace is resolved once into a plan and then each project's config is
resolved again when the project is scanned (``workspace/execution.py``). Both
resolutions read the config by the path the project's directory holds it at,
so a ``.ash/.ash.yaml`` that links to a file outside the tree is held to the
limits of a config inside the tree on the CLI, and to a client's limits when an
MCP client delivered the tree, as a single-directory scan holds it.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, List
from unittest.mock import patch

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
)
from tests.utils.delivered_trees import clone, symlink, write

SESSION = "client-1"

SUPPRESSIONS = (
    "project_name: linked\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - rule_id: B101\n"
    "      path: 'tests/**'\n"
    "      reason: asserts in tests\n"
)


class _Stop(Exception):
    pass


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    workspace = tmp_path / "workspaces"
    host = tmp_path / "host"
    host.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    clear_profile_registry()
    clear_session_state()
    yield {"workspace": workspace, "host": host, "tmp": tmp_path}
    clear_profile_registry()
    clear_session_state()


def _grants(tmp_path: Path) -> str:
    granted = tmp_path / "granted"
    granted.mkdir(exist_ok=True)
    return yaml.safe_dump(
        {"project_name": "g", "sandbox": {"extra_read_paths": [str(granted)]}}
    )


def _cli_workspace(tmp_path: Path, layout: str) -> Path:
    """A workspace on disk whose one project's config is in place or an outward link."""
    root = tmp_path / "wsroot"
    workspace = write(
        root / "dev.code-workspace", json.dumps({"folders": [{"path": "app"}]})
    )
    write(root / "app" / "main.py", "x = 1\n")
    target = root / "app" / ".ash" / ".ash.yaml"
    if layout == "in place":
        write(target, _grants(tmp_path))
    else:
        symlink(target, write(tmp_path / "outside" / "grant.yaml", _grants(tmp_path)))
    return workspace


def _delivered_workspace(server, text: str) -> Path:
    """A delivered workspace whose project config links to a host file holding ``text``."""
    host_file = write(server["host"] / "ash.yaml", text)
    return clone(
        server["tmp"],
        {
            "dev.code-workspace": json.dumps({"folders": [{"path": "app"}]}),
            "app/main.py": "x = 1\n",
        },
        {"app/.ash/.ash.yaml": host_file},
        SESSION,
    )


# ---------------------------------------------------------------------------
# The plan and the scan both read the config by its path in the project
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("layout", ["in place", "linked out"])
def test_a_cli_workspace_scan_confines_a_project_configs_grants(
    tmp_path: Path, layout: str
) -> None:
    """As a single-directory scan of the same project does."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.workspace import execution
    from automated_security_helper.workspace.resolver import resolve_workspace

    workspace = _cli_workspace(tmp_path, layout)

    plan = resolve_workspace(workspace)
    (project,) = plan.projects
    settings = execution.ProjectScanSettings(output_dir=tmp_path / "out")
    config = execution._project_config_with_policy(project, settings)

    assert list(config.sandbox.extra_read_paths) == []
    single = resolve_config(source_dir=workspace.parent / "app")
    assert list(single.sandbox.extra_read_paths) == []


def test_the_plan_names_a_linked_project_config_by_its_path_in_the_project(
    tmp_path: Path,
) -> None:
    from automated_security_helper.workspace.resolver import resolve_workspace

    workspace = _cli_workspace(tmp_path, "linked out")

    (project,) = resolve_workspace(workspace).projects

    assert (
        project.config_source
        == (workspace.parent.resolve() / "app" / ".ash" / ".ash.yaml").as_posix()
    )


def test_an_mcp_workspace_scan_marks_a_delivered_links_suppressions(
    _server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The host file is in a directory the operator set aside, so it is read."""
    from automated_security_helper.cli.mcp import workspace as ws
    from automated_security_helper.workspace import execution

    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(_server["host"]))
    source = _delivered_workspace(_server, SUPPRESSIONS)
    real = execution._project_config_with_policy
    resolved: List[Any] = []

    def stop_after(project, settings):
        resolved.append(real(project, settings))
        raise _Stop

    with patch.object(execution, "_project_config_with_policy", stop_after):
        try:
            asyncio.run(
                ws.mcp_scan_workspace(
                    str(source / "dev.code-workspace"), session_id=SESSION
                )
            )
        except _Stop:
            pass

    assert resolved, "the scan never resolved the project's config"
    suppressions = resolved[-1].global_settings.suppressions
    assert [entry.client_supplied for entry in suppressions] == [True]
