# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace policy the workspace root holds is read only when the caller may read it.

Why this exists
---------------
The MCP workspace tools check a policy file the caller names
(``workspace_config``) against the session's roots, and the project configs a
workspace's projects hold since the session's gate reached resolution. The policy
file that discovery finds at the workspace root (``.ash-workspace.yaml`` and the
other names, there or in ``.ash/``) is checked against the roots like a named
one: a link from it to a file outside the roots is refused before anything is
read, naming neither the outside path nor its values.

The session's gate goes through to policy discovery, which checks every
candidate name as the config discovery does, by the entry itself (a link to a
file that is not there included) and before anything is read, and refuses one
outside the roots with ``config_input_not_permitted``, naming neither the outside
path nor anything in it.

A workspace definition or policy file the caller names outside the roots is the
same refusal of a config input, so it carries the same ``error_type`` and exit
code 3 as the discovered one; it was reported as a workspace error (4) under the
exception's class name.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest

# Importing it installs its audit hook, which records the opens of watched paths.
from tests.unit.cli.mcp import test_mcp_config_confinement as confinement

pytestmark = pytest.mark.unit

SESSION = "client-one"
MARKER = "OUTSIDE-POLICY-MARKER"
# A ceiling stricter than the project's MEDIUM, so a policy that applies shows.
OUTSIDE_POLICY = "workspace:\n  max_severity_threshold: LOW\n"
INVALID_OUTSIDE_POLICY = f"workspace:\n  max_severity_threshold: {MARKER}\n"


@pytest.fixture
def layout(tmp_path, monkeypatch) -> Dict[str, Path]:
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    root = tmp_path / "ws"
    project = root / "app"
    project.mkdir(parents=True)
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "app"}]}), encoding="utf-8"
    )
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(root))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    return {"root": root, "workspace_file": workspace_file, "outside": outside}


@pytest.fixture
def opened_policies():
    """``watch(path)`` starts recording every open of ``path``; returns the record."""

    def watch(path: Path) -> list:
        confinement._RECORDED_OPENS.clear()
        confinement._WATCHED_OPENS.append(os.path.realpath(path))
        return confinement._RECORDED_OPENS

    yield watch
    confinement._WATCHED_OPENS.clear()
    confinement._RECORDED_OPENS.clear()


def _resolve(workspace_file: Path) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp.workspace import mcp_resolve_workspace

    return asyncio.run(
        mcp_resolve_workspace(workspace_file=str(workspace_file), session_id=SESSION)
    )


def _assert_refused_with_nothing_from_outside(
    response: Dict[str, Any], outside: Path
) -> None:
    assert response["success"] is False, response
    assert response["error_type"] == "config_input_not_permitted", response
    assert response["exit_code"] == 3, response
    text = json.dumps(response, default=str)
    assert str(outside) not in text, response
    assert MARKER not in text, response


@pytest.mark.parametrize("name", [".ash-workspace.yaml", "ash-workspace.json"])
def test_a_policy_linked_out_of_the_roots_is_refused_unread(
    layout, opened_policies, name
) -> None:
    target = layout["outside"] / "policy.yaml"
    target.write_text(OUTSIDE_POLICY, encoding="utf-8")
    (layout["root"] / name).symlink_to(target)
    opened = opened_policies(target)

    response = _resolve(layout["workspace_file"])

    _assert_refused_with_nothing_from_outside(response, layout["outside"])
    assert opened == [], "the outside policy was opened"


def test_a_policy_linked_to_a_missing_outside_file_is_refused_alike(layout) -> None:
    """So the answer does not say whether the outside path exists."""
    (layout["root"] / ".ash-workspace.yaml").symlink_to(
        layout["outside"] / "not-there.yaml"
    )

    response = _resolve(layout["workspace_file"])

    _assert_refused_with_nothing_from_outside(response, layout["outside"])


def test_a_policy_under_a_linked_out_ash_directory_is_refused(
    layout, opened_policies
) -> None:
    (layout["outside"] / "ash-workspace.yaml").write_text(
        OUTSIDE_POLICY, encoding="utf-8"
    )
    (layout["root"] / ".ash").symlink_to(layout["outside"], target_is_directory=True)
    opened = opened_policies(layout["outside"] / "ash-workspace.yaml")

    response = _resolve(layout["workspace_file"])

    _assert_refused_with_nothing_from_outside(response, layout["outside"])
    assert opened == [], "the outside policy was opened"


def test_an_invalid_outside_policy_is_refused_without_its_values(layout) -> None:
    target = layout["outside"] / "policy.yaml"
    target.write_text(INVALID_OUTSIDE_POLICY, encoding="utf-8")
    (layout["root"] / ".ash-workspace.yaml").symlink_to(target)

    response = _resolve(layout["workspace_file"])

    _assert_refused_with_nothing_from_outside(response, layout["outside"])


def test_a_workspace_scan_refuses_it_before_any_project_starts(
    layout, monkeypatch
) -> None:
    from automated_security_helper.cli.mcp import workspace as mcp_workspace

    target = layout["outside"] / "policy.yaml"
    target.write_text(OUTSIDE_POLICY, encoding="utf-8")
    (layout["root"] / ".ash-workspace.yaml").symlink_to(target)
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

    _assert_refused_with_nothing_from_outside(response, layout["outside"])
    assert started == [], "a project started"


TOOLS = ["mcp_resolve_workspace", "mcp_scan_workspace"]
SAME = ("error_type", "exit_code", "exit_code_meaning")


def _call(tool: str, monkeypatch, **kwargs: Any) -> Dict[str, Any]:
    """*tool* for this session, with no project allowed to start."""
    from automated_security_helper.cli.mcp import workspace as mcp_workspace

    def _no_project_starts(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("a project started")

    monkeypatch.setattr(mcp_workspace, "execute_workspace", _no_project_starts)
    return asyncio.run(getattr(mcp_workspace, tool)(session_id=SESSION, **kwargs))


@pytest.mark.parametrize("tool", TOOLS)
def test_a_policy_the_caller_names_is_refused_as_a_discovered_one(
    layout, monkeypatch, tool
) -> None:
    """The same outside file, named and then found: one error_type, one code."""
    target = layout["outside"] / "policy.yaml"
    target.write_text(INVALID_OUTSIDE_POLICY, encoding="utf-8")
    workspace_file = str(layout["workspace_file"])

    named = _call(
        tool, monkeypatch, workspace_file=workspace_file, workspace_config=str(target)
    )
    (layout["root"] / ".ash-workspace.yaml").symlink_to(target)
    discovered = _call(tool, monkeypatch, workspace_file=workspace_file)

    _assert_refused_with_nothing_from_outside(discovered, layout["outside"])
    assert named["success"] is False, named
    assert MARKER not in json.dumps(named, default=str), named
    assert {key: named[key] for key in SAME} == {
        key: discovered[key] for key in SAME
    }, (named, discovered)


@pytest.mark.parametrize("tool", TOOLS)
def test_a_workspace_definition_the_caller_names_outside_is_a_config_refusal(
    layout, monkeypatch, tool
) -> None:
    definition = layout["outside"] / "dev.code-workspace"
    definition.write_text(json.dumps({"folders": [{"path": MARKER}]}), "utf-8")

    response = _call(tool, monkeypatch, workspace_file=str(definition))

    assert response["success"] is False, response
    assert response["error_type"] == "config_input_not_permitted", response
    assert response["exit_code"] == 3, response
    assert MARKER not in json.dumps(response, default=str), response


def test_control_an_in_root_policy_is_read_and_applied(layout, monkeypatch) -> None:
    """A policy sets suppressions and ignore paths for every project, so a
    discovered one is used only when the operator set its directory aside in
    ASH_MCP_ALLOWED_CONFIG_ROOTS (``_refuse_a_client_chosen_policy``); the
    control grants the workspace root as a config root."""
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(layout["root"]))
    (layout["root"] / ".ash-workspace.yaml").write_text(
        OUTSIDE_POLICY, encoding="utf-8"
    )

    response = _resolve(layout["workspace_file"])

    assert response["success"] is True, response
    (project,) = response["projects"]
    assert project["effective_severity_threshold"] == "LOW", project
    assert project["threshold_tightened_by_policy"] is True, project
