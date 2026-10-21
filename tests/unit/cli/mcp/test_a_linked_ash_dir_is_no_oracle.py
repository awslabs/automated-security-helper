# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``.ash`` directory linked out of the roots answers alike whatever it holds.

Why this exists
---------------
Config discovery and workspace policy discovery look in a directory and in its
``.ash/``, and refuse a name there that resolves outside the directories the
session may read config from. Checking each name by whether it is there is not
enough: asking whether ``.ash/.ash.yaml`` is there follows a ``.ash`` link into the
directory it leads to, so with ``.ash`` linked to an outside directory, a tool
would refuse when that directory held the name and answer as usual when it did
not: one bit, per name, about a directory the session may not read.

A ``.ash`` that is a link outside the roots is refused by itself, before
anything in it is looked at, so the answer is the same either way. Each cell
asks the same question twice, with the outside directory holding the name and
without it.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable, Dict

import pytest

SESSION = "client-one"
OUTSIDE_CONFIG = "project_name: outside\n"
OUTSIDE_POLICY = "workspace:\n  max_severity_threshold: LOW\n"


@pytest.fixture
def roots(tmp_path, monkeypatch) -> Dict[str, Path]:
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
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(root))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    return {"tmp": tmp_path, "root": root, "project": project, "ws": workspace_file}


def _linked_out(directory: Path, tmp: Path, name: str, text: str, held: bool) -> Path:
    """``directory/.ash`` linked to an outside directory holding ``name`` or not."""
    outside = tmp / ("outside-holding" if held else "outside-empty")
    outside.mkdir()
    if held:
        (outside / name).write_text(text, encoding="utf-8")
    (directory / ".ash").symlink_to(outside, target_is_directory=True)
    return outside


def _without(response: Any, *paths: Path) -> str:
    """The response as text, with the tree paths that differ between runs out."""
    text = json.dumps(response, default=str, sort_keys=True)
    for path in paths:
        text = text.replace(str(path), "<tree>")
    return text


def _same_both_ways(ask: Callable[[bool], Any]) -> Dict[str, Any]:
    held, empty = ask(True), ask(False)
    assert held == empty, (held, empty)
    return held


def _fresh(roots: Dict[str, Path], held: bool) -> Dict[str, Path]:
    """A copy of the tree per run, so each run links its own ``.ash``."""
    import shutil

    base = roots["tmp"] / ("run-held" if held else "run-empty")
    base.mkdir()
    root = base / "ws"
    shutil.copytree(roots["root"], root)
    return {
        "tmp": base,
        "root": root,
        "project": root / "app",
        "ws": root / "dev.code-workspace",
    }


def test_config_discovery_in_a_scan_target(roots, monkeypatch) -> None:
    from automated_security_helper.cli.mcp.sandbox import validate_discovered_config

    def ask(held: bool) -> Any:
        tree = _fresh(roots, held)
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tree["root"]))
        _linked_out(tree["project"], tree["tmp"], ".ash.yaml", OUTSIDE_CONFIG, held)
        refusal = validate_discovered_config(tree["project"], SESSION)
        return None if refusal is None else _without(str(refusal), tree["root"])

    answer = _same_both_ways(ask)
    assert answer is not None, "a .ash linked out of the roots was not refused"


def test_get_config_discovery(roots, monkeypatch) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    def ask(held: bool) -> Any:
        tree = _fresh(roots, held)
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tree["root"]))
        _linked_out(tree["project"], tree["tmp"], ".ash.yaml", OUTSIDE_CONFIG, held)
        response = mcp_get_config(search_dir=str(tree["project"]), session_id=SESSION)
        return _without(response, tree["root"])

    answer = _same_both_ways(ask)
    assert "config_input_not_permitted" in answer, answer
    assert "outside" not in answer.replace("outside the", ""), answer


def test_a_workspace_projects_config_discovery(roots, monkeypatch) -> None:
    from automated_security_helper.cli.mcp.workspace import mcp_resolve_workspace

    def ask(held: bool) -> Any:
        tree = _fresh(roots, held)
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tree["root"]))
        _linked_out(tree["project"], tree["tmp"], ".ash.yaml", OUTSIDE_CONFIG, held)
        response = asyncio.run(
            mcp_resolve_workspace(workspace_file=str(tree["ws"]), session_id=SESSION)
        )
        return _without(response, tree["root"])

    answer = _same_both_ways(ask)
    assert '"error_type": "config_input_not_permitted"' in answer, answer
    assert '"exit_code": 3' in answer, answer


def test_workspace_policy_discovery(roots, monkeypatch) -> None:
    from automated_security_helper.cli.mcp.workspace import mcp_resolve_workspace

    def ask(held: bool) -> Any:
        tree = _fresh(roots, held)
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tree["root"]))
        _linked_out(
            tree["root"], tree["tmp"], "ash-workspace.yaml", OUTSIDE_POLICY, held
        )
        response = asyncio.run(
            mcp_resolve_workspace(workspace_file=str(tree["ws"]), session_id=SESSION)
        )
        return _without(response, tree["root"])

    answer = _same_both_ways(ask)
    assert '"error_type": "config_input_not_permitted"' in answer, answer
    assert '"exit_code": 3' in answer, answer


@pytest.mark.parametrize("where", ["scan target", "workspace root"])
def test_control_a_ash_linked_inside_the_roots_is_read(roots, where) -> None:
    """A ``.ash`` linked to a directory inside the roots is looked in."""
    from automated_security_helper.cli.mcp.sandbox import validate_discovered_config
    from automated_security_helper.cli.mcp.workspace import mcp_resolve_workspace

    inside = roots["root"] / "shared-ash"
    inside.mkdir()
    if where == "scan target":
        (inside / ".ash.yaml").write_text(OUTSIDE_CONFIG, encoding="utf-8")
        (roots["project"] / ".ash").symlink_to(inside, target_is_directory=True)
        assert validate_discovered_config(roots["project"], SESSION) is None
    else:
        (inside / "ash-workspace.yaml").write_text(OUTSIDE_POLICY, encoding="utf-8")
        (roots["root"] / ".ash").symlink_to(inside, target_is_directory=True)
        response = asyncio.run(
            mcp_resolve_workspace(workspace_file=str(roots["ws"]), session_id=SESSION)
        )
        assert response["success"] is True, response
        (project,) = response["projects"]
        assert project["effective_severity_threshold"] == "LOW", project


def test_control_a_plain_ash_directory_with_nothing_in_it_is_no_refusal(roots) -> None:
    """A scan target's own ``.ash/`` (its output lives there) is no config source."""
    from automated_security_helper.cli.mcp.sandbox import validate_discovered_config

    (roots["project"] / ".ash" / "ash_output").mkdir(parents=True)

    assert validate_discovered_config(roots["project"], SESSION) is None
