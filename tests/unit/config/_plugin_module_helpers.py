# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared constants, helpers and fixture body for the plugin-module record cells.

The cells that read an ``ash_plugin_modules`` entry from the environment, in
tests/unit/config and tests/unit/cli, build the same planted site and the same
environment. They import this one module
(``tests.unit.config._plugin_module_helpers``) so the environment contract is
held in one place.

``plant_site_and_environment`` plants the site modules and one in-tree module
under a lane tmp directory, clears the variables that choose a config, sets the
placeholder-shaped variables the entries read, and changes into the project
root. Each test module's ``root`` fixture is one call to it (a fixture imported
by name into a module is a redefinition for the linter, so the fixture stays in
the module and the body lives here). Every planted string is a placeholder,
never a real variable value.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Sequence

import pytest

SESSION = "client-one"
IN_TREE = "recin_ash_plugins"
INSTALLED = "recout_ash_plugins"
SEC_ONE = "recsecone_ash_plugins"
SEC_TWO = "recsectwo_ash_plugins"
UNIMPORTABLE = "recnone_ash_plugins"
PFX = "qvx9rec"
GLUED_FULL = f"{PFX}tail_ash_plugins"
SITE_MODULES = (INSTALLED, SEC_ONE, SEC_TWO, GLUED_FULL)
ALL_MODULES = (*SITE_MODULES, IN_TREE, UNIMPORTABLE)


def plant_site_and_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Plant the site, the in-tree module and the complete environment, and
    return the project root. A test module's ``root`` fixture calls this."""
    root = tmp_path / "roots" / "project"
    root.mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "roots"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    site = tmp_path / "site-out"
    for name in SITE_MODULES:
        (site / name).mkdir(parents=True)
        (site / name / "__init__.py").write_text("PLANTED = 1\n", encoding="utf-8")
    lib = root / "lib"
    (lib / IN_TREE).mkdir(parents=True)
    (lib / IN_TREE / "__init__.py").write_text("PLANTED = 1\n", encoding="utf-8")
    for name in ALL_MODULES:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.syspath_prepend(str(lib))
    monkeypatch.setenv("ASH_RECV_ONE", SEC_ONE)
    monkeypatch.setenv("ASH_RECV_TWO", SEC_TWO)
    monkeypatch.setenv("ASH_RECV_PAIR", f"{SEC_ONE},{SEC_TWO}")
    monkeypatch.setenv("ASH_RECV_PFX", PFX)
    monkeypatch.setenv("ASH_RECV_MIX", f"{IN_TREE},{SEC_TWO}")
    monkeypatch.setenv("ASH_RECV_IN", IN_TREE)
    monkeypatch.chdir(root)
    return root.resolve()


def entries_file(path: Path, entries: Sequence[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"  - {entry}\n" for entry in entries)
    path.write_text(
        f"project_name: demo\nash_plugin_modules:\n{body}", encoding="utf-8"
    )
    return path


def resolved_config(path: Path):
    from automated_security_helper.config.resolve_config import resolve_config

    return resolve_config(config_path=str(path))
