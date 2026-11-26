# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ``cli.mcp`` compatibility shims list names that exist and re-export them as such.

Each shim replaces itself with its ``config`` module in ``sys.modules`` and keeps a
``TYPE_CHECKING`` import block for tools that do not follow the swap. The private
names in that block drift when the module renames one, and a plain private import
reads as unused to a linter; the ``_a as _a`` form marks it a re-export.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SHIMS = {
    "automated_security_helper.cli.mcp.sandbox": "automated_security_helper.config.mcp_sandbox",
    "automated_security_helper.cli.mcp.profile_registry": "automated_security_helper.config.session_profiles",
    "automated_security_helper.cli.mcp.session_paths": "automated_security_helper.config.session_paths",
}


def _type_checking_imports(shim: str):
    # By file, not by ``find_spec``: once a shim has been imported its
    # ``sys.modules`` entry is the moved module, and its spec names that file.
    package = importlib.import_module("automated_security_helper.cli.mcp")
    path = Path(package.__path__[0]) / f"{shim.rsplit('.', 1)[-1]}.py"
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and "TYPE_CHECKING" in ast.dump(node.test):
            for stmt in node.body:
                if isinstance(stmt, ast.ImportFrom):
                    yield stmt


@pytest.mark.parametrize("shim,moved", SHIMS.items())
def test_every_listed_name_exists_on_the_moved_module(shim, moved):
    module = importlib.import_module(moved)
    names = [
        a.name
        for stmt in _type_checking_imports(shim)
        for a in stmt.names
        if a.name != "*"
    ]

    assert names
    assert [n for n in names if not hasattr(module, n)] == []


@pytest.mark.parametrize("shim,moved", SHIMS.items())
def test_every_listed_private_name_is_a_marked_reexport(shim, moved):
    plain = [
        a.name
        for stmt in _type_checking_imports(shim)
        for a in stmt.names
        if a.name != "*" and a.asname != a.name
    ]

    assert plain == []


def test_the_public_names_the_shims_had_to_list_are_in_the_star_surface():
    sandbox = importlib.import_module("automated_security_helper.config.mcp_sandbox")

    for name in (
        "caller_is_remote",
        "resolve_workspace_root",
        "validate_discovered_config",
    ):
        assert name in sandbox.__all__


def test_scan_target_reexports_the_env_name_it_does_not_define():
    from automated_security_helper.cli.mcp import scan_target
    from automated_security_helper.config import mcp_sandbox

    assert (
        scan_target.ASH_MCP_ALLOWED_ROOTS_ENV == mcp_sandbox.ASH_MCP_ALLOWED_ROOTS_ENV
    )
    # Equal strings cannot tell a re-export from a second literal (identifier-like
    # literals are interned, so even ``is`` holds for both), so the module's own
    # syntax tree is read: no statement in it assigns the name.
    tree = ast.parse(Path(scan_target.__file__).read_text())
    assigned = [
        target.id
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        if isinstance(target, ast.Name)
    ]
    assert "ASH_MCP_ALLOWED_ROOTS_ENV" not in assigned
