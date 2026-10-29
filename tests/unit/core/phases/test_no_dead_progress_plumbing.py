# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The phases' never-displayed progress plumbing stays removed.

EnginePhase.update_progress, ScannerExecutor._update_progress,
EnginePhase.initialize_progress and EnginePhase.phase_task were removed: nothing
set phase_task, so every update reached nothing on screen (measured on a real scan
with every progress call recorded). A call to one of them left behind, from a
branch merged later for instance, would raise AttributeError in the middle of a
scan. This fails on any reference to them in the package. The display is drawn by
each phase's own row and one row per converter, scanner and reporter; the real
scans in tests/unit/cli/test_scan_on_a_terminal.py run the phases through,
convert and inspect included.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.unit.walked_package import package_sources

pytestmark = pytest.mark.unit

REMOVED = {"update_progress", "_update_progress", "initialize_progress", "phase_task"}
PACKAGE = Path(__file__).resolve().parents[4] / "automated_security_helper"


def _package_sources(package: Path = PACKAGE) -> list[Path]:
    # Refused unless every part of the package is in the walk (walked_package).
    return package_sources(package)


def _referenced_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return node.name
    if isinstance(node, ast.keyword):
        return node.arg
    return None


def test_no_reference_to_the_removed_progress_plumbing_remains():
    found = []
    for source in _package_sources():
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            name = _referenced_name(node)
            if name in REMOVED:
                found.append(f"{source.relative_to(PACKAGE)}:{node.lineno}: {name}")

    assert found == [], found


def test_the_guard_refuses_a_tree_with_nothing_to_check(tmp_path):
    """Moved or pointed elsewhere, the guard would pass having read no module."""
    (tmp_path / "one.py").write_text("x = 1\n", encoding="utf-8")

    with pytest.raises(AssertionError):
        _package_sources(tmp_path)
