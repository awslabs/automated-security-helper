# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The in-tree refusal exempts the running interpreter by its path, not its inode.

A scanned tree's virtual environment links its python to the interpreter that runs
ASH. ``os.path.samefile`` calls the two one file, but the venv's python, started by
its own path, reads the tree's pyvenv.cfg and site-packages, so it is an in-tree
tool and is refused. An in-tree link named after another tool is refused for the
same reason. The interpreter's own path is admitted, and so is a python-named link
beside it that is the same file (the sibling modules pin that exemption and its
limit); a tool installed beside it, when ASH runs from a virtual environment inside
the scanned tree, is refused like any other in-tree file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.subprocess_utils import (
    _first_usable,
    _TreeScope,
)

pytestmark = pytest.mark.unit


def _tool(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    return path


def _scope_of(tree: Path) -> _TreeScope:
    return _TreeScope(roots=(os.path.abspath(tree),), allow=False)


@pytest.fixture
def same_file_everywhere(monkeypatch):
    """What a venv link to the running interpreter looks like to ``samefile``."""
    monkeypatch.setattr(os.path, "samefile", lambda a, b: True)


def test_a_tree_venv_link_to_the_running_interpreter_is_refused(
    tmp_path, same_file_everywhere
):
    """A venv python inside the tree is refused although it is the same binary."""
    tree = tmp_path / "repo"
    venv_python = _tool(tree / ".venv" / "bin", "python")

    chosen, refused = _first_usable("python", iter([str(venv_python)]), _scope_of(tree))

    assert chosen is None
    assert refused == str(venv_python)


def test_an_in_tree_link_named_after_another_tool_is_refused(
    tmp_path, same_file_everywhere
):
    """A tree's bandit that is the interpreter by inode is not started as bandit."""
    tree = tmp_path / "repo"
    fake_bandit = _tool(tree / "bin", "bandit")

    chosen, refused = _first_usable("bandit", iter([str(fake_bandit)]), _scope_of(tree))

    assert chosen is None
    assert refused == str(fake_bandit)


def test_the_running_interpreter_is_admitted_inside_a_scanned_tree():
    """The interpreter ASH runs from is admitted by its own path."""
    scope = _scope_of(Path(sys.executable).parent)

    chosen, refused = _first_usable("python", iter([sys.executable]), scope)

    assert chosen == sys.executable
    assert refused is None


def test_a_tool_beside_the_running_interpreter_is_refused(tmp_path, monkeypatch):
    """A sibling of the interpreter in a venv inside the tree is still in-tree."""
    tree = tmp_path / "repo"
    venv_bin = tree / ".venv" / "bin"
    python = _tool(venv_bin, "python")
    monkeypatch.setattr(sys, "executable", str(python))
    sibling = _tool(venv_bin, "uv")

    chosen, refused = _first_usable("uv", iter([str(sibling)]), _scope_of(tree))

    assert chosen is None
    assert refused == str(sibling)

    chosen, refused = _first_usable("python", iter([str(python)]), _scope_of(tree))

    assert chosen == str(python)
    assert refused is None
