# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv installed with ASH is passed over when it lies inside the scanned tree.

``find_uv_or_none`` prefers the uv beside ASH's interpreter. When ASH runs from a
virtual environment inside the repository being scanned, that uv is inside the
tree, and the spawn layer refuses every program inside the tree (only the running
interpreter is exempt). Choosing it made every uv spawn raise the
``FileNotFoundError`` a missing program raises, and ``uv_availability`` remembered
that as "uv absent" for the rest of the process, while a usable uv sat on PATH.

The lookup now applies the spawn layer's rule before choosing the bundled uv and
falls through to one outside the tree; the availability probe answers a refused
spawn for that call only instead of memoizing absence.
"""

from __future__ import annotations

import stat
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import uv_tool_runner
from automated_security_helper.utils.subprocess_utils import (
    ALLOW_IN_TREE_TOOLS_ENV,
    scanning_tree,
)
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
    find_uv_or_none,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="POSIX execute bits and shell scripts"
    ),
]


def _executable(path: Path) -> str:
    """A file the lookup counts as an executable. Nothing here runs it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


@pytest.fixture(autouse=True)
def _fresh_lookups(monkeypatch):
    _reset_uv_tool_runner_caches()
    monkeypatch.delenv(ALLOW_IN_TREE_TOOLS_ENV, raising=False)
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    yield
    _reset_uv_tool_runner_caches()


@pytest.fixture
def two_uvs(tmp_path, monkeypatch):
    """The bundled uv inside the tree to scan, and another uv on PATH outside it."""
    tree = tmp_path / "repo"
    tree.mkdir()
    in_tree = _executable(tree / ".venv" / "bin" / "uv")
    outside = _executable(tmp_path / "elsewhere" / "bin" / "uv")
    monkeypatch.setattr(uv_tool_runner, "bundled_uv_executable", lambda: in_tree)
    monkeypatch.setenv("PATH", str(tmp_path / "elsewhere" / "bin"))
    return tree, in_tree, outside


def test_the_bundled_uv_inside_the_scanned_tree_is_passed_over(two_uvs):
    tree, in_tree, outside = two_uvs
    with scanning_tree(tree):
        assert find_uv_or_none() == outside


def test_outside_a_scan_the_bundled_uv_still_comes_first(two_uvs):
    """The control: the preference for ASH's own uv is unchanged where the spawn
    layer would not refuse it."""
    _tree, in_tree, _outside = two_uvs
    assert find_uv_or_none() == in_tree


def test_with_in_tree_tools_allowed_the_bundled_uv_is_kept(two_uvs, monkeypatch):
    """The operator's opt-in is honored the way the spawn layer honors it."""
    tree, in_tree, _outside = two_uvs
    monkeypatch.setenv(ALLOW_IN_TREE_TOOLS_ENV, "1")
    with scanning_tree(tree):
        assert find_uv_or_none() == in_tree


def test_the_answer_is_per_scan_scope(two_uvs, tmp_path):
    """A scan of another tree, where the bundled uv is not inside, gets it back:
    the remembered answer belongs to the scope it was made in."""
    tree, in_tree, outside = two_uvs
    with scanning_tree(tree):
        assert find_uv_or_none() == outside
    other = tmp_path / "other"
    other.mkdir()
    with scanning_tree(other):
        assert find_uv_or_none() == in_tree


def test_a_refused_in_tree_uv_is_not_remembered_as_absent(two_uvs, monkeypatch):
    """A runner given an in-tree uv has its probe refused by the spawn layer.

    The refusal is this scan's, not uv's absence: the answer is False with the
    refusal as its failure, and nothing is memoized, so a later call in another
    scope probes again. The second half is read as the docstring promises it,
    through the probe itself, not through the one private slot: outside the
    scope the same runner asks uv again and takes its answer.
    """
    tree, in_tree, _outside = two_uvs
    runner = UVToolRunner(uv_executable=in_tree)
    with scanning_tree(tree):
        available, failure = runner.uv_availability()
    assert available is False
    assert failure is not None and "scanned tree" in failure, failure
    assert runner._uv_available_cache is None

    probes = []

    def _spawn_run(command, **kwargs):
        probes.append(list(command))
        return subprocess.CompletedProcess(command, 0, "uv 0.5.0\n", "")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    assert runner.uv_availability() == (True, None)
    assert probes == [[in_tree, "--version"]], probes
