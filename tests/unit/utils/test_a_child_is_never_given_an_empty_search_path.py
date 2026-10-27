# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A child's PATH is never empty and never names the working directory.

Why this file exists
--------------------
A child looks programs up by name itself (a ``#!/usr/bin/env node`` line, a binstub,
a scanner starting git), and it reads an empty PATH, like an empty or relative entry
in one, as the current directory. ``child_environ`` (``_spawn_env``) therefore hands a
child a PATH whose every entry is anchored: it names a directory without reference to
the working directory.

Three routes used to leave the child with a PATH that is not:

- every entry of the PATH is inside the scanned tree or not anchored, so the entries
  kept were none and PATH was written as ``""``;
- the caller's own env sets ``PATH=""``, which was passed through as it was;
- the fallback for a PATH with no anchored entry was ``os.defpath`` itself, and on
  Windows that is ``.;C:\\bin``, which carries ``.``.

The answer is the same for all three: PATH is ``os.defpath`` with the entries that are
not anchored taken off. If that leaves nothing, it is a fixed list of system
directories. A PATH that is not set at all is left unset, as ``find_executable`` tells
an unset PATH (the system's default directories) from an empty one.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.scanned_tree import is_inside_tree
from automated_security_helper.utils.subprocess_utils import (
    ALLOW_IN_TREE_TOOLS_ENV,
    child_environ,
    run_command,
    scanning_tree,
)
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX default directories and a POSIX child"
)

#: Stands for the scanned tree in a PATH value built before the tree exists.
_REPO = "<repo>"


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    """The scanned tree, and ASH's working directory, as ``cd repo && ash scan``."""
    tree = tmp_path / "repo"
    tree.mkdir()
    monkeypatch.chdir(tree)
    monkeypatch.delenv(ALLOW_IN_TREE_TOOLS_ENV, raising=False)
    return tree


def _entries(env) -> list:
    return env["PATH"].split(os.pathsep)


def assert_a_path_of_directories(env) -> None:
    """PATH is set, is not empty, and each entry is anchored."""
    assert "PATH" in env
    assert env["PATH"] != "", "an empty PATH is read as the working directory"
    not_anchored = [
        entry
        for entry in _entries(env)
        if not (entry and subprocess_utils._is_anchored(entry))
    ]
    assert not not_anchored, (
        f"entries that depend on the working directory: {not_anchored}"
    )


def _in_scope(repo, scope: str, env):
    """``child_environ(env)`` as a scan with ``scope`` would make it."""
    if scope == "no-scan":
        return child_environ(env)
    with scanning_tree(repo):
        return child_environ(env)


# ---------------------------------------------------------------------------
# 1: every entry is in the tree, or not anchored
# ---------------------------------------------------------------------------


def _all_in_tree(repo: Path, layout: str) -> list:
    in_tree = [str(repo / ".venv" / "bin"), str(repo / "node_modules" / ".bin")]
    return {
        "only-in-tree": in_tree,
        "in-tree-and-not-anchored": [in_tree[0], "bin", "", "."],
    }[layout]


@pytest.mark.parametrize("layout", ["only-in-tree", "in-tree-and-not-anchored"])
def test_a_path_with_no_entry_outside_the_tree_is_not_left_empty(
    repo, monkeypatch, layout
):
    monkeypatch.setenv("PATH", os.pathsep.join(_all_in_tree(repo, layout)))

    with scanning_tree(repo):
        env = child_environ()

    assert_a_path_of_directories(env)
    assert not [entry for entry in _entries(env) if is_inside_tree(entry, str(repo))]


@posix_only
def test_that_path_is_the_default_path(repo, monkeypatch):
    """The same answer as for a PATH with no anchored entry at all."""
    monkeypatch.setenv("PATH", os.pathsep.join(_all_in_tree(repo, "only-in-tree")))

    with scanning_tree(repo):
        env = child_environ()

    assert env["PATH"] == os.defpath


# ---------------------------------------------------------------------------
# 2: the caller's own env sets PATH=""
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scope", ["no-scan", "scan"])
def test_a_path_the_caller_set_to_empty_is_replaced(repo, scope):
    assert_a_path_of_directories(_in_scope(repo, scope, {"PATH": ""}))


@posix_only
def test_a_child_started_with_an_empty_path_gets_the_default_path(repo):
    """Through a spawn helper: what the child itself reads."""
    result = run_command(
        [sys.executable, "-c", "import os; print(os.environ['PATH'])"],
        cwd=repo,
        env={"PATH": ""},
        timeout=CHILD_TIMEOUT_SECONDS,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == os.defpath


# ---------------------------------------------------------------------------
# 3: the default path itself carries an entry that is not anchored
# ---------------------------------------------------------------------------


def test_the_windows_default_path_does_not_bring_the_working_directory_back(
    repo, monkeypatch
):
    """``ntpath.defpath`` is ``.;C:\\bin``: ``.`` is the working directory."""
    monkeypatch.setattr(os, "defpath", ".;C:\\bin")
    monkeypatch.setattr(os, "pathsep", ";")

    env = child_environ({"PATH": "bin;."})

    assert "." not in _entries(env)
    assert_a_path_of_directories(env)


@posix_only
@pytest.mark.parametrize("source", ["relative-entry", "caller-empty", "all-in-tree"])
def test_the_default_path_keeps_its_anchored_entries_in_order(
    repo, monkeypatch, source
):
    monkeypatch.setattr(os, "defpath", os.pathsep.join(["/opt/a", ".", "/opt/b"]))
    given = {
        "relative-entry": "bin",
        "caller-empty": "",
        "all-in-tree": str(repo / ".venv" / "bin"),
    }[source]

    env = _in_scope(repo, "scan", {"PATH": given})

    assert env["PATH"] == os.pathsep.join(["/opt/a", "/opt/b"])


@pytest.mark.parametrize(
    "default",
    [".", "", os.pathsep.join(["bin", "."]), os.pathsep],
    ids=["dot", "empty", "relative-and-dot", "separator-only"],
)
def test_a_default_path_with_no_anchored_entry_gives_fixed_directories(
    repo, monkeypatch, default
):
    monkeypatch.setattr(os, "defpath", default)

    env = child_environ({"PATH": "bin"})

    assert_a_path_of_directories(env)


# ---------------------------------------------------------------------------
# Every route through the spawn environment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scope", ["no-scan", "scan", "scan-with-opt-in"])
@pytest.mark.parametrize(
    "value",
    [
        pytest.param("", id="empty"),
        pytest.param(os.pathsep * 2, id="separators-only"),
        pytest.param(".", id="dot"),
        pytest.param("bin", id="relative"),
        pytest.param(os.pathsep.join(["bin", "", "."]), id="relative-and-empty"),
        pytest.param(_REPO + "/.venv/bin", id="in-tree-only"),
        pytest.param(
            os.pathsep.join([_REPO + "/.venv/bin", "bin"]), id="in-tree-and-relative"
        ),
    ],
)
def test_no_path_through_the_spawn_environment_is_empty_or_not_anchored(
    repo, monkeypatch, scope, value
):
    if scope == "scan-with-opt-in":
        monkeypatch.setenv(ALLOW_IN_TREE_TOOLS_ENV, "1")
    env = _in_scope(repo, scope, {"PATH": value.replace(_REPO, str(repo))})

    assert_a_path_of_directories(env)


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scope", ["no-scan", "scan"])
def test_control_an_unset_path_stays_unset(repo, scope):
    assert "PATH" not in _in_scope(repo, scope, {})


@posix_only
@pytest.mark.parametrize("scope", ["no-scan", "scan"])
def test_control_an_anchored_path_is_handed_over_as_it_is(repo, scope):
    given = os.pathsep.join(["/usr/bin", "/bin"])

    assert _in_scope(repo, scope, {"PATH": given})["PATH"] == given
