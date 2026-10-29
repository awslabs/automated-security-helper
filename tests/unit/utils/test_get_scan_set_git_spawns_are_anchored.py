# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every git command ``get_scan_set`` starts runs the resolved git, anchored.

Why this exists
---------------
``get_scan_set`` runs git inside the directory it scans. On Windows a program
started by its bare name is looked for in the working directory before PATH, so
a ``git.exe`` committed to the scanned repository would have run for the four
lookups the nesting check makes (common dir, git dir, worktrees, ls-files),
which passed ``git_argv``'s default program to ``subprocess`` while the
repository-root lookup and the diff resolved it. Those four also handed git a
raw copy of the environment, whose PATH may hold relative or empty entries that
let a program git starts by name be found through the working directory.

The tests pin the shape every spawn now has: ``argv[0]`` is the path
``_git_executable`` resolved and the environment's PATH holds anchored entries
only. The four nesting lookups leave GIT_DIR, GIT_WORK_TREE and GIT_COMMON_DIR
out; the repository-root lookup and the diff keep them on purpose, because a
pre-commit hook in a linked worktree runs ASH with GIT_DIR set to that
worktree's admin dir, git then calls the scanned directory the root, and the
nesting check records nothing for it (``test_scan_source`` pins that end to
end). Nothing is started: ``subprocess.run`` is replaced by a recorder.
"""

from __future__ import annotations

import ast
import os
import subprocess  # nosec B404
from pathlib import Path

import pytest

from automated_security_helper.utils import get_scan_set as gss

pytestmark = pytest.mark.unit

RESOLVED = "/opt/resolved/bin/git"

LOCATION_VARIABLES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")

#: Each helper that starts git, with how it is asked about a directory.
HELPERS = [
    pytest.param(lambda d: gss.git_repository_root(d), id="rev-parse --show-toplevel"),
    pytest.param(lambda d: gss.git_common_dir(d), id="rev-parse --git-common-dir"),
    pytest.param(
        lambda d: gss.git_absolute_git_dir(d), id="rev-parse --absolute-git-dir"
    ),
    pytest.param(lambda d: gss.git_worktree_paths(d), id="worktree list"),
    pytest.param(lambda d: gss.git_index_paths_below(d, "src"), id="ls-files"),
    pytest.param(
        lambda d: gss.git_untracked_paths_below(d, "src"), id="ls-files --others"
    ),
    pytest.param(lambda d: gss.get_changed_files("main", cwd=d), id="diff"),
]

#: The nesting check's lookups, which answer about the directory they run in.
NESTING_HELPERS = HELPERS[1:6]

#: The two that keep the caller's repository location (a git hook's GIT_DIR).
LOCATION_KEEPING_HELPERS = [HELPERS[0], HELPERS[6]]


@pytest.fixture
def recorded(monkeypatch):
    """Record each ``subprocess.run`` call instead of starting git."""
    calls: list[tuple[list[str], dict]] = []

    def run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(list(argv), 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(gss.subprocess, "run", run)
    monkeypatch.setattr(gss, "_git_executable", lambda: RESOLVED)
    return calls


@pytest.mark.parametrize("ask", HELPERS)
def test_each_helper_runs_the_resolved_git(tmp_path, recorded, ask):
    ask(tmp_path)

    assert recorded, "git was not started"
    assert [argv[0] for argv, _ in recorded] == [RESOLVED] * len(recorded)


def _with_location_variables(monkeypatch, elsewhere: Path) -> None:
    monkeypatch.setenv("GIT_DIR", str(elsewhere / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(elsewhere))
    monkeypatch.setenv("GIT_COMMON_DIR", str(elsewhere / ".git"))


@pytest.mark.parametrize("ask", NESTING_HELPERS)
def test_each_nesting_lookup_leaves_the_repository_location_variables_out(
    tmp_path, monkeypatch, recorded, ask
):
    """GIT_DIR and its siblings would make git answer about another repository."""
    _with_location_variables(monkeypatch, tmp_path / "elsewhere")

    ask(tmp_path)

    assert recorded, "git was not started"
    for _argv, kwargs in recorded:
        env = kwargs["env"]
        assert env is not os.environ
        assert not set(env) & set(LOCATION_VARIABLES), sorted(env)


@pytest.mark.parametrize("ask", LOCATION_KEEPING_HELPERS)
def test_the_root_lookup_and_the_diff_keep_the_callers_repository_location(
    tmp_path, monkeypatch, recorded, ask
):
    """A hook's GIT_DIR names the repository the scan is about; both must read it,
    or the diff is resolved against a root git found for another repository."""
    elsewhere = tmp_path / "elsewhere"
    _with_location_variables(monkeypatch, elsewhere)

    ask(tmp_path)

    assert recorded, "git was not started"
    for _argv, kwargs in recorded:
        env = kwargs["env"]
        assert env is not os.environ
        assert env.get("GIT_DIR") == str(elsewhere / ".git")
        assert env.get("GIT_WORK_TREE") == str(elsewhere)


@pytest.mark.parametrize("ask", HELPERS)
def test_each_helper_gives_git_an_anchored_path(tmp_path, monkeypatch, recorded, ask):
    """A relative or empty PATH entry names a directory under the working directory."""
    anchored = str(tmp_path / "bin")
    monkeypatch.setenv("PATH", os.pathsep.join(["bin", "", anchored]))

    ask(tmp_path)

    assert recorded, "git was not started"
    for _argv, kwargs in recorded:
        assert kwargs["env"]["PATH"] == anchored


@pytest.mark.parametrize("ask", HELPERS)
def test_each_helper_starts_nothing_when_no_git_is_found(tmp_path, monkeypatch, ask):
    """With no git on an anchored PATH, no bare name is handed to the OS to look up."""
    calls = []
    monkeypatch.setattr(gss.subprocess, "run", lambda *a, **k: calls.append(a))
    monkeypatch.setattr(gss, "_git_executable", lambda: None)

    assert ask(tmp_path) is None
    assert calls == []


def _git_argv_calls_without_a_program(path: Path) -> list[int]:
    """Lines of ``git_argv(...)`` calls in *path* that pass no ``program=``."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "git_argv"
        and not any(keyword.arg == "program" for keyword in node.keywords)
    ]


def test_every_git_argv_in_the_module_names_its_program():
    """The gate: a new spawn that takes ``git_argv``'s default fails here."""
    assert _git_argv_calls_without_a_program(Path(gss.__file__)) == []


def test_the_gate_sees_a_call_that_takes_the_default(tmp_path):
    """The gate's own control: the shape it looks for is found when present."""
    sample = tmp_path / "sample.py"
    sample.write_text(
        "from automated_security_helper.utils.git_command import git_argv\n"
        'a = git_argv("status")\n'
        'b = git_argv("status", program="/opt/git")\n',
        encoding="utf-8",
    )
    assert _git_argv_calls_without_a_program(sample) == [2]
