# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The git commands the nesting check runs start no program a repository names.

utils/scan_source.py asks git about every repository around a scan root: one
that encloses it, and one a GIT_CEILING_DIRECTORIES entry hides. Those
repositories' ``.git/config`` belongs to whoever wrote them, and its
``core.fsmonitor`` is a command git runs whenever it refreshes the index, which
``git ls-files`` does. Each command the check runs is built by
``utils/git_command.git_argv``, which turns ``core.fsmonitor`` off and points
``core.hooksPath`` at ``/dev/null`` on the command line, where they outrank the
repository's config.

Each test sets ``core.fsmonitor`` in the repository the check asks about to a
command that leaves a marker. The first proves with plain git that the marker
appears. The check's other git questions (``rev-parse`` for the root and the
common and git dirs, ``worktree list``) start no configured program with or
without the options (git 2.50.1, with every hook and core.fsmonitor set), so
no marker could tell whether they are built by git_argv; only a check that
reads the source can.
"""

from __future__ import annotations

import os
import shlex
import subprocess  # nosec B404
from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import (
    git_index_paths_below,
    git_repository_root,
    git_untracked_paths_below,
)
from automated_security_helper.utils.git_command import git_argv
from automated_security_helper.utils.scan_output_dirs import git_index_below
from automated_security_helper.utils.scan_source import (
    recorded_scan_source,
    repository_is_nested,
)
from tests.utils.git_isolation import isolate_git_at


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 B607 -- list args, no shell, fixture repos only
        [
            "git",
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        timeout=30,
    )


def _marks(marker: Path) -> int:
    return marker.read_text(encoding="utf-8").count("ran") if marker.exists() else 0


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A home directory kept in git that ignores src/, holding a checkout at
    src/project, with the ceiling at the home directory, and a core.fsmonitor in
    the home repository that leaves a marker.

    Returns:
        (home, project, marker)
    """
    scratch_home = tmp_path / "user"
    scratch_home.mkdir()
    monkeypatch.setenv("HOME", str(scratch_home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    isolate_git_at(tmp_path / "top", monkeypatch)
    home = tmp_path / "top" / "home"
    home.mkdir()
    _git(home, "init", "-q")
    (home / ".gitignore").write_text("/src/\n", encoding="utf-8")
    (home / "notes.txt").write_text("notes\n", encoding="utf-8")
    _git(home, "add", ".gitignore", "notes.txt")
    _git(home, "commit", "-qm", "home")
    project = home / "src" / "project"
    project.mkdir(parents=True)
    _git(project, "init", "-q")
    (project / "README.md").write_text("project\n", encoding="utf-8")
    _git(project, "add", "README.md")
    _git(project, "commit", "-qm", "project")
    marker = tmp_path / "fsmonitor-ran.txt"
    command = f"echo ran >> {shlex.quote(marker.as_posix())}; false"
    _git(home, "config", "core.fsmonitor", command)
    monkeypatch.setenv(
        "GIT_CEILING_DIRECTORIES",
        os.pathsep.join([str(tmp_path / "top"), str(home)]),
    )
    return home, project, marker


@pytest.mark.integration
def test_plain_git_runs_the_hidden_repositorys_fsmonitor(home):
    """The control: the listings the check needs, run without the options."""
    repo, _project, marker = home

    subprocess.run(  # nosec B603 B607 -- the control, plain git
        ["git", "ls-files", "-z", "--", "src/project"],
        cwd=repo,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )

    assert _marks(marker) > 0


@pytest.mark.integration
def test_the_ceiling_check_runs_no_fsmonitor(home):
    repo, project, marker = home

    assert repository_is_nested(project) is False
    assert recorded_scan_source(project, git_repository_root, {}) == "."
    assert _marks(marker) == 0


@pytest.mark.integration
@pytest.mark.parametrize(
    "ask",
    [
        pytest.param(lambda repo: git_index_paths_below(repo, "src"), id="index"),
        pytest.param(lambda repo: git_untracked_paths_below(repo, "src"), id="others"),
        pytest.param(
            lambda repo: git_index_paths_below(repo, "src/project", exactly=["src"]),
            id="index-exactly",
        ),
        pytest.param(
            lambda repo: git_untracked_paths_below(
                repo, "src/project", exactly=["src"]
            ),
            id="others-exactly",
        ),
        pytest.param(git_index_below, id="output-dirs"),
    ],
)
def test_each_git_question_runs_no_fsmonitor(home, ask):
    repo, _project, marker = home

    ask(repo)

    assert _marks(marker) == 0


@pytest.mark.unit
def test_git_argv_puts_the_options_before_the_subcommand():
    """The options as written, so a git_argv that adds none fails here too."""
    assert git_argv("ls-files", "-z") == [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "ls-files",
        "-z",
    ]
