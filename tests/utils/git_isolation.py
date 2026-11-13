# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Keep the git repositories a test builds from seeing whatever lies above them.

A test that builds real repositories under tmp_path gets the same answers from
git, and from ASH's nesting check (utils/scan_source.repository_is_nested), only
when nothing above tmp_path counts. tmp_path is outside every repository in CI,
but locally it can sit in a checkout's work tree (a basetemp under a worktree,
say). A GIT_CEILING_DIRECTORIES entry alone does not keep that out: the
nesting check honors a ceiling only when the repository it hides would neither
track nor list the directory below it.

So :func:`isolate_git_at` makes *directory* itself an empty repository that
excludes everything (``.git/info/exclude`` is ``*``), and puts the ceiling there.
git does not move up into the ceiling, and the nearest repository the ceiling
hides is that one, which holds nothing below it.

The nesting check asks every repository at or above a ceiling, though, so one
enclosing tmp_path still counts when it tracks or lists tmp_path. A test that
expects a root to record "." therefore needs tmp_path outside every repository,
as it is in CI and under a --basetemp outside every checkout.
"""

import os
import subprocess
from pathlib import Path


def excluding_repository_at(directory: Path) -> Path:
    """Make *directory* a real empty repository that excludes everything.

    The shape both halves of the isolation use: git can answer for it (it has
    a common dir, unlike a bare ``.git`` stub), it tracks nothing, and it
    lists nothing as untracked (``.git/info/exclude`` is ``*``). A test that
    needs "a repository root" the nesting check can be asked about, below an
    :func:`isolate_git_at` top, builds it with this.

    Returns:
        *directory*.
    """
    directory.mkdir(parents=True, exist_ok=True)
    # Without the variables that point git at another repository (a hook's
    # GIT_DIR, say), so the repository is made here.
    environ = {
        key: value
        for key, value in os.environ.items()
        if key not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE")
    }
    subprocess.run(
        ["git", "init", "-q", str(directory)],
        check=True,
        capture_output=True,
        env=environ,
    )
    exclude = directory / ".git" / "info" / "exclude"
    exclude.parent.mkdir(parents=True, exist_ok=True)
    exclude.write_text("*\n", encoding="utf-8")
    return directory


def isolate_git_at(directory: Path, monkeypatch) -> Path:
    """Make *directory* the top that git and the nesting check stop at.

    Run no git command with *directory* itself as its working directory: git
    finds the empty repository there. Below it, git stops at the ceiling.
    The ceiling is consulted only for roots strictly below *directory*, so a
    test must scan a subdirectory, never *directory* itself.

    Returns:
        *directory*.
    """
    excluding_repository_at(directory)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(directory))
    return directory
