# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How ``git_index_below`` asks git, and which directories its answer names.

Four readings of ``scan_output_dirs``, each pinned here against a stand-in for
the git spawn (no git runs):

- git ran with ASH's whole environment, so a GIT_INDEX_FILE (a hook's temporary
  index) answered for the repository, and GIT_ICASE_PATHSPECS or
  GIT_GLOB_PATHSPECS together with ``--literal-pathspecs`` made git exit 128 on
  every call; the variables that point git elsewhere or change what a pathspec
  matches are now left out of its environment;
- the pathspec and the prefix filter were case-exact, so on macOS and Windows an
  output directory spelled in another case than the committed one listed no
  entries and the committed-output refusal never fired; there the pathspec is
  matched without regard to case and the prefix compared with ``output_name_key``;
- the repository was searched along the directory's spelled parents, so one
  reached through a link that lands inside a repository read as "not in git";
  it is searched from where the directory really is;
- a ``.git`` entry inside an earlier run's ``.ash/ash_output`` made that
  directory its own repository, whose empty index read as "nothing committed",
  so the directory was named and left out whole, every file in it hidden; a
  directory is named only when a repository above it lists the index.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.scan_output_dirs import (
    classified_output_dirs,
    git_index_below,
)

pytestmark = pytest.mark.unit


class _GitStandIn:
    """Records every spawn and answers with one listing."""

    def __init__(self, stdout: bytes = b"") -> None:
        self.calls = []
        self.stdout = stdout

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        return SimpleNamespace(returncode=0, stdout=self.stdout, stderr=b"")


def _repository(tmp_path) -> Path:
    repo = Path(os.path.realpath(tmp_path)) / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "out").mkdir()
    return repo


def test_the_variables_that_redirect_git_are_left_out_of_its_environment(
    tmp_path, monkeypatch
):
    repo = _repository(tmp_path)
    git = _GitStandIn()
    monkeypatch.setattr(subprocess_utils, "spawn_run", git)
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "hook-index"))
    monkeypatch.setenv("GIT_ICASE_PATHSPECS", "1")
    monkeypatch.setenv("GIT_GLOB_PATHSPECS", "1")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "other" / ".git"))
    monkeypatch.setenv("ASH_KEEP_ME", "yes")

    answer = git_index_below(repo / "out")

    assert answer.names == []
    ((_, kwargs),) = git.calls
    environ = kwargs["env"]
    for name in (
        "GIT_INDEX_FILE",
        "GIT_ICASE_PATHSPECS",
        "GIT_GLOB_PATHSPECS",
        "GIT_DIR",
    ):
        assert name not in environ
    assert environ["ASH_KEEP_ME"] == "yes"


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_where_names_compare_without_case_the_pathspec_does_too(
    tmp_path, monkeypatch, platform
):
    repo = _repository(tmp_path)
    git = _GitStandIn(b"Out/reports/x.md\0Out/README\0other/y.md\0")
    monkeypatch.setattr(subprocess_utils, "spawn_run", git)
    monkeypatch.setattr(sys, "platform", platform)

    answer = git_index_below(repo / "out")

    ((args, _),) = git.calls
    assert "--icase-pathspecs" in args
    assert "--noglob-pathspecs" in args
    assert "--literal-pathspecs" not in args
    assert answer.names == ["reports/x.md", "README"]


def test_control_on_linux_the_pathspec_is_literal_and_case_exact(tmp_path, monkeypatch):
    repo = _repository(tmp_path)
    git = _GitStandIn(b"Out/reports/x.md\0out/kept.md\0")
    monkeypatch.setattr(subprocess_utils, "spawn_run", git)
    monkeypatch.setattr(sys, "platform", "linux")

    answer = git_index_below(repo / "out")

    ((args, _),) = git.calls
    assert "--literal-pathspecs" in args
    assert "--icase-pathspecs" not in args
    assert answer.names == ["kept.md"]


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_the_repository_is_found_from_where_the_directory_really_is(
    tmp_path, monkeypatch
):
    repo = _repository(tmp_path)
    (repo / "sub" / "out").mkdir(parents=True)
    alias = repo.parent / "alias"
    alias.symlink_to(repo / "sub")
    git = _GitStandIn(b"sub/out/committed.md\0")
    monkeypatch.setattr(subprocess_utils, "spawn_run", git)

    answer = git_index_below(alias / "out")

    assert answer.repository == repo
    assert answer.base == alias / "out"
    assert answer.names == ["committed.md"]
    ((args, kwargs),) = git.calls
    assert f"--work-tree={repo}" in args
    assert args[-1] == "sub/out"
    assert kwargs["cwd"] == repo


def test_a_repository_inside_an_earlier_output_dir_does_not_name_it(
    tmp_path, monkeypatch
):
    source = Path(os.path.realpath(tmp_path)) / "src"
    earlier = source / ".ash" / "ash_output"
    (earlier / ".git").mkdir(parents=True)
    (earlier / "hidden.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(subprocess_utils, "spawn_run", _GitStandIn())
    monkeypatch.chdir(source)

    named, scanned = classified_output_dirs(source, output_dir=tmp_path / "elsewhere")

    assert named == []
    assert scanned == [earlier]


def test_control_a_repository_above_an_earlier_output_dir_names_it(
    tmp_path, monkeypatch
):
    source = Path(os.path.realpath(tmp_path)) / "src"
    (source / ".git").mkdir(parents=True)
    earlier = source / ".ash" / "ash_output"
    earlier.mkdir(parents=True)
    (earlier / "report.md").write_text("old\n", encoding="utf-8")
    monkeypatch.setattr(subprocess_utils, "spawn_run", _GitStandIn())
    monkeypatch.chdir(source)

    named, scanned = classified_output_dirs(source, output_dir=tmp_path / "elsewhere")

    assert named == [earlier]
    assert scanned == []
