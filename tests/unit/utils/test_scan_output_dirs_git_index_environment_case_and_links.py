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
  directory is named only when a repository above it lists the index;
- resolving the directory before asking git also resolved a directory that is
  itself a committed link, so git was asked about the link's target and the
  entry that marks the directory as tracked (``""``) was lost; a directory that
  is itself a link is asked about by its own name, under its parent resolved.
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


@pytest.fixture(autouse=True)
def nothing_above_the_test_directory_is_searched(tmp_path, monkeypatch):
    """These tests expect no repository above their directory. With ``--basetemp``
    inside a checkout, or a temporary directory under a work tree, the upward
    search for ``.git`` found the developer's checkout, the stand-in answered for
    it and ``assert named == []`` failed. The test directory is a ceiling; a test
    that sets its own overrides this."""
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", os.path.realpath(tmp_path))


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
    # The case-insensitive and literal readings travel on the pathspec element
    # itself: a global --icase-pathspecs needs --noglob-pathspecs beside it, and
    # that pair leaves a leading ':' of the directory's name to be read as
    # pathspec magic, where the element form takes the rest literally.
    assert args[-1] == ":(literal,icase)out"
    assert "--icase-pathspecs" not in args
    assert "--noglob-pathspecs" not in args
    assert "--literal-pathspecs" not in args
    assert answer.names == ["reports/x.md", "README"]


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="a name holding ':' cannot exist on Windows; the pathspec arm for the "
    "win32 platform is measured here with the directory on a POSIX host",
)
@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_where_names_compare_without_case_a_leading_colon_is_still_a_name(
    tmp_path, monkeypatch, platform
):
    """APFS allows ':' in a name. git reads a leading ':' of a pathspec as magic
    unless the element is literal: ':out' matched 'out' and ':!x' excluded, so
    the committed files under such a directory were listed as none and the
    committed-output refusal never fired."""
    repo = _repository(tmp_path)
    (repo / ":out").mkdir()
    git = _GitStandIn(b":out/README\0other/y.md\0")
    monkeypatch.setattr(subprocess_utils, "spawn_run", git)
    monkeypatch.setattr(sys, "platform", platform)

    answer = git_index_below(repo / ":out")

    ((args, _),) = git.calls
    assert args[-1] == ":(literal,icase):out"
    assert answer.names == ["README"]


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


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_directory_that_is_itself_a_link_is_asked_about_by_its_own_name(
    tmp_path, monkeypatch
):
    """``.ash/ash_output`` committed as a link to ``../src``: git tracks the link
    as an entry, listed as ``""`` below the link's own path. Asked about ``src``
    instead, git listed src's files and never that entry."""
    repo = _repository(tmp_path)
    (repo / "src").mkdir()
    (repo / ".ash").mkdir()
    (repo / ".ash" / "ash_output").symlink_to(repo / "src", target_is_directory=True)
    git = _GitStandIn(b".ash/ash_output\0")
    monkeypatch.setattr(subprocess_utils, "spawn_run", git)

    answer = git_index_below(repo / ".ash" / "ash_output")

    assert answer.repository == repo
    assert answer.base == repo / ".ash" / "ash_output"
    assert answer.names == [""]
    ((args, _),) = git.calls
    assert args[-1] == ".ash/ash_output"


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_link_whose_parent_sits_through_a_link_is_asked_where_the_parent_is(
    tmp_path, monkeypatch
):
    """The parent is resolved, as any directory is; only the last component, the
    link itself, is kept as spelled."""
    repo = _repository(tmp_path)
    (repo / "sub" / "src").mkdir(parents=True)
    (repo / "sub" / "out").symlink_to(repo / "sub" / "src", target_is_directory=True)
    alias = repo.parent / "alias"
    alias.symlink_to(repo / "sub")
    git = _GitStandIn(b"")
    monkeypatch.setattr(subprocess_utils, "spawn_run", git)

    answer = git_index_below(alias / "out")

    assert answer.repository == repo
    assert answer.names == []
    ((args, _),) = git.calls
    assert args[-1] == "sub/out"


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_control_a_directory_below_a_link_is_still_asked_about_where_it_really_is(
    tmp_path, monkeypatch
):
    repo = _repository(tmp_path)
    (repo / "src" / "deep").mkdir(parents=True)
    (repo / "linked").symlink_to(repo / "src", target_is_directory=True)
    git = _GitStandIn(b"src/deep/kept.md\0")
    monkeypatch.setattr(subprocess_utils, "spawn_run", git)

    answer = git_index_below(repo / "linked" / "deep")

    assert answer.names == ["kept.md"]
    ((args, _),) = git.calls
    assert args[-1] == "src/deep"


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


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_ceiling_spelled_through_a_link_still_stops_the_walk(tmp_path, monkeypatch):
    """The walk starts from where the directory really is, so a GIT_CEILING_DIRECTORIES
    entry is compared the same way: spelled through a link, it names the directory
    it leads to, and the search stops below it as git's own search does."""
    tree = Path(os.path.realpath(tmp_path))
    (tree / ".git").mkdir()
    (tree / "real" / "sub").mkdir(parents=True)
    alias = tree / "alias"
    alias.symlink_to(tree / "real")
    git = _GitStandIn()
    monkeypatch.setattr(subprocess_utils, "spawn_run", git)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(alias))

    answer = git_index_below(alias / "sub")

    assert answer.repository is None
    assert answer.names is None
    assert git.calls == []


def test_control_a_ceiling_spelled_as_the_real_path_stops_the_walk(
    tmp_path, monkeypatch
):
    tree = Path(os.path.realpath(tmp_path))
    (tree / ".git").mkdir()
    (tree / "real" / "sub").mkdir(parents=True)
    git = _GitStandIn()
    monkeypatch.setattr(subprocess_utils, "spawn_run", git)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tree / "real"))

    answer = git_index_below(tree / "real" / "sub")

    assert answer.repository is None
    assert git.calls == []
