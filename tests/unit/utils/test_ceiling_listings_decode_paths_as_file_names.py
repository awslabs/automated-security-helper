# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The paths the nesting check reads from git are decoded as file names.

utils/scan_source.py asks git about the repositories around a scan root: their
common and git dirs (``git_common_dir``, ``git_absolute_git_dir``), their
worktrees (``git_worktree_paths``), and, when a GIT_CEILING_DIRECTORIES entry
hides the repository that holds the root, what that repository tracks or leaves
untracked below a directory (``git_index_paths_below``,
``git_untracked_paths_below``). Each answer is a path that is compared with a
directory on disk, so each is read as bytes and decoded as UTF-8, with
undecodable bytes kept as surrogates, the way Python spells a file name. Only
the line end git adds is removed from a path printed on a line of its own.

git prints these paths in UTF-8 on Windows too, where text mode would decode
them with the locale's code page (cp1252 in an English locale). That locale is
simulated here: a subprocess call that asks for text is given cp1252 as its
encoding, the encoding Windows would pick for it.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import get_scan_set
from automated_security_helper.utils.get_scan_set import (
    git_absolute_git_dir,
    git_common_dir,
    git_index_paths_below,
    git_untracked_paths_below,
    git_worktree_paths,
)
from automated_security_helper.utils.scan_source import repository_is_nested
from tests.utils.git_isolation import isolate_git_at

# Built with chr() so the source file stays ASCII.
CAFE = f"caf{chr(0xE9)}"
#: Any commit id: a gitlink records one without the commit having to exist.
GITLINK_COMMIT = "1" * 40


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(  # nosec B603 B607 -- list args, no shell, fixture repos only
        [
            "git",
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        timeout=30,
    )


@pytest.fixture
def git_home(tmp_path, monkeypatch):
    """git reads no configuration but the repositories' own."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    return home


@pytest.fixture
def repository(tmp_path, git_home):
    """A repository tracking a gitlink and a file under non-ASCII names, with
    an untracked one beside them."""
    repo = tmp_path / "repo"
    (repo / "vendor").mkdir(parents=True)
    _git(repo, "init", "-q")
    (repo / "vendor" / f"{CAFE}.txt").write_text("x\n", encoding="utf-8")
    _git(repo, "add", "--", f"vendor/{CAFE}.txt")
    _git(
        repo,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{GITLINK_COMMIT},vendor/{CAFE}",
    )
    (repo / "vendor" / f"new-{CAFE}.txt").write_text("y\n", encoding="utf-8")
    return repo


@pytest.fixture
def linked(tmp_path, git_home, monkeypatch):
    """A repository under a non-ASCII directory, with a linked worktree inside
    its checkout, and git kept from looking above tmp_path."""
    isolate_git_at(tmp_path / "top", monkeypatch)
    repo = tmp_path / "top" / CAFE / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    (repo / ".gitignore").write_text("/wt/\n", encoding="utf-8")
    _git(repo, "add", ".gitignore")
    _git(repo, "commit", "-qm", "fixture")
    _git(repo, "worktree", "add", "-q", "--detach", "wt")
    return repo


@pytest.fixture(params=["utf-8 locale", "cp1252 locale"])
def locale_encoding(request, monkeypatch):
    """Run git's subprocesses as they run under the given locale."""
    if request.param == "cp1252 locale":
        real_run = subprocess.run

        def run_as_windows_would(*args, **kwargs):
            if (kwargs.get("text") or kwargs.get("universal_newlines")) and not (
                kwargs.get("encoding")
            ):
                kwargs["encoding"] = "cp1252"
            return real_run(*args, **kwargs)

        monkeypatch.setattr(get_scan_set.subprocess, "run", run_as_windows_would)
    return request.param


def test_a_tracked_non_ascii_path_is_listed_as_its_file_name(
    repository, locale_encoding
):
    listed = git_index_paths_below(repository, "vendor")

    assert listed is not None
    assert sorted(listed) == sorted([f"vendor/{CAFE}", f"vendor/{CAFE}.txt"])


def test_an_untracked_non_ascii_path_is_listed_as_its_file_name(
    repository, locale_encoding
):
    listed = git_untracked_paths_below(repository, "vendor")

    assert listed == [f"vendor/new-{CAFE}.txt"]


@pytest.mark.skipif(
    sys.platform != "linux", reason="only Linux file systems take any byte string"
)
def test_a_tracked_path_that_is_not_utf8_is_listed_as_python_spells_it(repository):
    name = os.fsdecode(b"vendor/\xff.txt")
    (repository / name).write_text("z\n", encoding="utf-8")
    _git(repository, "add", "--", name)

    listed = git_index_paths_below(repository, "vendor")

    assert listed is not None
    assert name in listed


def test_a_hidden_superproject_holds_a_non_ascii_submodule(
    tmp_path, git_home, locale_encoding, monkeypatch
):
    """The repository a ceiling hides tracks the root as a gitlink, so the root
    is nested."""
    isolate_git_at(tmp_path / "top", monkeypatch)
    superproject = tmp_path / "top" / "super"
    (superproject / "vendor").mkdir(parents=True)
    _git(superproject, "init", "-q")
    _git(
        superproject,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{GITLINK_COMMIT},vendor/{CAFE}",
    )
    submodule = superproject / "vendor" / CAFE
    submodule.mkdir()
    _git(submodule, "init", "-q")
    monkeypatch.setenv(
        "GIT_CEILING_DIRECTORIES",
        os.pathsep.join([str(tmp_path / "top"), str(superproject / "vendor")]),
    )

    assert repository_is_nested(submodule) is True


def test_the_common_dir_of_a_non_ascii_worktree_is_its_file_name(
    linked, locale_encoding
):
    assert git_common_dir(linked / "wt") == (linked / ".git").resolve()


def test_the_git_dir_of_a_non_ascii_worktree_is_its_file_name(linked, locale_encoding):
    assert (
        git_absolute_git_dir(linked / "wt")
        == (linked / ".git" / "worktrees" / "wt").resolve()
    )


def test_a_non_ascii_worktree_is_listed_as_its_file_name(linked, locale_encoding):
    assert git_worktree_paths(linked) == {
        linked.resolve(),
        (linked / "wt").resolve(),
    }


def test_a_non_ascii_linked_worktree_in_its_checkout_is_not_nested(
    linked, locale_encoding
):
    assert repository_is_nested(linked / "wt") is False


@pytest.mark.skipif(
    sys.platform != "linux", reason="only Linux file systems take any byte string"
)
def test_a_linked_worktree_whose_name_is_not_utf8_is_not_nested(linked):
    """Its admin dir's gitdir file records the worktree's path as its bytes,
    and the record is read as Python spells that file name."""
    name = os.fsdecode(b"wt\xe9")
    _git(linked, "worktree", "add", "-q", "--detach", name)
    worktree = linked / name
    assert worktree.resolve() in (git_worktree_paths(linked) or set())

    assert repository_is_nested(worktree) is False


@pytest.mark.skipif(
    sys.platform == "win32", reason="Windows file names cannot end in a space"
)
def test_a_common_dir_whose_name_ends_in_a_space_is_kept_whole(tmp_path, git_home):
    repo = tmp_path / "repo"
    git_dir = tmp_path / "git dir "
    _git(tmp_path, "init", "-q", "--separate-git-dir", str(git_dir), str(repo))

    assert git_common_dir(repo) == git_dir.resolve()
