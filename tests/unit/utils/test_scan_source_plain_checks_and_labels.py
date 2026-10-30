# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Readings of ``scan_source`` at its edges, none of which starts git.

- A label segment ending in a newline, or holding a C1 control such as NEL, is not
  a relative scan source: ``$`` matched before a final newline, and the control
  class stopped at DEL.
- ``scan_source_label`` falls back to identity when the text says the directory
  is not below the root, as on a volume that compares names without regard to case.
- ``_registered_worktree`` compares the recorded path as the platform compares
  paths, as the worktree listing is compared.
- ``_repository_holds`` reads a hidden repository's admin dirs only when it needs
  its worktree listing: a root with a common dir of its own is decided by the
  index listings.
- A regular file at ``<common>/worktrees`` is plain: git lists no linked worktree.
- A HEAD that is a symlink into ``refs/`` is read as the symref git reads it as.
- An admin-dir entry gone between the listing and its stat is skipped; a junction
  (a reparse point naming another path) is not descended.
- A HEAD padded past the record limit is followed as git follows it.
- A per-worktree symref is looked up in the worktree's admin dir.
- An ancestor's ``.git`` is checked for a FIFO before git is started on it.
- A reftable stack is checked as packed-refs is.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import scan_source
from automated_security_helper.utils.scan_source import (
    _admin_dirs_are_plain,
    _git_entry_is_plain,
    _head_target_is_plain,
    _registered_worktree,
    _repository_holds,
    _tree_is_plain,
    _WorktreeCheck,
    is_relative_scan_source,
    repository_is_nested,
    scan_source_label,
)

pytestmark = pytest.mark.unit

needs_fifos = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@pytest.mark.parametrize("label", ["a\n", "services/api\n", "a\x85b", "a\u009fb"])
def test_a_segment_ending_in_a_newline_or_holding_a_c1_control_is_refused(label):
    assert not is_relative_scan_source(label)


@pytest.mark.parametrize("label", [".", "services/api", "a b", "café"])
def test_control_plain_segments_are_accepted(label):
    assert is_relative_scan_source(label)


def test_the_label_is_relative_when_the_file_system_says_the_root_holds_it(
    tmp_path, monkeypatch
):
    """Stood in for a case-insensitive volume: ``os.path.samefile`` answers as one
    does for two spellings of the root, and nothing else about the paths changes."""
    root = tmp_path / "Repo"
    (root / "services" / "api").mkdir(parents=True)
    real_samefile = os.path.samefile

    def samefile(first, second):
        if os.fspath(first).lower() == os.fspath(second).lower():
            return True
        return real_samefile(first, second)

    monkeypatch.setattr(scan_source.os.path, "samefile", samefile)

    label = scan_source_label(tmp_path / "repo" / "services" / "api", root)

    assert label == "services/api"


def test_control_a_directory_outside_the_root_keeps_its_absolute_path(tmp_path):
    root = tmp_path / "repo"
    (tmp_path / "other").mkdir()
    root.mkdir()

    label = scan_source_label(tmp_path / "other", root)

    assert label == (tmp_path / "other").resolve().as_posix()


def test_the_recorded_worktree_path_is_compared_as_the_platform_compares_paths(
    tmp_path, monkeypatch
):
    common = tmp_path / "common"
    admin = common / "worktrees" / "x"
    admin.mkdir(parents=True)
    root = tmp_path / "root"
    root.mkdir()
    (admin / "gitdir").write_text(
        (tmp_path / "ROOT" / ".git").as_posix() + "\n", encoding="utf-8"
    )
    monkeypatch.setattr(scan_source, "git_absolute_git_dir", lambda path: admin)
    monkeypatch.setattr(scan_source.os.path, "normcase", lambda text: text.lower())

    assert _registered_worktree(root, common)


def test_a_root_with_its_own_common_dir_is_decided_by_the_listings(
    tmp_path, monkeypatch
):
    hidden = tmp_path / "hidden"
    root = hidden / "vendor" / "lib"
    root.mkdir(parents=True)
    commons = {hidden.resolve(): tmp_path / "X", root.resolve(): tmp_path / "Y"}
    monkeypatch.setattr(scan_source, "_git_entry_is_plain", lambda entry: True)
    monkeypatch.setattr(
        scan_source, "git_common_dir", lambda path: commons[Path(path).resolve()]
    )
    monkeypatch.setattr(scan_source, "_admin_dirs_are_plain", lambda common: False)
    monkeypatch.setattr(scan_source, "git_index_paths_below", lambda *a, **k: [])
    monkeypatch.setattr(scan_source, "git_untracked_paths_below", lambda *a, **k: [])

    assert not _repository_holds(root.resolve(), hidden.resolve(), _WorktreeCheck(root))


def test_control_a_root_sharing_the_hidden_common_dir_reads_its_admin_dirs(
    tmp_path, monkeypatch
):
    hidden = tmp_path / "hidden"
    root = hidden / "vendor" / "lib"
    root.mkdir(parents=True)
    monkeypatch.setattr(scan_source, "_git_entry_is_plain", lambda entry: True)
    monkeypatch.setattr(scan_source, "git_common_dir", lambda path: tmp_path / "X")
    monkeypatch.setattr(scan_source, "_admin_dirs_are_plain", lambda common: False)

    assert _repository_holds(root.resolve(), hidden.resolve(), _WorktreeCheck(root))


def _common_with_a_branch(tmp_path: Path) -> Path:
    common = tmp_path / "common"
    (common / "refs" / "heads").mkdir(parents=True)
    (common / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (common / "refs" / "heads" / "main").write_text("0" * 40 + "\n", encoding="utf-8")
    return common


def test_a_regular_file_where_the_worktrees_directory_would_be_is_plain(tmp_path):
    common = _common_with_a_branch(tmp_path)
    (common / "worktrees").write_text("not a directory\n", encoding="utf-8")

    assert _admin_dirs_are_plain(common)


@needs_symlinks
def test_a_symlink_head_into_the_refs_is_read_as_a_symref(tmp_path):
    common = _common_with_a_branch(tmp_path)
    (common / "HEAD").unlink()
    (common / "HEAD").symlink_to("refs/heads/main")

    assert _head_target_is_plain(common / "HEAD", common)


@needs_symlinks
@needs_fifos
def test_a_symlink_head_is_followed_to_the_branch_it_names(tmp_path):
    common = _common_with_a_branch(tmp_path)
    (common / "HEAD").unlink()
    (common / "HEAD").symlink_to("refs/heads/main")
    (common / "refs" / "heads" / "main").unlink()
    os.mkfifo(common / "refs" / "heads" / "main")

    assert not _head_target_is_plain(common / "HEAD", common)


@needs_symlinks
def test_control_a_symlink_head_outside_the_refs_is_not_plain(tmp_path):
    common = _common_with_a_branch(tmp_path)
    (common / "HEAD").unlink()
    (common / "HEAD").symlink_to("../elsewhere")

    assert not _head_target_is_plain(common / "HEAD", common)


class _GoneEntry:
    def __init__(self, path: Path) -> None:
        self.path = str(path)
        self.name = path.name

    def stat(self, follow_symlinks=True):
        raise FileNotFoundError(2, "No such file or directory", self.path)


class _JunctionEntry:
    def __init__(self, path: Path) -> None:
        self.path = str(path)
        self.name = path.name

    def stat(self, follow_symlinks=True):
        return SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755,
            st_file_attributes=0x400,
            st_reparse_tag=0xA0000003,
        )


class _Listing:
    def __init__(self, entries) -> None:
        self._entries = entries

    def __enter__(self):
        return iter(self._entries)

    def __exit__(self, *exc):
        return False


def _scandir_with(monkeypatch, top: Path, entries):
    real_scandir = os.scandir

    def scandir(path="."):
        if Path(path) == top:
            return _Listing(entries)
        return real_scandir(path)

    monkeypatch.setattr(scan_source.os, "scandir", scandir)


def test_an_entry_gone_between_the_listing_and_its_stat_is_skipped(
    tmp_path, monkeypatch
):
    admin = tmp_path / "admin"
    admin.mkdir()
    (admin / "HEAD").write_text("0" * 40 + "\n", encoding="utf-8")
    _scandir_with(monkeypatch, admin, [_GoneEntry(admin / "index.lock")])

    assert _tree_is_plain(admin)


def test_a_junction_in_an_admin_dir_is_not_descended(tmp_path, monkeypatch):
    admin = tmp_path / "admin"
    (admin / "junction").mkdir(parents=True)
    (admin / "junction" / "plain").write_text("", encoding="utf-8")
    _scandir_with(monkeypatch, admin, [_JunctionEntry(admin / "junction")])

    assert not _tree_is_plain(admin)


@needs_fifos
def test_a_head_padded_past_the_record_limit_is_still_followed(tmp_path):
    common = _common_with_a_branch(tmp_path)
    (common / "HEAD").write_text(
        "ref: refs/heads/main" + " " * 5000 + "\n", encoding="utf-8"
    )
    (common / "refs" / "heads" / "main").unlink()
    os.mkfifo(common / "refs" / "heads" / "main")

    assert not _head_target_is_plain(common / "HEAD", common)


@needs_fifos
def test_a_per_worktree_symref_is_looked_up_in_the_admin_dir(tmp_path):
    common = _common_with_a_branch(tmp_path)
    admin = common / "worktrees" / "x"
    (admin / "refs" / "worktree").mkdir(parents=True)
    (admin / "HEAD").write_text("ref: refs/worktree/w\n", encoding="utf-8")
    os.mkfifo(admin / "refs" / "worktree" / "w")

    assert not _head_target_is_plain(admin / "HEAD", common, admin=admin)
    assert not _admin_dirs_are_plain(common)


def test_control_a_per_worktree_symref_naming_a_plain_ref_is_plain(tmp_path):
    common = _common_with_a_branch(tmp_path)
    admin = common / "worktrees" / "x"
    (admin / "refs" / "worktree").mkdir(parents=True)
    (admin / "HEAD").write_text("ref: refs/worktree/w\n", encoding="utf-8")
    (admin / "refs" / "worktree" / "w").write_text("0" * 40 + "\n", encoding="utf-8")
    (admin / "gitdir").write_text("x\n", encoding="utf-8")

    assert _admin_dirs_are_plain(common)


@needs_fifos
def test_an_ancestors_git_dir_is_checked_before_git_is_started_on_it(
    tmp_path, monkeypatch
):
    outer = tmp_path / "outer"
    (outer / ".git").mkdir(parents=True)
    (outer / ".git" / "config").write_text("", encoding="utf-8")
    os.mkfifo(outer / ".git" / "HEAD")
    inner = outer / "third_party" / "inner"
    (inner / ".git").mkdir(parents=True)
    (inner / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    def never(path):
        raise AssertionError(f"git was started on {path}")

    monkeypatch.setattr(scan_source, "git_common_dir", never)

    assert not _git_entry_is_plain(outer / ".git")
    assert repository_is_nested(inner)


def test_control_a_plain_git_dir_passes_the_entry_check(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (repo / ".git" / "config").write_text("", encoding="utf-8")

    assert _git_entry_is_plain(repo / ".git")


def test_a_gitfile_is_followed_to_the_git_dir_it_names(tmp_path):
    (tmp_path / "admin").mkdir()
    (tmp_path / "admin" / "HEAD").write_text("0" * 40 + "\n", encoding="utf-8")
    (tmp_path / "admin" / "commondir").write_text("../..\n", encoding="utf-8")
    gitfile = tmp_path / "wt" / ".git"
    gitfile.parent.mkdir()
    gitfile.write_text(f"gitdir: {(tmp_path / 'admin').as_posix()}\n", encoding="utf-8")

    assert _git_entry_is_plain(gitfile)


@needs_fifos
def test_a_gitfile_record_is_taken_as_git_takes_it_with_its_trailing_space(tmp_path):
    """git takes everything after ``gitdir: `` and drops only trailing carriage
    returns and newlines, so ``gitdir: <tmp>/admin `` names the directory whose
    name ends in a space. The check stripped the space and looked at ``admin``,
    which is plain, while git would wait on the FIFO in ``admin ``."""
    plain = tmp_path / "admin"
    plain.mkdir()
    (plain / "HEAD").write_text("0" * 40 + "\n", encoding="utf-8")
    spaced = tmp_path / "admin "
    spaced.mkdir()
    os.mkfifo(spaced / "HEAD")
    gitfile = tmp_path / "wt" / ".git"
    gitfile.parent.mkdir()
    gitfile.write_text(f"gitdir: {spaced.as_posix()}\n", encoding="utf-8")

    assert not _git_entry_is_plain(gitfile)


def test_a_gitfile_without_gits_exact_prefix_is_not_plain(tmp_path):
    """``gitdir:<path>`` with no space is a file git refuses as an invalid gitfile,
    so git opens nothing through it; it counts as not plain, the side that errs
    toward nested, as ``_marks_a_checkout`` counts it."""
    admin = tmp_path / "admin"
    admin.mkdir()
    (admin / "HEAD").write_text("0" * 40 + "\n", encoding="utf-8")
    gitfile = tmp_path / "wt" / ".git"
    gitfile.parent.mkdir()
    gitfile.write_text(f"gitdir:{admin.as_posix()}\n", encoding="utf-8")

    assert not _git_entry_is_plain(gitfile)


@needs_fifos
def test_the_common_dirs_config_is_checked_through_commondir(tmp_path):
    """A linked worktree's admin dir holds no config: git's repository-format check
    reads ``<commondir>/config``, which the admin dir's own three files never
    covered, so a FIFO there held git_common_dir for git's timeout."""
    common = tmp_path / "common"
    admin = common / "worktrees" / "x"
    admin.mkdir(parents=True)
    (admin / "HEAD").write_text("0" * 40 + "\n", encoding="utf-8")
    (admin / "commondir").write_text("../..\n", encoding="utf-8")
    os.mkfifo(common / "config")
    gitfile = tmp_path / "wt" / ".git"
    gitfile.parent.mkdir()
    gitfile.write_text(f"gitdir: {admin.as_posix()}\n", encoding="utf-8")

    assert not _git_entry_is_plain(gitfile)


@needs_fifos
def test_a_git_directory_with_a_commondir_file_is_checked_the_same_way(tmp_path):
    common = tmp_path / "common"
    common.mkdir()
    os.mkfifo(common / "config")
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (repo / ".git" / "commondir").write_text("../../common\n", encoding="utf-8")

    assert not _git_entry_is_plain(repo / ".git")


def test_control_a_commondir_naming_a_plain_common_dir_is_plain(tmp_path):
    common = tmp_path / "common"
    common.mkdir()
    (common / "config").write_text("", encoding="utf-8")
    admin = common / "worktrees" / "x"
    admin.mkdir(parents=True)
    (admin / "HEAD").write_text("0" * 40 + "\n", encoding="utf-8")
    (admin / "commondir").write_text("../..\n", encoding="utf-8")

    assert _git_entry_is_plain(admin)


@needs_fifos
def test_a_reftable_stack_is_checked_as_packed_refs_is(tmp_path):
    common = _common_with_a_branch(tmp_path)
    (common / "reftable").mkdir()
    os.mkfifo(common / "reftable" / "tables.list")

    assert not _admin_dirs_are_plain(common)


def test_control_a_repository_without_a_reftable_is_plain(tmp_path):
    assert _admin_dirs_are_plain(_common_with_a_branch(tmp_path))
