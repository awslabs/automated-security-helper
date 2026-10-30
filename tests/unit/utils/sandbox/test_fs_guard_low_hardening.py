# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The write guard's edges: root choice, spellings, races, depth, modes and names.

Before these tests the guard chose the deepest registered root, so the components
between an output directory and a scanner's results directory were opened by name;
it matched a root by spelling alone, so the same directory reached through a link
above it was written with a plain open; a component replaced by a link between the
check and the open surfaced as NotADirectoryError on Linux; two writers creating
the same component raced into FileExistsError; a chain of directories a few
hundred deep ended the sweep in RecursionError with nothing said; the Windows
branch of unlink_beneath passed through a junction; the atomic writer reset the
file's mode; its refusal classes lacked the base class's remedy; and the
operator-destination writer had no newline argument. The atomic writer still
refuses a multi-name target below a registered root (a tamper signal) and
replaces one outside every root. Every test writes under tmp_path.
"""

from __future__ import annotations

import errno
import os
import stat
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.sandbox import fs_guard
from automated_security_helper.utils.sandbox.fs_guard import (
    OutputHardLinkRefused,
    OutputLinkRefused,
    open_for_atomic_write,
    open_for_write,
    register_writable_root,
    release_writable_root,
    replace_without_following,
    unlink_beneath,
)

pytestmark = pytest.mark.unit

POSIX = pytest.mark.skipif(
    sys.platform == "win32", reason="symlinks and directory descriptors"
)


@pytest.fixture
def root(tmp_path):
    """A registered root, released after the test."""
    path = tmp_path / "root"
    path.mkdir()
    register_writable_root(path)
    yield path
    release_writable_root(path)


def test_the_refusals_carry_the_base_classs_remedy(tmp_path):
    link = OutputLinkRefused(tmp_path / "f", tmp_path / "link")
    hard = OutputHardLinkRefused(tmp_path / "f", 2)
    assert isinstance(link.remedy, str) and link.remedy
    assert isinstance(hard.remedy, str) and hard.remedy
    assert link.found and hard.found


def test_the_outermost_registered_root_guards_the_write(tmp_path):
    outer = tmp_path / "out"
    inner = outer / "scanners" / "probe"
    inner.mkdir(parents=True)
    register_writable_root(outer)
    register_writable_root(inner)
    try:
        assert fs_guard._writable_root_for(inner / "report.json") == outer
    finally:
        release_writable_root(inner)
        release_writable_root(outer)


@POSIX
def test_a_root_reached_through_another_spelling_is_still_guarded(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (real / "sub").symlink_to(elsewhere, target_is_directory=True)
    register_writable_root(real)
    try:
        assert fs_guard._writable_root_for(alias / "sub" / "f") == real
        with pytest.raises(OutputLinkRefused):
            open_for_write(alias / "sub" / "f")
        with open_for_write(alias / "plain" / "g") as handle:
            handle.write("x")
    finally:
        release_writable_root(real)
    assert not (elsewhere / "f").exists()
    assert (real / "plain" / "g").read_text() == "x"


@POSIX
def test_a_tree_nested_past_the_limit_is_refused_not_overrun(tmp_path):
    root = tmp_path / "deep"
    chain = root.joinpath(*(["d"] * (fs_guard._SWEEP_DEPTH_LIMIT + 5)))
    chain.mkdir(parents=True)
    with pytest.raises(OSError, match="nested"):
        fs_guard._sweep_tree(root)
    with pytest.raises(OSError, match="nested"):
        fs_guard.refuse_links_below(root)
    shallow = tmp_path / "shallow"
    shallow.joinpath(*(["d"] * 20)).mkdir(parents=True)
    assert fs_guard._sweep_tree(shallow) == 0
    fs_guard.refuse_links_below(shallow)


@POSIX
def test_a_component_replaced_by_a_link_is_refused_whatever_the_open_says(
    root, tmp_path, monkeypatch
):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "comp").symlink_to(elsewhere, target_is_directory=True)
    pre_checks = []

    def late_link(name, dir_fd):
        # The first look at the component is before the swap: not a link yet.
        if name == "comp" and not pre_checks:
            pre_checks.append(name)
            return False
        return stat.S_ISLNK(os.lstat(name, dir_fd=dir_fd).st_mode)

    original_open = os.open

    def enotdir_open(path, flags, *args, **kwargs):
        if path == "comp" and kwargs.get("dir_fd") is not None:
            raise NotADirectoryError(errno.ENOTDIR, "not a directory", path)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(fs_guard, "_is_link", late_link)
    monkeypatch.setattr(os, "open", enotdir_open)

    with pytest.raises(OutputLinkRefused):
        open_for_write(root / "comp" / "f")
    assert not (elsewhere / "f").exists()


@POSIX
def test_a_component_another_writer_creates_first_is_used(root, monkeypatch):
    original_mkdir = os.mkdir

    def racing_mkdir(path, mode=0o777, *, dir_fd=None):
        original_mkdir(path, mode, dir_fd=dir_fd)
        raise FileExistsError(errno.EEXIST, "made meanwhile", path)

    monkeypatch.setattr(os, "mkdir", racing_mkdir)

    with open_for_write(root / "new" / "f") as handle:
        handle.write("x")
    assert (root / "new" / "f").read_text() == "x"


def test_unlink_beneath_refuses_a_junction_on_the_by_name_branch(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "junction").mkdir(parents=True)
    (root / "junction" / "file").write_text("x")
    monkeypatch.delattr(os, "fwalk", raising=False)
    monkeypatch.setattr(
        fs_guard, "is_link", lambda path: Path(path) == root / "junction"
    )

    assert unlink_beneath(root, ("junction", "file")) is False
    assert (root / "junction" / "file").exists()


def test_replace_without_following_takes_a_newline_argument(tmp_path):
    target = tmp_path / "guide.md"
    replace_without_following(target, "a\nb\n", newline="\r\n")
    assert target.read_bytes() == b"a\r\nb\r\n"
    replace_without_following(target, "a\nb\n", newline="\n")
    assert target.read_bytes() == b"a\nb\n"


@POSIX
def test_an_atomic_write_refuses_a_multi_name_entry_below_a_root_and_replaces_it_outside(
    root, tmp_path
):
    """Below a registered root a target another name refers to is refused before
    the staging file is made (the other name may be a scanner's: a tamper signal);
    outside every root (tmp_path is not one) the entry is replaced and the file the
    other name refers to is spared."""
    target = root / "report.json"
    target.write_text("old")
    other = root / "other-name"
    os.link(target, other)
    with pytest.raises(OutputHardLinkRefused):
        with open_for_atomic_write(target) as handle:
            handle.write("new")
    assert target.read_text() == "old"
    assert other.read_text() == "old"
    assert os.stat(target).st_nlink == 2
    assert sorted(entry.name for entry in root.iterdir()) == [
        "other-name",
        "report.json",
    ]

    target = tmp_path / "report.json"
    target.write_text("old")
    other = tmp_path / "other-name"
    os.link(target, other)
    with open_for_atomic_write(target) as handle:
        handle.write("new")
    assert target.read_text() == "new"
    assert other.read_text() == "old"
    assert os.stat(target).st_nlink == 1


@POSIX
def test_an_atomic_write_keeps_the_files_mode(root):
    """A mode no creation path produces: the staging file is opened 0o666 less the
    umask (0o644 under the one set here), so a writer that copied nothing would
    end at 0o644 and not at the 0o640 the file had."""
    target = root / "secret.json"
    target.write_text("old")
    target.chmod(0o640)
    previous = os.umask(0o022)
    try:
        with open_for_atomic_write(target) as handle:
            handle.write("new")
    finally:
        os.umask(previous)
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o640
    assert target.read_text() == "new"
