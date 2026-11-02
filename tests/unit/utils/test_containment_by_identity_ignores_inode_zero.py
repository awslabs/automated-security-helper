# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Containment decided by identity gives no answer on a mount without inodes.

``os.path.samefile`` compares ``(st_dev, st_ino)`` and nothing else. A mount that
reports inode 0 for every file (some network and FUSE file systems do) made every
directory on it the same one, so an outside candidate was taken for the root: the
workspace resolver's containment check accepted it, ``scan_source`` labeled an
outside directory as inside the repository, and the output-directory ownership
check called any two directories one. ``output_dir_links.same_by_identity``
refuses to answer when either side has no identity, and the three callers use it.

Every path here is under ``tmp_path``. The stand-in for such a mount reports
inode 0 for what is under ``tmp_path`` and leaves everything else alone.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import (
    output_dir_links,
    path_containment,
    scan_output_dirs,
    scan_source,
)

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@pytest.fixture
def mount_without_inodes(tmp_path, monkeypatch):
    """Report inode 0 for every path under ``tmp_path``, as such a mount does."""
    real_stat = os.stat
    prefixes = (os.path.abspath(tmp_path), os.path.realpath(tmp_path))

    def stat(path, *args, **kwargs):
        found = real_stat(path, *args, **kwargs)
        try:
            named = os.path.abspath(os.fspath(path))
        except TypeError:
            return found
        if any(named == p or named.startswith(p + os.sep) for p in prefixes):
            fields = tuple(found)
            return os.stat_result(fields[:1] + (0,) + fields[2:])
        return found

    monkeypatch.setattr(os, "stat", stat)


def _two_directories(tmp_path):
    base = Path(os.path.realpath(tmp_path))
    root = base / "root"
    outside = base / "elsewhere" / "deep"
    root.mkdir()
    outside.mkdir(parents=True)
    return root, outside


def test_two_directories_on_a_mount_without_inodes_are_not_one(
    tmp_path, mount_without_inodes
):
    root, outside = _two_directories(tmp_path)

    assert not output_dir_links.same_by_identity(outside, root)
    assert not output_dir_links.same_by_identity(root, root)


def test_control_a_directory_is_its_own_identity_and_no_other(tmp_path):
    root, outside = _two_directories(tmp_path)

    assert output_dir_links.same_by_identity(root, root)
    assert not output_dir_links.same_by_identity(root, outside)
    assert not output_dir_links.same_by_identity(root, tmp_path / "missing")


def test_an_outside_candidate_is_not_within_the_root_on_such_a_mount(
    tmp_path, mount_without_inodes
):
    root, outside = _two_directories(tmp_path)

    assert path_containment._is_within(outside, root) is False


def test_the_scan_source_label_is_not_relative_to_a_root_on_such_a_mount(
    tmp_path, mount_without_inodes
):
    root, outside = _two_directories(tmp_path)

    assert scan_source._relative_by_identity(outside, root) is None


def test_the_output_directory_check_does_not_join_two_directories_on_such_a_mount(
    tmp_path, mount_without_inodes
):
    root, outside = _two_directories(tmp_path)

    assert scan_output_dirs._same_directory(outside, root) is False


@needs_symlinks
def test_control_a_link_to_the_root_is_still_within_it_by_identity(tmp_path):
    root, _ = _two_directories(tmp_path)
    (root / "sub").mkdir()
    link = Path(os.path.realpath(tmp_path)) / "alias"
    link.symlink_to(root, target_is_directory=True)

    assert path_containment._is_within(link / "sub", root) is True
    assert scan_source._relative_by_identity(link / "sub", root) == "sub"
