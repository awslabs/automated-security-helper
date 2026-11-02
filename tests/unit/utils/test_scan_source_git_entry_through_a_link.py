# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``.git`` that is a link to a gitfile is read as the gitfile.

``_git_entry_is_plain`` resolved a link at ``.git`` and then required the result to
be a directory, so a link to a gitfile (a regular file naming the git dir) failed
that test and the repository was labeled not plain, hence nested, where git follows
the link, reads the gitfile and starts on the directory it names. A link to a
gitfile is now parsed as a gitfile, with a relative record joined under the
directory of the link, as git joins it.

Nothing here starts git. Every path is under ``tmp_path``.
"""

from __future__ import annotations

import os
import sys

import pytest

from automated_security_helper.utils.scan_source import _git_entry_is_plain

pytestmark = pytest.mark.unit

needs_fifos = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


def _admin(tmp_path, name="admin"):
    admin = tmp_path / name
    admin.mkdir()
    (admin / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (admin / "config").write_text("", encoding="utf-8")
    return admin


@needs_symlinks
def test_a_link_to_a_gitfile_naming_a_plain_git_dir_is_plain(tmp_path):
    admin = _admin(tmp_path)
    store = tmp_path / "store"
    store.mkdir()
    (store / "gitfile").write_text(f"gitdir: {admin.as_posix()}\n", encoding="utf-8")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").symlink_to(store / "gitfile")

    assert _git_entry_is_plain(checkout / ".git")


@needs_symlinks
def test_a_relative_record_in_a_linked_gitfile_is_joined_under_the_links_directory(
    tmp_path,
):
    _admin(tmp_path, "admin")
    elsewhere = tmp_path / "store" / "deeper"
    elsewhere.mkdir(parents=True)
    # Joined under the link's directory (checkout/), ``../admin`` is the plain
    # directory; joined under the file's directory (store/deeper/) it names
    # ``store/admin``, which does not exist.
    (elsewhere / "gitfile").write_text("gitdir: ../admin\n", encoding="utf-8")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").symlink_to(elsewhere / "gitfile")

    assert _git_entry_is_plain(checkout / ".git")


@needs_symlinks
@needs_fifos
def test_a_link_to_a_gitfile_naming_a_git_dir_with_a_fifo_is_not_plain(tmp_path):
    admin = tmp_path / "admin"
    admin.mkdir()
    os.mkfifo(admin / "HEAD")
    store = tmp_path / "store"
    store.mkdir()
    (store / "gitfile").write_text(f"gitdir: {admin.as_posix()}\n", encoding="utf-8")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").symlink_to(store / "gitfile")

    assert not _git_entry_is_plain(checkout / ".git")


@needs_symlinks
def test_a_link_to_a_file_that_is_not_a_gitfile_is_not_plain(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    (store / "gitfile").write_text("not a gitfile\n", encoding="utf-8")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").symlink_to(store / "gitfile")

    assert not _git_entry_is_plain(checkout / ".git")


@needs_symlinks
def test_control_a_link_to_a_plain_git_directory_is_still_plain(tmp_path):
    admin = _admin(tmp_path)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").symlink_to(admin, target_is_directory=True)

    assert _git_entry_is_plain(checkout / ".git")
