# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A delivered tree is empty only when no directory of it holds a file.

``_holds_an_entry`` reads a directory whose listing fails as holding nothing.
That is judged per directory: one subdirectory that cannot be listed must not
make a tree with a readable file read as empty, which refused the delivery as
``delivered_source_missing``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp_server import _holds_an_entry

pytestmark = pytest.mark.unit

_UNREADABLE_BINDS = os.name != "nt" and not (
    hasattr(os, "geteuid") and os.geteuid() == 0
)


@pytest.mark.skipif(
    not _UNREADABLE_BINDS, reason="a mode of 000 does not bind this user or platform"
)
def test_a_tree_with_a_readable_file_and_an_unreadable_subdirectory_holds_an_entry(
    tmp_path,
):
    tree = tmp_path / "tree"
    locked = tree / "a-locked"
    locked.mkdir(parents=True)
    (tree / "z-readable.py").write_text("print(1)\n", encoding="utf-8")
    locked.chmod(0)
    try:
        # Control: the directory really cannot be listed.
        with pytest.raises(PermissionError):
            os.scandir(locked)
        assert _holds_an_entry(tree) is True
    finally:
        locked.chmod(0o700)


def test_a_listing_that_fails_in_one_directory_does_not_end_the_walk(
    tmp_path, monkeypatch
):
    """The same case with the failing listing and the order made certain: the
    unreadable directory is the one the walk takes up first, whatever order the
    file system lists the root in, and no mode bit is needed."""
    tree = tmp_path / "tree"
    locked = tree / "a-locked"
    readable = tree / "z-readable"
    locked.mkdir(parents=True)
    readable.mkdir()
    (readable / "app.py").write_text("print(1)\n", encoding="utf-8")
    real = os.scandir

    class _Listing:
        def __init__(self, entries):
            self.entries = entries

        def __enter__(self):
            return iter(self.entries)

        def __exit__(self, *exc):
            return False

    def scandir(path):
        if Path(path) == locked:
            raise PermissionError(13, "Permission denied", str(path))
        if Path(path) == tree:
            with real(path) as listing:
                # The walk pops the last directory it was given.
                entries = sorted(listing, key=lambda each: each.name, reverse=True)
            return _Listing(entries)
        return real(path)

    monkeypatch.setattr(os, "scandir", scandir)

    assert _holds_an_entry(tree) is True


@pytest.mark.skipif(
    not _UNREADABLE_BINDS, reason="a mode of 000 does not bind this user or platform"
)
def test_a_tree_whose_only_content_is_an_unreadable_directory_holds_nothing(tmp_path):
    tree = tmp_path / "tree"
    locked = tree / "locked"
    locked.mkdir(parents=True)
    locked.chmod(0)
    try:
        assert _holds_an_entry(tree) is False
    finally:
        locked.chmod(0o700)


def test_a_tree_of_empty_directories_and_a_bare_git_directory_holds_nothing(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref\n", encoding="utf-8")
    assert _holds_an_entry(tmp_path) is False


def test_a_missing_directory_holds_nothing(tmp_path):
    assert _holds_an_entry(tmp_path / "absent") is False
