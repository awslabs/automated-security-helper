# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A gitfile's relative record is followed link by link, as git follows it.

``_git_entry_is_plain`` checks the HEAD, config and commondir of the git dir that
a gitfile (or a ``.git`` link to one) names. The relative record was joined under
the checkout and collapsed as text, so ``link/../admin`` read as
``<checkout>/admin``. git opens it with the link followed first: ``..`` goes to
the parent of what the link names, so it waits in ``<link target's parent>/admin``.
With a link in the record the check read one directory and git waited on another.
The ``commondir`` record had the same shape and is read the same way
(``test_scan_source_commondir_follows_links_as_git_does``).

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.scan_source import (
    _git_dir_named_by,
    _git_entry_is_plain,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here"),
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]

_RECORD = "gitdir: link/../admin\n"


def _admin(path: Path, *, fifo: str | None) -> Path:
    """A git dir at *path* whose HEAD and config are regular files, except the
    one named by *fifo*, which is a FIFO."""
    path.mkdir(parents=True)
    for name in ("HEAD", "config"):
        if name == fifo:
            os.mkfifo(path / name)
        else:
            (path / name).write_text("", encoding="utf-8")
    return path


def _two_admins(tmp_path, *, fifo_beside_the_checkout, fifo_name="config"):
    """A checkout with a ``link`` to ``elsewhere/sub`` and two ``admin`` dirs: one
    beside the checkout's link (what the collapsed text names) and one beside the
    link's target (what git opens). One holds a FIFO named *fifo_name*, the other
    is plain. Returns (checkout, the admin git opens)."""
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "sub").mkdir(parents=True)
    (checkout / "link").symlink_to(elsewhere / "sub")
    beside_the_checkout = _admin(
        checkout / "admin", fifo=fifo_name if fifo_beside_the_checkout else None
    )
    beside_the_target = _admin(
        elsewhere / "admin", fifo=None if fifo_beside_the_checkout else fifo_name
    )
    assert beside_the_checkout != beside_the_target
    return checkout, beside_the_target


@pytest.mark.parametrize("fifo_name", ["HEAD", "config"])
def test_a_fifo_in_the_dir_git_opens_through_a_link_in_a_gitfile_record_is_found(
    tmp_path, fifo_name
):
    checkout, _ = _two_admins(
        tmp_path, fifo_beside_the_checkout=False, fifo_name=fifo_name
    )
    gitfile = checkout / ".git"
    gitfile.write_text(_RECORD, encoding="utf-8")

    assert not _git_entry_is_plain(gitfile)


@pytest.mark.parametrize("fifo_name", ["HEAD", "config"])
def test_a_plain_dir_git_opens_is_not_masked_by_a_fifo_in_the_collapsed_dir(
    tmp_path, fifo_name
):
    """The other direction: the text-collapsed dir holds the FIFO, the dir git
    opens is plain, and the entry is plain."""
    checkout, _ = _two_admins(
        tmp_path, fifo_beside_the_checkout=True, fifo_name=fifo_name
    )
    gitfile = checkout / ".git"
    gitfile.write_text(_RECORD, encoding="utf-8")

    assert _git_entry_is_plain(gitfile)


@pytest.mark.parametrize("fifo_name", ["HEAD", "config"])
def test_a_fifo_in_the_dir_git_opens_is_found_through_a_dot_git_link_to_a_gitfile(
    tmp_path, fifo_name
):
    """A relative record in a gitfile that ``.git`` links to is joined under the
    link's directory (the checkout), and its own link is followed the same way."""
    checkout, _ = _two_admins(
        tmp_path, fifo_beside_the_checkout=False, fifo_name=fifo_name
    )
    store = tmp_path / "store"
    store.mkdir()
    (store / "gitfile").write_text(_RECORD, encoding="utf-8")
    (checkout / ".git").symlink_to(store / "gitfile")

    assert not _git_entry_is_plain(checkout / ".git")


@pytest.mark.parametrize("fifo_name", ["HEAD", "config"])
def test_a_plain_dir_git_opens_is_not_masked_through_a_dot_git_link_to_a_gitfile(
    tmp_path, fifo_name
):
    checkout, _ = _two_admins(
        tmp_path, fifo_beside_the_checkout=True, fifo_name=fifo_name
    )
    store = tmp_path / "store"
    store.mkdir()
    (store / "gitfile").write_text(_RECORD, encoding="utf-8")
    (checkout / ".git").symlink_to(store / "gitfile")

    assert _git_entry_is_plain(checkout / ".git")


def test_the_git_dir_is_the_one_git_opens_through_the_link(tmp_path):
    checkout, beside_the_target = _two_admins(tmp_path, fifo_beside_the_checkout=False)
    gitfile = checkout / ".git"
    gitfile.write_text(_RECORD, encoding="utf-8")

    assert _git_dir_named_by(gitfile, checkout) == Path(
        os.path.realpath(beside_the_target)
    )


def test_control_a_record_with_no_link_names_the_dir_the_text_names(tmp_path):
    admin = _admin(tmp_path / "admin", fifo=None)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    gitfile = checkout / ".git"
    gitfile.write_text("gitdir: ../admin\n", encoding="utf-8")

    assert _git_dir_named_by(gitfile, checkout) == Path(os.path.realpath(admin))
    assert _git_entry_is_plain(gitfile)


def test_control_a_record_naming_a_fifo_dir_with_no_link_is_not_plain(tmp_path):
    _admin(tmp_path / "admin", fifo="HEAD")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    gitfile = checkout / ".git"
    gitfile.write_text("gitdir: ../admin\n", encoding="utf-8")

    assert not _git_entry_is_plain(gitfile)


def test_a_record_holding_a_nul_names_nothing_that_can_be_told(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    gitfile = checkout / ".git"
    gitfile.write_bytes(b"gitdir: ../ad\x00min\n")

    assert _git_dir_named_by(gitfile, checkout) is None
    assert not _git_entry_is_plain(gitfile)
