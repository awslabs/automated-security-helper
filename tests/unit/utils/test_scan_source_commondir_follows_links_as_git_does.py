# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``commondir`` record is followed link by link, as git follows it.

``_git_entry_is_plain`` checks the ``config`` in the common dir that a git dir's
``commondir`` file names, because git reads it before anything else and waits
on a FIFO there. The record was resolved by collapsing its text, so
``link/../common`` read as ``<git dir>/common``. git opens it with the link
followed first: ``..`` goes to the parent of what the link names, so it waits in
``<link target's parent>/common``. With a link in the record the check read one
``config`` and git waited on another.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.scan_source import (
    _common_dir_named,
    _git_entry_is_plain,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here"),
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]


def _two_common_dirs(tmp_path, *, plain_beside_the_git_dir):
    """A git dir whose ``commondir`` is ``link/../common``, with two ``common``
    dirs: one beside the git dir (what the collapsed text names) and one beside
    the link's target (what git opens). ``config`` is a regular file in one and a
    FIFO in the other, as *plain_beside_the_git_dir* says."""
    repo = tmp_path / "repo"
    git_dir = repo / ".git"
    git_dir.mkdir(parents=True)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git_dir / "commondir").write_text("link/../common\n", encoding="utf-8")
    beside_the_git_dir = git_dir / "common"
    beside_the_git_dir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "sub").mkdir(parents=True)
    beside_the_target = elsewhere / "common"
    beside_the_target.mkdir()
    (git_dir / "link").symlink_to(elsewhere / "sub")
    plain, waited_on = (
        (beside_the_git_dir, beside_the_target)
        if plain_beside_the_git_dir
        else (beside_the_target, beside_the_git_dir)
    )
    (plain / "config").write_text("", encoding="utf-8")
    os.mkfifo(waited_on / "config")
    return git_dir, beside_the_target


def test_the_common_dir_is_the_one_git_opens_through_the_link(tmp_path):
    git_dir, beside_the_target = _two_common_dirs(
        tmp_path, plain_beside_the_git_dir=True
    )

    assert _common_dir_named(git_dir) == Path(os.path.realpath(beside_the_target))


def test_a_fifo_config_in_the_dir_git_opens_is_found_through_a_link(tmp_path):
    git_dir, _ = _two_common_dirs(tmp_path, plain_beside_the_git_dir=True)

    assert not _git_entry_is_plain(git_dir)


def test_a_plain_config_in_the_dir_git_opens_is_not_masked_by_the_other_dir(tmp_path):
    """The other direction: the text-collapsed dir holds the FIFO, the dir git
    opens holds a regular file, and the entry is plain."""
    git_dir, _ = _two_common_dirs(tmp_path, plain_beside_the_git_dir=False)

    assert _git_entry_is_plain(git_dir)


def test_control_a_record_with_no_link_names_the_dir_the_text_names(tmp_path):
    common = tmp_path / "common"
    common.mkdir()
    git_dir = tmp_path / "repo" / ".git"
    git_dir.mkdir(parents=True)
    (git_dir / "commondir").write_text("../../common\n", encoding="utf-8")

    assert _common_dir_named(git_dir) == Path(os.path.realpath(common))


def test_control_no_commondir_file_names_the_git_dir_itself(tmp_path):
    git_dir = tmp_path / "repo" / ".git"
    git_dir.mkdir(parents=True)

    assert _common_dir_named(git_dir) == git_dir


def test_a_record_holding_a_nul_names_nothing_that_can_be_told(tmp_path):
    git_dir = tmp_path / "repo" / ".git"
    git_dir.mkdir(parents=True)
    (git_dir / "commondir").write_bytes(b"../com\x00mon\n")

    assert _common_dir_named(git_dir) is None
