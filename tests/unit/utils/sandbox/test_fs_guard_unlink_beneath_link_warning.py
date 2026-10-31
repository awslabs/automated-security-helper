# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""unlink_beneath says when the entry it removed was a link.

The detect-secrets scanner removes its two worker exchange files with
``unlink_beneath`` before it writes the request. A symlink planted at one of those
names is removed as the link it is, never followed, so nothing is written through
it, but the writers that refuse a link raise ``OutputLinkRefused`` for the same
plant and a clean run leaves no link there. The removal is therefore logged as a
warning that names the entry, and the CHANGELOG names the exception. A file that
another name also refers to is removed by name only, and said the same way. A
regular file with one name, and a name that is not there, are removed in silence.
"""

import logging
import os
import sys

import pytest

from automated_security_helper.utils.sandbox import fs_guard

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks and hard links"),
]

NAME = "worker-request.json"


def _removal_warnings(caplog):
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING and NAME in record.getMessage()
    ]


def test_a_symlink_at_the_name_is_removed_not_followed_and_said(tmp_path, caplog):
    outside = tmp_path / "outside.txt"
    outside.write_text("keep\n")
    work = tmp_path / "work"
    work.mkdir()
    (work / NAME).symlink_to(outside)

    with caplog.at_level(logging.WARNING, logger="ash"):
        assert fs_guard.unlink_beneath(tmp_path, ("work", NAME)) is True

    assert not (work / NAME).is_symlink() and not (work / NAME).exists()
    assert outside.read_text() == "keep\n"
    (message,) = _removal_warnings(caplog)
    assert "symlink" in message
    assert str(tmp_path) not in message, "the warning names the entry, not its path"


def test_a_file_another_name_refers_to_is_removed_by_name_only_and_said(
    tmp_path, caplog
):
    other = tmp_path / "other-name"
    other.write_text("keep\n")
    work = tmp_path / "work"
    work.mkdir()
    os.link(other, work / NAME)

    with caplog.at_level(logging.WARNING, logger="ash"):
        assert fs_guard.unlink_beneath(tmp_path, ("work", NAME)) is True

    assert not (work / NAME).exists()
    assert other.read_text() == "keep\n"
    assert os.stat(other).st_nlink == 1
    (message,) = _removal_warnings(caplog)
    assert "other name" in message


def test_a_file_with_one_name_is_removed_without_a_warning(tmp_path, caplog):
    """The control: the warning is for a link, not for every removal."""
    work = tmp_path / "work"
    work.mkdir()
    (work / NAME).write_text("stale\n")

    with caplog.at_level(logging.WARNING, logger="ash"):
        assert fs_guard.unlink_beneath(tmp_path, ("work", NAME)) is True

    assert not (work / NAME).exists()
    assert _removal_warnings(caplog) == []


def test_a_missing_name_is_fine_and_silent(tmp_path, caplog):
    (tmp_path / "work").mkdir()

    with caplog.at_level(logging.WARNING, logger="ash"):
        assert fs_guard.unlink_beneath(tmp_path, ("work", NAME)) is True

    assert _removal_warnings(caplog) == []


def test_a_directory_at_the_name_is_still_refused_without_a_warning(tmp_path, caplog):
    (tmp_path / "work" / NAME).mkdir(parents=True)

    with caplog.at_level(logging.WARNING, logger="ash"):
        with pytest.raises(IsADirectoryError):
            fs_guard.unlink_beneath(tmp_path, ("work", NAME))

    assert (tmp_path / "work" / NAME).is_dir()
    assert _removal_warnings(caplog) == []


# The platform without os.fwalk removes by name from lstat checks. Taking fwalk
# away selects that branch on any POSIX host, where these links can be planted.


def test_by_name_a_file_another_name_refers_to_is_removed_by_name_only_and_said(
    tmp_path, caplog, monkeypatch
):
    monkeypatch.delattr(os, "fwalk", raising=False)
    other = tmp_path / "other-name"
    other.write_text("keep\n")
    work = tmp_path / "work"
    work.mkdir()
    os.link(other, work / NAME)

    with caplog.at_level(logging.WARNING, logger="ash"):
        assert fs_guard.unlink_beneath(tmp_path, ("work", NAME)) is True

    assert not (work / NAME).exists()
    assert other.read_text() == "keep\n"
    assert os.stat(other).st_nlink == 1
    (message,) = _removal_warnings(caplog)
    assert "other name" in message


def test_by_name_a_symlink_at_the_name_is_removed_not_followed_and_said(
    tmp_path, caplog, monkeypatch
):
    monkeypatch.delattr(os, "fwalk", raising=False)
    outside = tmp_path / "outside.txt"
    outside.write_text("keep\n")
    work = tmp_path / "work"
    work.mkdir()
    (work / NAME).symlink_to(outside)

    with caplog.at_level(logging.WARNING, logger="ash"):
        assert fs_guard.unlink_beneath(tmp_path, ("work", NAME)) is True

    assert not (work / NAME).is_symlink()
    assert outside.read_text() == "keep\n"
    (message,) = _removal_warnings(caplog)
    assert "symlink" in message


def test_by_name_a_file_with_one_name_and_a_missing_name_are_silent(
    tmp_path, caplog, monkeypatch
):
    """The controls: the warning is for a link, not for every removal."""
    monkeypatch.delattr(os, "fwalk", raising=False)
    work = tmp_path / "work"
    work.mkdir()
    (work / NAME).write_text("stale\n")

    with caplog.at_level(logging.WARNING, logger="ash"):
        assert fs_guard.unlink_beneath(tmp_path, ("work", NAME)) is True
        assert not (work / NAME).exists()
        assert fs_guard.unlink_beneath(tmp_path, ("work", NAME)) is True

    assert _removal_warnings(caplog) == []
