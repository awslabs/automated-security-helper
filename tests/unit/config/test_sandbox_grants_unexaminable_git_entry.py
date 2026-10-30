# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``.git`` entry nobody can examine is an unverifiable boundary, not "no checkout".

``_git_shaped`` already counts a ``.git`` directory it cannot search, with a
warning, because failing open there would hand the repository's own files the
operator's trust. An entry that ``lstat`` itself refuses -- the directory holding
it cannot be searched, or its name is too long to look up -- is the same
situation: ``os.path.isfile`` and ``os.path.isdir`` answer False for it exactly
as they do for an entry that is not there. Only an entry that is provably absent
bounds nothing.

The refusal is injected by an ``lstat`` stand-in for exactly the entry's path, so
these tests run as any user.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from automated_security_helper.config.sandbox_grants import _git_shaped

pytestmark = pytest.mark.unit


def _lstat_raises_for(monkeypatch, entry: Path, error: OSError) -> None:
    real = os.lstat
    spelled = os.fspath(entry)

    def lstat(name, *args, **kwargs):
        if os.fspath(name) == spelled:
            raise error
        return real(name, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)


def _warnings_about(ash_log, entry: Path) -> list:
    return [
        record.getMessage()
        for record in ash_log
        if f"Treating {entry.as_posix()} as a checkout boundary" in record.getMessage()
    ]


@pytest.mark.parametrize("code", [errno.EACCES, errno.ENAMETOOLONG])
def test_an_entry_lstat_refuses_bounds_the_tree_with_a_warning(
    code, tmp_path, monkeypatch, ash_log, _warned_window
):
    entry = tmp_path / "blocked" / ".git"
    refusal = OSError(code, os.strerror(code), os.fspath(entry))
    _lstat_raises_for(monkeypatch, entry, refusal)

    assert _git_shaped(entry) is True

    warned = _warnings_about(ash_log, entry)
    assert len(warned) == 1, [record.getMessage() for record in ash_log]
    assert os.strerror(code) in warned[0], warned


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError(errno.ENOENT, "No such file or directory"),
        NotADirectoryError(errno.ENOTDIR, "Not a directory"),
    ],
    ids=["absent", "parent-is-a-file"],
)
def test_an_entry_that_is_provably_absent_bounds_nothing(
    error, tmp_path, monkeypatch, ash_log, _warned_window
):
    entry = tmp_path / "plain" / ".git"
    _lstat_raises_for(monkeypatch, entry, error)

    assert _git_shaped(entry) is False

    assert _warnings_about(ash_log, entry) == []


def test_an_entry_that_is_not_there_bounds_nothing(tmp_path, ash_log, _warned_window):
    entry = tmp_path / ".git"

    assert _git_shaped(entry) is False

    assert _warnings_about(ash_log, entry) == []
