# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The paths ASH reads from git are the paths git stores, byte for byte.

With the default ``core.quotePath``, git C-quotes a path holding a byte above
0x7f, a control character, a double quote or a backslash (``naive.py`` spelled
with U+00EF for its ``i`` prints as ``"na\\303\\257ve.py"``), and a name can
begin with a space. ``get_changed_files`` runs the diff with
``core.quotePath=false`` and ``-z`` and splits on NUL with nothing stripped,
each name decoded as Python decodes a file name, so each name read back matches
its file (git 2.50.1) and ``--changed-files-only`` keeps the findings in each
of them.

Reading ``git rev-parse --show-toplevel`` in ``git_repository_root`` the same lossy
way would strip a trailing space from the root's name, so every changed path would
be joined onto a directory that is not the repository, and a root that is not UTF-8
would make the call raise ``UnicodeDecodeError``. Only the newline git ends the
line with is removed, and the root is decoded as a file name.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import (
    get_changed_files,
    git_repository_root,
)

# Built with chr() so the source file stays ASCII.
NAIVE = f"na{chr(0xEF)}ve.py"

#: Names every platform can hold.
PORTABLE_NAMES = (NAIVE, " lead.py", "plain.py")
#: Names Windows refuses (a control character, a quote, a separator).
POSIX_NAMES = ("tab\tname.py", 'quo"te.py', "back\\slash.py", "new\nline.py")

POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32", reason="Windows does not allow these names"
)
RAW_BYTES_ONLY = pytest.mark.skipif(
    sys.platform in ("win32", "darwin"),
    reason="a name that is not UTF-8 needs a filesystem that stores raw bytes",
)


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(  # nosec B603 B607 -- list args, no shell, fixture repos only
        [
            "git",
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        timeout=30,
    )


@pytest.fixture
def isolated_git(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    return tmp_path


def _clone_with_changes(root: Path, work: Path, names) -> Path:
    """A checkout of a ``file://`` origin with one commit adding *names* on top."""
    origin = root / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")
    (origin / "base.py").write_text("base = 1\n", encoding="utf-8")
    _git(origin, "add", "base.py")
    _git(origin, "commit", "-q", "-m", "base")
    _git(root, "clone", "-q", origin.as_uri(), os.fsdecode(work))
    for name in names:
        path = Path(os.fsdecode(work)) / name
        with open(os.fsencode(path), "wb") as handle:
            handle.write(b"x = 1\n")
    _git(Path(os.fsdecode(work)), "add", "-A")
    _git(Path(os.fsdecode(work)), "commit", "-q", "-m", "change")
    return Path(os.fsdecode(work))


def _check(work: Path, names) -> None:
    changed = get_changed_files(base_ref="origin/main", cwd=work)

    assert changed is not None
    assert sorted(str(path) for path in changed) == sorted(names)
    root = git_repository_root(work)
    for path in changed:
        assert (root / path).is_file(), path


def test_changed_names_come_back_as_git_stores_them(isolated_git):
    work = _clone_with_changes(isolated_git, isolated_git / "work", PORTABLE_NAMES)

    _check(work, PORTABLE_NAMES)


@POSIX_ONLY
def test_changed_names_git_would_quote_come_back_whole(isolated_git):
    names = PORTABLE_NAMES + POSIX_NAMES
    work = _clone_with_changes(isolated_git, isolated_git / "work", names)

    _check(work, names)


@RAW_BYTES_ONLY
def test_a_changed_name_that_is_not_utf8_comes_back_as_its_file(isolated_git):
    name = os.fsdecode(b"caf\xe9.py")
    work = _clone_with_changes(isolated_git, isolated_git / "work", [name])

    _check(work, [name])


@POSIX_ONLY
def test_a_repository_root_ending_in_a_space_is_that_root(isolated_git):
    work = _clone_with_changes(isolated_git, isolated_git / "work ", ["a.py"])

    assert git_repository_root(work) == work.resolve()
    _check(work, ["a.py"])


@RAW_BYTES_ONLY
def test_a_repository_root_that_is_not_utf8_is_that_root(isolated_git):
    work = _clone_with_changes(
        isolated_git, isolated_git / os.fsdecode(b"w\xe9rk"), ["a.py"]
    )

    assert git_repository_root(work) == work.resolve()
    _check(work, ["a.py"])
