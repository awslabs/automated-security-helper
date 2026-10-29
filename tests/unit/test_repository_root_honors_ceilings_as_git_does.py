# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH finds the repository an output directory is in as git would, ceilings included.

``scan_output_dirs._repository_root_of`` looks for a ``.git`` entry in a
directory and its ancestors, and honors ``GIT_CEILING_DIRECTORIES``. It stopped
at once when the directory it started from was itself listed, so a repository
whose root was listed was not found, and neither was one above a listed starting
directory. git still looks in the directory it starts from; a ceiling only stops
it from moving up into a listed directory. Measured with git 2.50.1, and each case
below is checked against ``git rev-parse --show-toplevel`` run from the same
directory with the same ceilings.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Sequence

import pytest

from automated_security_helper.utils.scan_output_dirs import (
    _repository_root_of,
    tracked_files_in,
)
from tests.unit.workspace.test_execution import _git

pytestmark = pytest.mark.integration

#: (where the search starts, the ceilings, the repository it finds), all relative
#: to a repository at ``r``.
CASES = [
    ("r", ["r"], "r"),
    ("r/a", ["r/a"], "r"),
    ("r/a/b", ["r/a"], None),
    ("r/a/b", ["r"], None),
    ("r/a/b", ["r/a/b", "r/a"], None),
    ("r/a/b", ["r/a/"], None),
    ("r/a/b", [], "r"),
    ("r/a/b", ["relative/entries/are/ignored"], "r"),
]


def _ceilings(tmp_path: Path, listed: Sequence[str]) -> str:
    """*listed*, the entries under ``r`` made absolute as written (a trailing ``/``
    kept), and tmp_path last, so that nothing above it counts."""
    entries = [
        f"{tmp_path.as_posix()}/{entry}" if entry.split("/")[0] == "r" else entry
        for entry in listed
    ]
    return os.pathsep.join([*entries, str(tmp_path)])


def _gits_answer(start: Path) -> Optional[Path]:
    found = _git(start, "rev-parse", "--show-toplevel")
    return Path(found.stdout.strip()).resolve() if found.returncode == 0 else None


@pytest.mark.parametrize(("start", "listed", "expected"), CASES)
def test_the_repository_found_is_the_one_git_finds(
    tmp_path, monkeypatch, start, listed, expected
):
    repository = tmp_path / "r"
    (repository / "a" / "b").mkdir(parents=True)
    assert _git(repository, "init", "-q").returncode == 0
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", _ceilings(tmp_path, listed))
    begin = tmp_path / start
    want = None if expected is None else (tmp_path / expected)

    # A control: git itself finds what the case says it finds.
    assert _gits_answer(begin) == (None if want is None else want.resolve())

    assert _repository_root_of(begin) == want


def test_a_repository_whose_root_is_a_ceiling_is_asked_about_its_files(
    tmp_path, monkeypatch
):
    """An output directory that is the root of its repository, listed as a ceiling,
    as a CI job may list its workspace: git is asked which files it tracks there."""
    repository = tmp_path / "out"
    repository.mkdir()
    (repository / "kept.txt").write_text("kept\n", encoding="utf-8")
    assert _git(repository, "init", "-q").returncode == 0
    assert _git(repository, "add", "kept.txt").returncode == 0
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv(
        "GIT_CEILING_DIRECTORIES", os.pathsep.join([str(repository), str(tmp_path)])
    )

    assert tracked_files_in(repository) == [repository / "kept.txt"]


def test_a_repository_above_a_listed_ceiling_is_not_asked(tmp_path, monkeypatch):
    repository = tmp_path / "repo"
    output = repository / "build" / "out"
    output.mkdir(parents=True)
    (output / "kept.txt").write_text("kept\n", encoding="utf-8")
    assert _git(repository, "init", "-q").returncode == 0
    assert _git(repository, "add", "build/out/kept.txt").returncode == 0
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv(
        "GIT_CEILING_DIRECTORIES",
        os.pathsep.join([str(repository / "build"), str(tmp_path)]),
    )

    assert tracked_files_in(output) is None
