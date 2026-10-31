# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A fresh scan's committed-output check runs ``git ls-files`` once per directory.

Why these tests exist
---------------------
The check for a fresh scan asks two questions of one directory: which results
paths git tracks, and which of the previous-run files outside the results paths
(``_previous_run_files_outside_the_results_paths``) it tracks. Each was a call of
its own, so every fresh scan, at every entry point, spawned ``git ls-files``
twice for the directory, each spawn allowed its own timeout. Without a failures
record (the single-directory check) nothing kept the first listing. One listing
now answers both questions, and a listing that git could not give is one wait,
not two.

git is not run here: ``git_index_below`` is a fake that counts what it was asked.
The earlier counting test faked the results-path reader too, so it passed while
production made two calls; this one fakes only the git reader both paths share.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.core import committed_output as committed_output_module
from automated_security_helper.core.committed_output import (
    committed_entries_in_the_way,
)
from automated_security_helper.utils.scan_output_dirs import (
    RESULTS_FILE_NAME,
    GitIndexAnswer,
)

pytestmark = pytest.mark.unit


def _outside_the_results_paths() -> str:
    names = committed_output_module._previous_run_files_outside_the_results_paths()
    assert names, "the premise: a previous-run file the results paths do not list"
    return names[0]


def _counting_git(monkeypatch, output: Path, names: list[str]) -> list[Path]:
    asked: list[Path] = []

    def index_below(directory, **_kw):
        base = Path(directory).resolve()
        asked.append(base)
        return GitIndexAnswer(base=base, names=list(names), repository=output)

    monkeypatch.setattr(committed_output_module, "git_index_below", index_below)
    return asked


def test_a_fresh_scan_lists_its_directory_once(tmp_path, monkeypatch):
    output = (tmp_path / "out").resolve()
    output.mkdir()
    asked = _counting_git(monkeypatch, output, [])

    committed_entries_in_the_way(output)

    # Red at the base: one listing for the results paths, one for the files
    # outside them.
    assert asked == [output]


def test_both_kinds_of_entry_are_still_found_from_the_one_listing(
    tmp_path, monkeypatch
):
    output = (tmp_path / "out").resolve()
    output.mkdir()
    outside = _outside_the_results_paths()
    asked = _counting_git(monkeypatch, output, [RESULTS_FILE_NAME, outside])

    found = committed_entries_in_the_way(output)

    assert asked == [output]
    assert sorted(found) == sorted([output / RESULTS_FILE_NAME, output / outside])


def test_a_directory_git_could_not_list_is_waited_for_once(tmp_path, monkeypatch):
    output = (tmp_path / "out").resolve()
    output.mkdir()
    asked: list[Path] = []

    def hung(directory, **_kw):
        base = Path(directory).resolve()
        asked.append(base)
        return GitIndexAnswer(base=base, repository=output, error="git timed out")

    monkeypatch.setattr(committed_output_module, "git_index_below", hung)
    (output / RESULTS_FILE_NAME).write_text("{}")

    with pytest.raises(committed_output_module.UnverifiedOutputFilesError):
        committed_entries_in_the_way(output)

    # The control: an answer git could not give already ended the check after one
    # ask, and still does.
    assert asked == [output]


def test_a_directory_outside_a_repository_has_nothing_committed(tmp_path, monkeypatch):
    """git answering "no repository" gives no entries and no refusal, in one ask."""
    output = (tmp_path / "out").resolve()
    output.mkdir()
    asked: list[Path] = []

    def no_repository(directory, **_kw):
        asked.append(Path(directory).resolve())
        return GitIndexAnswer(base=Path(directory).resolve())

    monkeypatch.setattr(committed_output_module, "git_index_below", no_repository)

    assert committed_entries_in_the_way(output) == []
    # Red at the base: asked twice.
    assert asked == [output]
