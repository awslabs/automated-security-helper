# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three edges of the committed-output check, with git faked.

* A workspace check asked git about every project directory on its own, so a
  hung git cost one timeout per project before the run was refused. After git
  fails for a repository, the next directory in it gets the same answer.
* ``_combined`` quoted the first answer it saw, which can be the answer of a
  check that found nothing on disk, for another repository, and not the one of
  the entries the refusal names.
* The refusal for entries git could not account for named the output directory
  itself as one "which git tracks", a claim it had just said it could not make.

git is not run here: the answers are fakes of what ``git_index_below`` returns.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.core import committed_output as committed_output_module
from automated_security_helper.core.committed_output import (
    UnverifiedOutputFilesError,
    _combined,
    _Found,
    committed_entries_in_project_outputs,
    committed_output_files_error,
    unverified_output_files_error,
)
from automated_security_helper.utils.scan_output_dirs import (
    RESULTS_FILE_NAME,
    GitIndexAnswer,
)

pytestmark = pytest.mark.unit

HUNG = "git did not answer within 30 seconds"


def _project(repository: Path, name: str) -> Path:
    directory = repository / "out" / "projects" / name
    directory.mkdir(parents=True)
    (directory / RESULTS_FILE_NAME).write_text("{}")
    return directory


def _hung_git(monkeypatch, repositories: list[Path]) -> list[Path]:
    """Every call to git for a directory raises or returns the hung answer."""
    asked: list[Path] = []

    def repository_of(directory: Path):
        for repository in repositories:
            if Path(directory).is_relative_to(repository):
                return repository
        return None

    def listing(directory, **_kw):
        asked.append(Path(directory))
        return GitIndexAnswer(
            Path(directory), repository=repository_of(Path(directory)), error=HUNG
        )

    monkeypatch.setattr(committed_output_module, "git_index_below", listing)
    monkeypatch.setattr(committed_output_module, "_repository_root_of", repository_of)
    return asked


def test_a_hung_git_is_waited_for_once_per_repository(tmp_path, monkeypatch):
    repository = (tmp_path / "repo").resolve()
    projects = [_project(repository, name) for name in ("api", "web", "worker")]
    asked = _hung_git(monkeypatch, [repository])

    with pytest.raises(UnverifiedOutputFilesError) as refused:
        committed_entries_in_project_outputs(projects)

    # Red at the base: git was asked for each of the three projects.
    assert len(asked) == 1
    assert HUNG in str(refused.value)
    # The refusal still names the entries of every project.
    assert len(refused.value.entries) == 3


def test_a_directory_in_another_repository_is_still_asked(tmp_path, monkeypatch):
    first = (tmp_path / "first").resolve()
    second = (tmp_path / "second").resolve()
    projects = [
        _project(first, "api"),
        _project(first, "web"),
        _project(second, "api"),
    ]
    asked = _hung_git(monkeypatch, [first, second])

    with pytest.raises(UnverifiedOutputFilesError):
        committed_entries_in_project_outputs(projects)

    assert len(asked) == 2


def test_the_refusal_quotes_the_answer_of_the_entries_it_names(tmp_path):
    empty_check = GitIndexAnswer(
        tmp_path / "a", repository=tmp_path / "a", error="another repository's error"
    )
    entry_check = GitIndexAnswer(
        tmp_path / "b", repository=tmp_path / "b", error="the entries' error"
    )
    entry = tmp_path / "b" / RESULTS_FILE_NAME

    combined = _combined(
        [
            _Found([], [], empty_check),
            _Found([], [entry], entry_check),
        ]
    )

    # Red at the base: the first answer, the empty check's, won.
    assert combined.answer is entry_check
    assert combined.unverified == [entry]


def test_unverified_output_directory_is_not_said_to_be_tracked(tmp_path):
    output = (tmp_path / "out").resolve()
    answer = GitIndexAnswer(output, repository=tmp_path, error="index is corrupt")

    unverified = str(unverified_output_files_error(output, [output], answer))
    committed = str(committed_output_files_error(output, [output]))

    # Red at the base: the unverified message said git tracks the directory.
    assert "the output directory itself" in unverified
    assert "which git tracks" not in unverified
    # The control: for committed entries git does track it.
    assert "the output directory itself, which git tracks" in committed
