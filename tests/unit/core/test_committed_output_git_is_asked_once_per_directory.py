# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One composite check asks git about a directory once.

The workspace check asked git about its output root three times (the results
paths, the spool, the projects entry), each a ``git ls-files`` of its own with
its own timeout, and derived three answers from one listing. The listing git
gives for a directory is now kept for the rest of the check, so the second and
third asks about the same directory read the first's answer; a listing for one
directory is never used for another.

git is not run here: ``git_index_below`` is a fake that counts what it was asked.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.core import committed_output as committed_output_module
from automated_security_helper.core.committed_output import (
    WORKSPACE_PROJECTS_DIR_NAME,
    _found_in_the_way,
    _GitFailures,
    committed_entries_in_a_workspace_output,
)
from automated_security_helper.utils.scan_output_dirs import (
    GitIndexAnswer,
    GitIndexUnavailable,
)

pytestmark = pytest.mark.unit


def _counting_git(monkeypatch, repository: Path, names_by_dir: dict[Path, list[str]]):
    """A fake of the git reader, recording the directory of every ask."""
    asked: list[Path] = []

    def index_below(directory, **_kw):
        base = Path(directory).resolve()
        asked.append(base)
        return GitIndexAnswer(
            base=base, names=list(names_by_dir.get(base, [])), repository=repository
        )

    monkeypatch.setattr(committed_output_module, "git_index_below", index_below)
    return asked


def test_the_workspace_root_is_listed_once_for_the_spool_and_the_projects_entry(
    tmp_path, monkeypatch
):
    output = (tmp_path / "out").resolve()
    output.mkdir()
    project = output / WORKSPACE_PROJECTS_DIR_NAME / "api"
    project.mkdir(parents=True)
    asked = _counting_git(monkeypatch, output, {})

    committed_entries_in_a_workspace_output(output, [project])

    # Red at the previous tip: the spool check and the projects-entry check each
    # ran their own listing of the root, so the root was asked twice here.
    assert asked.count(output) == 1, asked


def test_a_listing_kept_for_one_directory_is_not_used_for_another(
    tmp_path, monkeypatch
):
    output = (tmp_path / "out").resolve()
    output.mkdir()
    project = output / WORKSPACE_PROJECTS_DIR_NAME / "api"
    project.mkdir(parents=True)
    failures = _GitFailures()
    asked = _counting_git(monkeypatch, output, {output: ["reports/x.sarif"]})
    first = committed_output_module._index_below(output, failures)
    second = committed_output_module._index_below(project, failures)

    assert first.names == ["reports/x.sarif"]
    assert second.names == []
    assert asked == [output, project]


def test_a_kept_listing_answers_the_results_paths_check(tmp_path, monkeypatch):
    """The results-paths check reads a kept listing as its own listing would:
    the entries at the results paths, the directory itself when git tracks it."""
    output = (tmp_path / "out").resolve()
    output.mkdir()
    failures = _GitFailures()
    asked = _counting_git(
        monkeypatch, output, {output: ["ash_aggregated_results.json"]}
    )
    committed_output_module._index_below(output, failures)

    found = _found_in_the_way(output, None, None, (), failures)

    # The kept listing answered: no second ask, and the committed entry is read
    # from it.
    assert asked == [output]
    assert found.committed == [output / "ash_aggregated_results.json"]
    assert found.answer is None


def test_a_kept_listing_whose_superproject_question_fails_is_unanswered(
    tmp_path, monkeypatch
):
    """The kept-listing branch asks the enclosing repository whether it tracks the
    directory, the same question committed_files_at_results_paths asks inside the
    try below it. That question raises GitIndexUnavailable when the enclosing
    repository gives no listing; asked outside the try, it escaped the check raw
    where every other git failure is folded into an unanswered directory."""
    output = (tmp_path / "out").resolve()
    output.mkdir()
    failures = _GitFailures()
    _counting_git(monkeypatch, output, {output: ["reports/x.sarif"]})
    committed_output_module._index_below(output, failures)
    failed = GitIndexAnswer(
        output,
        repository=output.parent,
        error="index file corrupt",
        could_not_run=False,
    )

    def no_listing(answer):
        raise GitIndexUnavailable(failed)

    monkeypatch.setattr(
        committed_output_module, "_an_enclosing_repository_tracks_the_root", no_listing
    )

    found = _found_in_the_way(output, None, None, (), failures)

    assert found.committed == []
    assert found.answer is failed
    # The failure is remembered under the enclosing repository, the key every
    # later directory in that repository is answered from; known_for(output)
    # itself still returns the kept listing, which is read before the failures.
    assert failures._answers[output.parent] is failed
    assert failures.known_for(output).names == ["reports/x.sarif"]


@pytest.mark.parametrize(
    "tracked, expected",
    [
        (False, lambda out: [out / "ash_aggregated_results.json"]),
        (True, lambda out: [out, out / "ash_aggregated_results.json"]),
    ],
)
def test_a_kept_listing_reads_the_superprojects_answer_both_ways(
    tmp_path, monkeypatch, tracked, expected
):
    """A superproject that does not track the directory (the commonest shape: a
    nested clone or an ignored checkout) answers "no", and the directory is not
    added to what is committed; one that tracks it answers "yes" and is."""
    output = (tmp_path / "out").resolve()
    output.mkdir()
    failures = _GitFailures()
    _counting_git(monkeypatch, output, {output: ["ash_aggregated_results.json"]})
    committed_output_module._index_below(output, failures)
    monkeypatch.setattr(
        committed_output_module,
        "_an_enclosing_repository_tracks_the_root",
        lambda answer: tracked,
    )

    found = _found_in_the_way(output, None, None, (), failures)

    assert found.committed == expected(output)
    assert found.answer is None
