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
    _GitFailures,
    _found_in_the_way,
    committed_entries_in_a_workspace_output,
)
from automated_security_helper.utils.scan_output_dirs import GitIndexAnswer

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
