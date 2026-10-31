# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A committed inner-run outcome record refuses a fresh scan.

Every fresh scan removed ``ash_inner_run_outcome.json`` from its output
directory (the orchestrator and the CLI's host-side discard both named it), but
the file was listed by neither the previous-run file names nor the results
paths the committed-output refusal reads, so a committed one was deleted with
no refusal. The name is now a previous-run file, and the fresh-scan check looks
for the previous-run files the results-path list does not carry. git is not run
here: the index answer is the fake, the one shape ``git_index_below`` returns.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.core import committed_output as committed_output_module
from automated_security_helper.core.committed_output import (
    PREVIOUS_RUN_FILE_NAMES,
    committed_entries_in_the_way,
)
from automated_security_helper.utils.inner_run_outcome import INNER_RUN_OUTCOME_FILE
from automated_security_helper.utils.scan_output_dirs import (
    RESULTS_FILE_NAME,
    GitIndexAnswer,
)

pytestmark = pytest.mark.unit


def _fake_git(monkeypatch, output: Path, names: list[str]) -> None:
    monkeypatch.setattr(
        committed_output_module,
        "git_index_below",
        lambda directory, **_kw: GitIndexAnswer(
            base=Path(directory).resolve(), names=list(names), repository=output
        ),
    )


def test_the_inner_run_outcome_record_is_a_previous_run_file():
    # Red at the base: the tuple held the results, scan-start and run files alone.
    assert INNER_RUN_OUTCOME_FILE in PREVIOUS_RUN_FILE_NAMES


def test_a_committed_inner_run_outcome_refuses_a_fresh_scan(tmp_path, monkeypatch):
    output = (tmp_path / "out").resolve()
    output.mkdir()
    _fake_git(monkeypatch, output, [INNER_RUN_OUTCOME_FILE])

    found = committed_entries_in_the_way(output)

    # Red at the base: the results-path list does not name the file, so [].
    assert found == [output / INNER_RUN_OUTCOME_FILE]


def test_a_report_over_existing_results_is_not_refused_for_it(tmp_path, monkeypatch):
    """The control: a scoped check writes no previous-run file, so none is sought."""
    output = (tmp_path / "out").resolve()
    output.mkdir()
    _fake_git(monkeypatch, output, [INNER_RUN_OUTCOME_FILE])

    found = committed_entries_in_the_way(output, files=(RESULTS_FILE_NAME,))

    assert found == []


def test_the_extra_lookup_ends_when_the_results_paths_list_the_name(monkeypatch):
    """Once scan_output_dirs lists the file, nothing is looked for twice."""
    root_files, directories = committed_output_module.results_path_names()
    monkeypatch.setattr(
        committed_output_module,
        "results_path_names",
        lambda: ((*root_files, INNER_RUN_OUTCOME_FILE), directories),
    )

    assert committed_output_module._previous_run_files_outside_the_results_paths() == ()
