# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The verdict counts the first run of the project's SARIF report, as it carries the model's.

Why this file exists
--------------------
A project's verdict counts its findings from the SARIF report its own reporter
wrote (``_verdict_results``), because the reporter serializes every suppression
where the in-memory model does not. The reader folded the results of EVERY run
in that file into one list, while the run carried into the unified file is the
model's ``runs[0]`` (``_extract_run`` keeps the first and warns about the rest).
A file with two runs was therefore counted twice over while the carried run's
``tool`` and ``rules`` described one, and a file with no run counted zero
findings instead of falling back to the model as an unreadable file does.

The contract these cases pin:

- the report's first run is what the verdict counts, and a second run is logged
  and left out, as the model's second run is;
- a report with no run falls back to the model's results, as an unreadable or
  unparsable report does;
- a one-run report, the shipped shape, counts exactly what it carries (control).
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.models.workspace import ProjectRunStatus
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
    _sarif,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _result(index: int) -> dict:
    return {
        "ruleId": f"rule-{index}",
        "level": "error",
        "message": {"text": f"finding {index}"},
        "properties": {"scanner_name": "bandit", "issue_severity": "HIGH"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f"src/f{index}.py"}}}
        ],
    }


def _report(*runs: list) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "ASH"}}, "results": list(results)}
            for results in runs
        ],
    }


def _scan(tmp_path, written: dict):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        # The model carries four findings; the file is what the verdict counts.
        "sarif": _sarif(level="error", count=4),
        "written_sarif": written,
    }
    return _run(tmp_path, plan)


def test_a_second_run_in_the_report_is_not_counted(tmp_path, caplog):
    """Red at the base: both runs' results were folded in, 3 counted for 2."""
    caplog.set_level(logging.WARNING, logger="ash")

    outcome = _scan(tmp_path, _report([_result(1), _result(2)], [_result(3)]))

    entry = outcome.payload.projects[0]
    assert entry.status is ProjectRunStatus.COMPLETED, entry.error
    assert entry.finding_count == 2
    assert any(
        "carries 2 runs" in record.getMessage()
        and "counts only the first" in record.getMessage()
        for record in caplog.records
    ), [record.getMessage() for record in caplog.records]


def test_a_report_with_no_run_falls_back_to_the_models_results(tmp_path, caplog):
    """Red at the base: zero findings were counted from a file with no run,
    while an unreadable file fell back to the model's four."""
    caplog.set_level(logging.WARNING, logger="ash")

    outcome = _scan(tmp_path, {"version": "2.1.0", "runs": []})

    entry = outcome.payload.projects[0]
    assert entry.status is ProjectRunStatus.COMPLETED, entry.error
    assert entry.finding_count == 4
    assert any("carries no run" in record.getMessage() for record in caplog.records), [
        record.getMessage() for record in caplog.records
    ]


def test_a_one_run_report_counts_what_it_carries(tmp_path, caplog):
    """Control: the shipped shape, one run, counted as before and without a warning."""
    caplog.set_level(logging.WARNING, logger="ash")

    outcome = _scan(tmp_path, _report([_result(1), _result(2), _result(3)]))

    entry = outcome.payload.projects[0]
    assert entry.status is ProjectRunStatus.COMPLETED, entry.error
    assert entry.finding_count == 3
    assert not any("SARIF report" in record.getMessage() for record in caplog.records)
