# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The report step is told which projects this run scanned to completion.

``emit_workspace_reports`` takes ``completed_projects`` so that a caller holding
each project's outcome does not make the report step parse the whole unified
results file back to learn it. The executor holds every outcome and passed none,
so the report step read the file, and a file of another shape answered "unknown",
which turned its stale-artefact check off: a per-project report left by an earlier
run was then listed as this run's.

The executor now passes the keys whose outcome is COMPLETED.
"""

from __future__ import annotations

import pytest

from automated_security_helper.workspace import execution
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _sarif,
)
from tests.unit.workspace.test_workspace_reporting import FakeMergedReporter

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _report_step_arguments(tmp_path, monkeypatch, behaviour: dict) -> dict:
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
    FakeOrchestrator.behaviour.update(behaviour)
    seen: dict = {}
    real = execution.emit_workspace_reports

    def spy(**kwargs):
        seen.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(execution, "emit_workspace_reports", spy)
    execute_workspace(
        plan,
        ProjectScanSettings(
            output_dir=tmp_path / "out",
            phases=("scan", "report"),
            max_parallel_projects=1,
        ),
        orchestrator_factory=FakeOrchestrator.create,
        reporter_classes=[FakeMergedReporter],
    )
    assert seen, "control: the report step did not run"
    return seen


def test_only_the_projects_that_completed_are_named(tmp_path, monkeypatch):
    seen = _report_step_arguments(
        tmp_path,
        monkeypatch,
        {
            "api": {"sarif": _sarif(level="warning")},
            "web": {"raise": RuntimeError("the tool crashed")},
        },
    )

    # RED at the base: the argument was not passed at all, so the report step
    # read the answer back from the results file.
    assert seen.get("completed_projects") is not None
    assert sorted(seen["completed_projects"]) == ["api"]


def test_every_project_is_named_when_every_project_completed(tmp_path, monkeypatch):
    """Control: a clean run names them all."""
    seen = _report_step_arguments(
        tmp_path,
        monkeypatch,
        {
            "api": {"sarif": _sarif(level="warning")},
            "web": {"sarif": _sarif(level="warning")},
        },
    )

    assert sorted(seen["completed_projects"]) == ["api", "web"]
