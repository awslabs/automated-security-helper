# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An abandoned project's secret values reach the workspace masking set.

Why this file exists
--------------------
A value one project's secret finding exposed is masked in every project's output,
from the union of the values each project's own masking found. A project
abandoned at its ``project_timeout`` was recorded FAILED by the poll loop, and the
result its worker later returned, which carries those values, was never read.
So a password one project found in a file and another project passed on a
command line stayed in clear in the second project's reports, and the abandoned
project's own reports, written by its scan before the abandon could be seen,
were never masked with the other projects' values.

The contract these cases pin:

- an abandoned project whose worker comes back (a caller-given event, the pool
  waits for the stop) has its values masked in the other projects' output;
- its own reports are masked with the other projects' values;
- a worker that does not come back is named on the project's error and in the
  log, so the gap is loud rather than silent.
"""

from __future__ import annotations

import logging
import threading

import pytest

from automated_security_helper.core.cancellation import CancelEvent
from automated_security_helper.models.workspace import ProjectRunStatus
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.workspace import execution
from automated_security_helper.workspace.execution import execute_workspace
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _sarif,
    _settings,
)

pytestmark = pytest.mark.unit

PROJECT_TIMEOUT = 0.3
#: Values of the shape the masking propagates: long, mixed, no dictionary word.
WEDGED_VALUE = "zzWedgedValue0071Kq"
QUICK_VALUE = "zzQuickValue0072Lr"


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _plant_report(tmp_path, key, text):
    reports = tmp_path / "out" / "projects" / key / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    path = reports / "ash.html"
    path.write_text(f"<pre>{text}</pre>\n", encoding="utf-8")
    return path


def _run_with_events(tmp_path, plan, **overrides):
    return execute_workspace(
        plan,
        _settings(tmp_path, **overrides),
        orchestrator_factory=FakeOrchestrator.create,
        cancel_events={project.key: CancelEvent() for project in plan.projects},
    )


def _entry(outcome, key):
    return next(entry for entry in outcome.payload.projects if entry.project == key)


def test_an_abandoned_workers_values_are_masked_in_the_other_projects_output(
    tmp_path,
):
    """``wedged`` overruns, is released shortly after, and comes back inside the grace."""
    _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"), ("quick", "MEDIUM"))
    release = threading.Event()
    FakeOrchestrator.behaviour["wedged"] = {
        "block": release,
        "sarif": _sarif(level="error", count=1),
        "secret_values": [WEDGED_VALUE],
    }
    planted = _plant_report(tmp_path, "quick", WEDGED_VALUE)
    timer = threading.Timer(PROJECT_TIMEOUT + 0.3, release.set)
    timer.start()
    try:
        outcome = _run_with_events(tmp_path, plan, project_timeout=PROJECT_TIMEOUT)
    finally:
        timer.cancel()
        release.set()

    assert _entry(outcome, "wedged").status is ProjectRunStatus.FAILED
    assert _entry(outcome, "quick").status is ProjectRunStatus.COMPLETED
    masked = planted.read_text(encoding="utf-8")
    assert WEDGED_VALUE not in masked, (
        "the abandoned project's secret value stayed in clear in another "
        "project's report: it never reached the workspace masking set"
    )


def test_an_abandoned_projects_own_reports_are_masked_with_the_others_values(
    tmp_path,
):
    _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"), ("quick", "MEDIUM"))
    release = threading.Event()
    FakeOrchestrator.behaviour["wedged"] = {"block": release}
    FakeOrchestrator.behaviour["quick"] = {
        "sarif": _sarif(level="error", count=1),
        "secret_values": [QUICK_VALUE],
    }
    planted = _plant_report(tmp_path, "wedged", QUICK_VALUE)
    timer = threading.Timer(PROJECT_TIMEOUT + 0.3, release.set)
    timer.start()
    try:
        outcome = _run_with_events(tmp_path, plan, project_timeout=PROJECT_TIMEOUT)
    finally:
        timer.cancel()
        release.set()

    assert _entry(outcome, "wedged").status is ProjectRunStatus.FAILED
    assert QUICK_VALUE not in planted.read_text(encoding="utf-8"), (
        "the abandoned project's own report, written by its scan, kept another "
        "project's secret value in clear"
    )


def test_a_worker_that_does_not_come_back_is_named_as_unmasked(
    tmp_path, caplog, monkeypatch
):
    """No caller event: the pool does not wait for the stop, and says so."""
    caplog.set_level(logging.ERROR, logger=ASH_LOGGER.name)
    monkeypatch.setattr(execution, "_ABANDONED_STOP_GRACE_POLLS", 4)
    _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"), ("quick", "MEDIUM"))
    release = threading.Event()
    FakeOrchestrator.behaviour["wedged"] = {
        "block": release,
        "secret_values": [WEDGED_VALUE],
    }
    FakeOrchestrator.behaviour["quick"] = {
        "sarif": _sarif(level="error", count=1),
        "secret_values": [QUICK_VALUE],
    }
    try:
        outcome = execute_workspace(
            plan,
            _settings(tmp_path, project_timeout=PROJECT_TIMEOUT),
            orchestrator_factory=FakeOrchestrator.create,
        )
    finally:
        release.set()

    entry = _entry(outcome, "wedged")
    assert entry.status is ProjectRunStatus.FAILED
    assert entry.error is not None
    assert entry.error.startswith("timed out"), entry.error
    assert "did not reach the workspace masking set" in entry.error, entry.error
    assert "did not reach the workspace masking set" in caplog.text, caplog.text


def test_a_worker_that_comes_back_is_not_named_as_unmasked(tmp_path):
    """Must-not-flag control: a stop that finishes inside the grace adds no note."""
    _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"))
    release = threading.Event()
    FakeOrchestrator.behaviour["wedged"] = {"block": release}
    timer = threading.Timer(PROJECT_TIMEOUT + 0.3, release.set)
    timer.start()
    try:
        outcome = _run_with_events(tmp_path, plan, project_timeout=PROJECT_TIMEOUT)
    finally:
        timer.cancel()
        release.set()

    entry = _entry(outcome, "wedged")
    assert entry.status is ProjectRunStatus.FAILED
    assert entry.error is not None
    assert entry.error.startswith("timed out"), entry.error
    assert "did not reach" not in entry.error, entry.error
