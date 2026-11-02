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
- its own reports do not survive the abandon: the late worker discards them with
  the results they hold (they contradict the FAILED verdict), so no value another
  project exposed can stay in clear in them; what the discard leaves under
  ``projects/<key>`` is the tools' own output, which the masking leaves alone for
  every project;
- a worker that does not come back is named on the project's error and in the
  log, so the gap is loud rather than silent.

How the wedged project is released
----------------------------------
``wedged`` blocks on its own cancel event, the one the executor sets when it
abandons the project, so the release is the abandon itself and no clock is
involved: the scan returns as soon as it has been given up on, however long the
plan setup or the sibling took. An earlier shape released it from a
``threading.Timer`` started before ``execute_workspace`` and gave the sibling a
0.3 s budget; on a contended CI runner the sibling took 0.38 s and was abandoned
before any masking assertion ran, and a slow start of ``wedged`` could fire the
timer before its deadline. The budget is the one ``test_execution.py`` documents
(``PROJECT_TIMEOUT``), for the reason given there: it has to cover the fixed cost
of starting a project at all.
"""

from __future__ import annotations

import logging
import re
import threading

import pytest

from automated_security_helper.core.cancellation import CancelEvent
from automated_security_helper.models.workspace import ProjectRunStatus
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.workspace import execution
from automated_security_helper.workspace.execution import execute_workspace
from tests.unit.workspace.test_execution import (
    PROJECT_TIMEOUT,
    FakeOrchestrator,
    _make_workspace,
    _sarif,
    _settings,
)

pytestmark = pytest.mark.unit

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


def _cancel_events(plan):
    """One caller-given cancel event per project; the abandon sets the project's."""
    return {project.key: CancelEvent() for project in plan.projects}


def _run_with_events(tmp_path, plan, events, **overrides):
    return execute_workspace(
        plan,
        _settings(tmp_path, project_timeout=PROJECT_TIMEOUT, **overrides),
        orchestrator_factory=FakeOrchestrator.create,
        cancel_events=events,
    )


def _entry(outcome, key):
    return next(entry for entry in outcome.payload.projects if entry.project == key)


def test_an_abandoned_workers_values_are_masked_in_the_other_projects_output(
    tmp_path,
):
    """``wedged`` overruns, is released by its abandon, and comes back inside the grace."""
    _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"), ("quick", "MEDIUM"))
    events = _cancel_events(plan)
    FakeOrchestrator.behaviour["wedged"] = {
        "block": events["wedged"],
        "sarif": _sarif(level="error", count=1),
        "secret_values": [WEDGED_VALUE],
    }
    planted = _plant_report(tmp_path, "quick", WEDGED_VALUE)
    try:
        outcome = _run_with_events(tmp_path, plan, events)
    finally:
        events["wedged"].set()

    assert _entry(outcome, "wedged").status is ProjectRunStatus.FAILED
    assert _entry(outcome, "quick").status is ProjectRunStatus.COMPLETED
    masked = planted.read_text(encoding="utf-8")
    assert WEDGED_VALUE not in masked, (
        "the abandoned project's secret value stayed in clear in another "
        "project's report: it never reached the workspace masking set"
    )


def test_an_abandoned_projects_own_output_keeps_no_other_projects_value_in_clear(
    tmp_path,
):
    """The late worker discards the reports and keeps only the tools' own output."""
    _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"), ("quick", "MEDIUM"))
    events = _cancel_events(plan)
    FakeOrchestrator.behaviour["wedged"] = {"block": events["wedged"]}
    FakeOrchestrator.behaviour["quick"] = {
        "sarif": _sarif(level="error", count=1),
        "secret_values": [QUICK_VALUE],
    }
    planted = _plant_report(tmp_path, "wedged", QUICK_VALUE)
    tool_output = tmp_path / "out" / "projects" / "wedged" / "scanners" / "bandit"
    tool_output.mkdir(parents=True, exist_ok=True)
    raw = tool_output / "raw.txt"
    raw.write_text(f"{QUICK_VALUE}\n", encoding="utf-8")
    try:
        outcome = _run_with_events(tmp_path, plan, events)
    finally:
        events["wedged"].set()

    assert _entry(outcome, "wedged").status is ProjectRunStatus.FAILED
    assert not planted.exists(), (
        "the abandoned project's report survived the discard: it holds findings "
        "the FAILED verdict says do not exist"
    )
    assert raw.exists(), "the tools' own output is kept by the discard"
    assert not (
        tmp_path / "out" / "projects" / "wedged" / "ash_aggregated_results.json"
    ).exists(), "the results file survived the discard"


def test_a_worker_that_does_not_come_back_is_named_as_unmasked(tmp_path, caplog):
    """No caller event: the pool does not wait for the stop, and says so.

    ``wedged`` blocks on a plain event this test releases only after the
    workspace has returned, so the worker has not come back whatever the host's
    speed; without a caller-given event the one bounded grace is all it gets.
    """
    caplog.set_level(logging.ERROR, logger=ASH_LOGGER.name)
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
    # The note names the grace the worker was in fact given, read from the
    # abandon's clock: at least the bounded wait the pool spent on it, never the
    # fixed "2s" it used to print whatever had elapsed.
    given = re.search(r"had not stopped (\d+\.\d)s after it was abandoned", entry.error)
    assert given is not None, entry.error
    assert float(given.group(1)) >= execution._ABANDONED_STOP_GRACE_SECONDS - 0.1, (
        entry.error
    )


def test_a_worker_that_comes_back_is_not_named_as_unmasked(tmp_path):
    """Must-not-flag control: a stop that finishes inside the grace adds no note."""
    _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"))
    events = _cancel_events(plan)
    FakeOrchestrator.behaviour["wedged"] = {"block": events["wedged"]}
    try:
        outcome = _run_with_events(tmp_path, plan, events)
    finally:
        events["wedged"].set()

    entry = _entry(outcome, "wedged")
    assert entry.status is ProjectRunStatus.FAILED
    assert entry.error is not None
    assert entry.error.startswith("timed out"), entry.error
    assert "did not reach" not in entry.error, entry.error
