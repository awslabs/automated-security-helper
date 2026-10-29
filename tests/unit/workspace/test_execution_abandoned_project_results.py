# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project abandoned at its timeout leaves no results that contradict its verdict.

Why this file exists
--------------------
The workspace records a project FAILED when it overruns ``project_timeout``, and
``_scan_one_project`` declines to write ``projects/<key>/ash_aggregated_results.json``
for a project it finds abandoned. Two gaps remained between those two facts.

The scan phase saves that same file itself, before the workspace layer can see
that the project was abandoned. Declining the workspace's own write left the
scan's copy in place: real findings in the project's subtree beside a unified
file recording the project FAILED with none.

The deadline poll read the clock after ``wait`` returned and abandoned every
overrunning project still in its pending set, including one that had finished in
the gap between the two reads. That project had completed, had written its
results, and was recorded FAILED with finding_count 0 all the same.

The contract these cases pin:

- a project that finishes after being abandoned has the results file the scan
  saved removed, so its subtree agrees with the FAILED verdict;
- a project whose future is already done when the poll overruns it keeps its
  completed outcome.
"""

from __future__ import annotations

import threading
import time

import pytest

from automated_security_helper.models.workspace import ProjectRunStatus
from automated_security_helper.workspace import execution
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
    _sarif,
)

pytestmark = pytest.mark.unit

PROJECT_TIMEOUT = 0.3


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def test_the_results_file_the_scan_saved_is_removed_after_an_abandon(tmp_path):
    _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"))
    release = threading.Event()
    FakeOrchestrator.behaviour["wedged"] = {
        "block": release,
        "sarif": _sarif(level="error", count=3),
        "save_results": True,
    }
    results = tmp_path / "out" / "projects" / "wedged" / "ash_aggregated_results.json"
    try:
        outcome = _run(tmp_path, plan, project_timeout=PROJECT_TIMEOUT)
        # Let the abandoned worker finish: the scan saves its file, then the
        # workspace layer sees the abandon.
        release.set()
        deadline = time.monotonic() + 5.0
        while results.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        release.set()

    entry = outcome.payload.projects[0]
    assert entry.status is ProjectRunStatus.FAILED
    assert entry.finding_count == 0
    assert not results.exists(), (
        "the scan phase's own results file survived the abandon and contradicts "
        "the FAILED verdict recorded for the project"
    )


def test_a_project_that_finished_before_the_poll_read_the_clock_is_not_abandoned(
    tmp_path, monkeypatch
):
    """The gap between ``wait`` returning and the deadline read is widened to a certainty."""
    real_wait = execution.wait
    widened = {"count": 0}

    def wait_then_let_it_finish(pending, **kwargs):
        done, still_pending = real_wait(pending, **kwargs)
        if widened["count"] == 0 and still_pending:
            # The first poll returns nothing done; before the loop reads the
            # clock, every pending future finishes. The old loop abandoned them.
            widened["count"] += 1
            for future in still_pending:
                future.result(timeout=5.0)
        return done, still_pending

    monkeypatch.setattr(execution, "wait", wait_then_let_it_finish)
    _, plan = _make_workspace(tmp_path, ("slow", "MEDIUM"))
    FakeOrchestrator.behaviour["slow"] = {
        "sleep": PROJECT_TIMEOUT * 2,
        "sarif": _sarif(level="error", count=2),
    }

    outcome = _run(tmp_path, plan, project_timeout=PROJECT_TIMEOUT)

    entry = outcome.payload.projects[0]
    assert widened["count"] == 1, "the widened gap never happened; nothing measured"
    assert entry.status is ProjectRunStatus.COMPLETED, entry.error
    assert entry.finding_count == 2
