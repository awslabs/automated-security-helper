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

- a project that finishes after being abandoned has the results file and the
  reports the scan saved removed, and the tools' own output kept, so its subtree
  agrees with the FAILED verdict;
- a project whose future is already done when the poll overruns it keeps its
  completed outcome;
- the commit-or-abandon decision is taken once: a worker that has claimed its
  write cannot be abandoned afterwards, and an abandoned worker cannot claim.
"""

from __future__ import annotations

import logging
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
ABANDONED_LATE = "finished after being abandoned"


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _wait_for_the_late_worker(caplog, deadline_seconds=5.0):
    """Block until the abandoned worker has run its discard, or the deadline.

    ``_run`` returns with the pool shut down ``wait=False``, so the worker is
    still blocked when it returns and the scan's files do not exist yet. An
    assertion made then passes with or without the discard; the worker's own
    warning is the signal that it has finished and acted.
    """
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if any(ABANDONED_LATE in record.getMessage() for record in caplog.records):
            return True
        time.sleep(0.02)
    return False


def test_the_output_the_scan_saved_is_removed_after_an_abandon(tmp_path, caplog):
    caplog.set_level(logging.WARNING, logger="ash")
    _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"))
    release = threading.Event()
    FakeOrchestrator.behaviour["wedged"] = {
        "block": release,
        "sarif": _sarif(level="error", count=3),
        "save_results": True,
    }
    project_output = tmp_path / "out" / "projects" / "wedged"
    results = project_output / "ash_aggregated_results.json"
    try:
        outcome = _run(tmp_path, plan, project_timeout=PROJECT_TIMEOUT)
        # Let the abandoned worker finish: the scan saves its file and its
        # reports, then the workspace layer sees the abandon.
        release.set()
        finished = _wait_for_the_late_worker(caplog)
    finally:
        release.set()

    assert finished, "the abandoned worker never reported finishing"
    entry = outcome.payload.projects[0]
    assert entry.status is ProjectRunStatus.FAILED
    assert entry.finding_count == 0
    assert not results.exists(), (
        "the scan phase's own results file survived the abandon and contradicts "
        "the FAILED verdict recorded for the project"
    )
    assert not (project_output / "reports").exists(), (
        "the report phase's own files survived the abandon"
    )
    # The tools' own output is not this run's to rewrite or remove.
    assert (project_output / "scanners" / "bandit" / "raw.json").exists()


def test_the_discard_leaves_the_tools_output_and_every_link_alone(tmp_path):
    project_output = tmp_path / "out" / "projects" / "api"
    (project_output / "reports").mkdir(parents=True)
    (project_output / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
    (project_output / "reports" / "ash.sarif").write_text("{}", encoding="utf-8")
    (project_output / "scanners" / "bandit").mkdir(parents=True)
    (project_output / "scanners" / "bandit" / "raw.json").write_text(
        "{}", encoding="utf-8"
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "kept.txt").write_text("outside\n", encoding="utf-8")
    (project_output / "linked").symlink_to(outside, target_is_directory=True)

    execution._discard_project_output(project_output)

    assert not (project_output / "ash_aggregated_results.json").exists()
    assert not (project_output / "reports").exists()
    assert (project_output / "scanners" / "bandit" / "raw.json").exists()
    assert (project_output / "linked").is_symlink()
    assert (outside / "kept.txt").read_text(encoding="utf-8") == "outside\n"


def test_the_gate_takes_the_decision_once():
    """A claim excludes a later abandon, and an abandon excludes a later claim."""
    committed = execution._AbandonGate()
    assert committed.try_commit() is True
    assert committed.set() is False
    assert committed.is_set() is False

    abandoned = execution._AbandonGate()
    assert abandoned.set() is True
    assert abandoned.is_set() is True
    assert abandoned.try_commit() is False
    # Idempotent on the side that won.
    assert abandoned.set() is True
    assert committed.try_commit() is True


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
