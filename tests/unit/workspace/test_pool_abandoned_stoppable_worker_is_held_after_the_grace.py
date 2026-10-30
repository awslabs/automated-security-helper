# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An abandoned worker with a caller-given event holds its slot after the grace.

``_run_projects`` decides when a queued project is given up on from the
workers held by abandoned projects. A worker with a caller-given event (the MCP
registry's shape) was never counted, on the reasoning that the pool waits for
its stop at shutdown and the worker is about to be free. A scan that never
checks its scope is not about to be free: it held its slot for the rest of its
run, the queued projects were never failed as never started, and the run was
bounded by neither ``project_timeout`` nor the server's scan timeout. Such a
worker now counts as held once ``_ABANDONED_STOP_GRACE_SECONDS`` have passed on
the clock since its stop was requested (the grace was counted in polls, and a
poll ends at every completion, so it was spent early whenever other projects
finished); one that comes back inside the grace frees its slot as before.

The grace is one for every abandoned worker, and derived from the stop. A worker
WITHOUT a caller-given event (the CLI) was given none: its slot was written off
in the poll after the abandon, on the reasoning that the pool does not wait for
its stop at shutdown. Whether the pool waits at shutdown says nothing about when
the slot frees for a queued project, and the stop reaches the scanner's child the
same way on both paths, so the queued projects were failed as never started
while the stop was about to free the slot. And the grace itself was asserted at
2 s against a stop that gives the child ``SANDBOX_STOP_GRACE_SECONDS`` after
SIGTERM before SIGKILL: a tool that ignores SIGTERM came back after the grace,
with its slot already written off. The grace is now that stop grace plus a
margin, and the same on both paths.
"""

import threading

import pytest

from automated_security_helper.core.cancellation import CancelEvent
from automated_security_helper.utils.subprocess_utils import SANDBOX_STOP_GRACE_SECONDS
from automated_security_helper.workspace import execution as execution_module
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    _run_projects,
)
from automated_security_helper.workspace.plan import ProjectPlan
from tests.unit.workspace.test_pool_projects_chain_to_the_scan_wide_cancel import (
    _AScanThatWaitsForItsCancel,
    _settle,
)

pytestmark = pytest.mark.unit

#: Seconds of grace for these cases: short enough that a red run ends, long
#: enough that a worker released inside it is seen to come back.
GRACE_SECONDS = 0.2


def _project(tmp_path, key):
    project_dir = tmp_path / "workspace" / key
    project_dir.mkdir(parents=True, exist_ok=True)
    return ProjectPlan(
        key=key,
        relative_path=key,
        path=project_dir.as_posix(),
        label=key,
        display_label=key,
    )


def _settings(tmp_path, **overrides) -> ProjectScanSettings:
    defaults = {"output_dir": tmp_path / "out", "phases": ("scan",)}
    defaults.update(overrides)
    return ProjectScanSettings(**defaults)


class _AScanThatIgnoresItsScope:
    """Stands in for ``_scan_one_project``: ``wedged`` blocks on an event and never
    checks its cancel scope; every other project returns at once."""

    def __init__(self, release):
        self.release = release
        self.exits = {}

    def __call__(
        self,
        project,
        settings,
        orchestrator_factory,
        abandoned=None,
        module_names=None,
    ):
        if project.key == "wedged":
            self.release.wait(timeout=10)
            self.exits[project.key] = "released"
        else:
            self.exits[project.key] = "finished on its own"
        return execution_module._failed_outcome(
            project, settings, self.exits[project.key]
        )


def test_a_stoppable_worker_that_never_stops_is_counted_held_after_the_grace(
    tmp_path, monkeypatch
):
    """One slot; ``wedged`` is abandoned and never checks its scope; ``queued`` waits.

    Before: ``wedged`` was never counted, so ``queued`` was never given up on
    and ran only once the release, standing in for the end of the wedged scan,
    freed the slot. Now ``queued`` is failed as never started once the grace has
    passed; the pool still waits for ``wedged`` at shutdown, as the caller's
    event asks.

    The wedged scan is let go the moment the pool gives up on ``queued``
    (``_close_never_started`` is the one call that does so), not after a
    wall-clock margin: a slow poll on a loaded runner cannot let ``queued`` run
    first, and a pool that never gives up leaves the scan blocked until its own
    bound, after which ``queued`` runs and the last assertion reads it.
    """
    monkeypatch.setattr(
        execution_module, "_ABANDONED_STOP_GRACE_SECONDS", GRACE_SECONDS
    )
    release = threading.Event()
    scan = _AScanThatIgnoresItsScope(release)
    monkeypatch.setattr(execution_module, "_scan_one_project", scan)
    events = {"wedged": CancelEvent(), "queued": CancelEvent()}
    real_close = execution_module._close_never_started

    def release_once_queued_is_given_up(future, gate, key):
        closed = real_close(future, gate, key)
        if key == "queued":
            release.set()
        return closed

    monkeypatch.setattr(
        execution_module, "_close_never_started", release_once_queued_is_given_up
    )
    try:
        collected = _run_projects(
            [_project(tmp_path, "wedged"), _project(tmp_path, "queued")],
            _settings(tmp_path, project_timeout=0.2),
            None,
            1,
            cancel_events=events,
        )
    finally:
        release.set()

    assert collected["wedged"].outcome.error.startswith("timed out"), collected
    assert "never started" in (collected["queued"].outcome.error or ""), (
        "the queued project was never given up on: the abandoned worker with a "
        "caller event was not counted as holding its slot"
    )
    assert scan.exits.get("queued") is None, scan.exits


def test_a_stoppable_worker_that_stops_inside_the_grace_frees_its_slot(
    tmp_path, monkeypatch
):
    """Must-not-flag control: a scan that honours its scope comes back at once,
    and the queued project runs on its slot instead of being failed."""
    monkeypatch.setattr(
        execution_module, "_ABANDONED_STOP_GRACE_SECONDS", GRACE_SECONDS
    )
    scan = _AScanThatWaitsForItsCancel()
    release = threading.Event()
    release.set()
    scan.release["queued"] = release
    monkeypatch.setattr(execution_module, "_scan_one_project", scan)
    events = {"wedged": CancelEvent(), "queued": CancelEvent()}

    collected = _run_projects(
        [_project(tmp_path, "wedged"), _project(tmp_path, "queued")],
        _settings(tmp_path, project_timeout=0.2),
        None,
        1,
        cancel_events=events,
    )

    assert _settle(scan, "wedged") == "cancelled"
    assert collected["wedged"].outcome.error.startswith("timed out"), collected
    assert "finished on its own" in (collected["queued"].outcome.error or ""), collected


def test_the_grace_is_derived_from_the_subprocess_layers_stop_grace():
    """Red at the base: 2.0 s, asserted, against a stop that waits
    ``SANDBOX_STOP_GRACE_SECONDS`` after SIGTERM before it kills."""
    assert execution_module._ABANDONED_STOP_GRACE_SECONDS > SANDBOX_STOP_GRACE_SECONDS


def test_there_is_one_grace_for_every_abandoned_worker():
    """Red at the base: a second constant, 0.0, for the worker without a
    caller-given event."""
    assert not hasattr(execution_module, "_REAPER_GRACE_SECONDS")


def test_a_worker_without_a_caller_event_that_stops_inside_the_grace_frees_its_slot(
    tmp_path, monkeypatch
):
    """The CLI path (no ``cancel_events``): one slot; ``wedged`` is abandoned and
    its stop frees the slot a little later, inside the grace; ``queued`` runs on it.

    Red at the base: the slot was written off in the poll after the abandon
    (``_REAPER_GRACE_SECONDS = 0.0``), so ``queued`` was failed as never started
    before the stop could free the slot. The release stands in for the stop
    returning the worker; it is started from the abandon itself, so it lands
    after the abandon whatever the poll timing, well inside a 1 s grace.
    """
    monkeypatch.setattr(execution_module, "_ABANDONED_STOP_GRACE_SECONDS", 1.0)
    release = threading.Event()
    scan = _AScanThatIgnoresItsScope(release)
    monkeypatch.setattr(execution_module, "_scan_one_project", scan)
    real_failed = execution_module._failed_outcome
    timers = []

    def release_shortly_after_the_abandon(project, settings, error, **kwargs):
        if project.key == "wedged" and error.startswith("timed out"):
            timer = threading.Timer(0.3, release.set)
            timers.append(timer)
            timer.start()
        return real_failed(project, settings, error, **kwargs)

    monkeypatch.setattr(
        execution_module, "_failed_outcome", release_shortly_after_the_abandon
    )
    try:
        collected = _run_projects(
            [_project(tmp_path, "wedged"), _project(tmp_path, "queued")],
            _settings(tmp_path, project_timeout=0.2),
            None,
            1,
        )
    finally:
        release.set()
        for timer in timers:
            timer.cancel()

    assert collected["wedged"].outcome.error.startswith("timed out"), collected
    assert scan.exits.get("wedged") == "released", scan.exits
    assert "finished on its own" in (collected["queued"].outcome.error or ""), (
        "the queued project was failed as never started although the abandoned "
        "worker's slot was freed inside the grace"
    )
