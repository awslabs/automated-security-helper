"""The pool chains every project's cancel event to the scan-wide one.

``_run_projects`` builds the chain on the submitting thread, because its pool
workers enter their scopes with no ambient context to link from
(:func:`link_parent`'s docstring): a caller-given event is linked to the
submitting thread's ambient event, and a project without one gets its own
event, built by the pool, so abandoning it stops it the way a cancelled scan
stops instead of leaving a worker nothing can interrupt.
"""

import threading
import time

import pytest

from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
    raise_if_cancelled,
)
from automated_security_helper.workspace import execution as execution_module
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    _run_projects,
)
from automated_security_helper.workspace.plan import ProjectPlan

pytestmark = pytest.mark.unit

#: How long the stand-in scan runs when nothing cancels it. Long enough that a
#: cell asserting a cancel arrived cannot be satisfied by the scan simply
#: ending, short enough that a red run ends.
_CAP_SECONDS = 3.0


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


class _AScanThatWaitsForItsCancel:
    """Stands in for ``_scan_one_project``: polls its scope like a real scan.

    Records how each project's scan ended in ``exits``: "cancelled" when the
    scope raised, "finished on its own" when the project's ``release`` event
    was set first, "ran to the cap" when nothing happened for ``_CAP_SECONDS``.
    """

    def __init__(self):
        self.exits = {}
        self.release = {}

    def __call__(
        self,
        project,
        settings,
        orchestrator_factory,
        abandoned=None,
        module_names=None,
    ):
        deadline = time.monotonic() + _CAP_SECONDS
        release = self.release.get(project.key)
        while time.monotonic() < deadline:
            try:
                raise_if_cancelled()
            except ScanCancelled:
                self.exits[project.key] = "cancelled"
                raise
            if release is not None and release.is_set():
                self.exits[project.key] = "finished on its own"
                return execution_module._failed_outcome(
                    project, settings, "finished on its own"
                )
            time.sleep(0.01)
        self.exits[project.key] = "ran to the cap"
        return execution_module._failed_outcome(project, settings, "ran to the cap")


def _settle(scan, key, deadline_s=2.0):
    """Wait briefly for *key*'s exit record: the pool does not wait for an
    abandoned caller-event-less worker at shutdown, so the record can land a
    moment after ``_run_projects`` returns."""
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline and key not in scan.exits:
        time.sleep(0.02)
    return scan.exits.get(key)


def test_an_abandoned_project_without_a_caller_event_is_stopped(tmp_path, monkeypatch):
    """A CLI-shape project (no caller event) is stopped when it is abandoned.

    The pool builds the event itself, so the abandon's cancel reaches the
    worker's scope; before that wiring the worker could not be interrupted
    and ran to completion in the background.
    """
    scan = _AScanThatWaitsForItsCancel()
    monkeypatch.setattr(execution_module, "_scan_one_project", scan)

    collected = _run_projects(
        [_project(tmp_path, "slow")],
        _settings(tmp_path, project_timeout=0.2),
        None,
        1,
        cancel_events=None,
    )

    assert collected["slow"].outcome.error.startswith("timed out"), collected
    assert _settle(scan, "slow") == "cancelled"


@pytest.mark.parametrize("shape", ["caller-event", "pool-built"])
def test_a_scan_wide_cancel_reaches_every_pool_project(tmp_path, monkeypatch, shape):
    """A direct set of the scan-wide event cancels the pool's projects.

    The drive is a plain ``set()`` on the submitting thread's ambient event:
    exactly what the SIGTERM latch sets. It must reach a worker whose event
    the caller gave (the MCP registry's shape, linked by the pool) and one
    whose event the pool built (the CLI's shape, constructed with the
    ambient event as its parent).
    """
    scan = _AScanThatWaitsForItsCancel()
    monkeypatch.setattr(execution_module, "_scan_one_project", scan)
    scan_wide = CancelEvent()
    events = {"one": CancelEvent()} if shape == "caller-event" else None

    timer = threading.Timer(0.3, scan_wide.set)
    timer.start()
    try:
        with cancel_scope(scan_wide):
            collected = _run_projects(
                [_project(tmp_path, "one")],
                _settings(tmp_path),
                None,
                1,
                cancel_events=events,
            )
    finally:
        timer.cancel()

    assert _settle(scan, "one") == "cancelled"
    assert "cancelled" in (collected["one"].outcome.error or ""), collected


def test_a_projects_own_cancel_stays_its_own(tmp_path, monkeypatch):
    """Must-not-flag control, green before and after the pool wiring.

    Setting one project's event -- the same plain ``set()`` the pool's
    ``_cancel`` performs when it abandons that project -- cancels that
    project only: a sibling still running finishes on its own, and the
    scan-wide event the chain links to is never set from below.
    """
    scan = _AScanThatWaitsForItsCancel()
    release = threading.Event()
    scan.release["quick"] = release
    monkeypatch.setattr(execution_module, "_scan_one_project", scan)
    scan_wide = CancelEvent()
    events = {"slow": CancelEvent(), "quick": CancelEvent()}

    stop_slow = threading.Timer(0.2, events["slow"].set)
    finish_quick = threading.Timer(0.5, release.set)
    stop_slow.start()
    finish_quick.start()
    try:
        with cancel_scope(scan_wide):
            collected = _run_projects(
                [_project(tmp_path, "slow"), _project(tmp_path, "quick")],
                _settings(tmp_path),
                None,
                2,
                cancel_events=events,
            )
    finally:
        stop_slow.cancel()
        finish_quick.cancel()

    assert _settle(scan, "slow") == "cancelled"
    assert _settle(scan, "quick") == "finished on its own"
    assert "cancelled" in (collected["slow"].outcome.error or ""), collected
    assert "finished on its own" in (collected["quick"].outcome.error or ""), collected
    # The chain answers downward only: a project's set never reaches the
    # scan-wide event. Read with the plain Event flag, not the chain.
    assert not threading.Event.is_set(scan_wide)


def test_an_abandon_cancels_no_other_project(tmp_path, monkeypatch):
    """Must-not-flag control through the real abandon path.

    One worker slot sequences the two projects: the first overruns its budget
    and is abandoned by the pool's own sweep, which must set that project's
    event only. The second project, starting on the freed slot after the
    abandon has already run, finishes on its own -- it would start already
    cancelled if the abandon touched any other project's event.
    """
    scan = _AScanThatWaitsForItsCancel()
    release = threading.Event()
    scan.release["quick"] = release
    monkeypatch.setattr(execution_module, "_scan_one_project", scan)
    scan_wide = CancelEvent()
    events = {"slow": CancelEvent(), "quick": CancelEvent()}

    finish_quick = threading.Timer(0.7, release.set)
    finish_quick.start()
    try:
        with cancel_scope(scan_wide):
            collected = _run_projects(
                [_project(tmp_path, "slow"), _project(tmp_path, "quick")],
                _settings(tmp_path, project_timeout=0.4),
                None,
                1,
                cancel_events=events,
            )
    finally:
        finish_quick.cancel()

    assert _settle(scan, "slow") == "cancelled"
    assert _settle(scan, "quick") == "finished on its own"
    assert collected["slow"].outcome.error.startswith("timed out"), collected
    assert "finished on its own" in (collected["quick"].outcome.error or ""), collected
    assert not threading.Event.is_set(scan_wide)
