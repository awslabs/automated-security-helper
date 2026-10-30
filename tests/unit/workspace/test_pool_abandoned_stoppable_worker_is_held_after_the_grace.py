"""An abandoned worker with a caller-given event holds its slot after the grace.

``_run_projects`` decides when a queued project is given up on from the
workers held by abandoned projects. A worker with a caller-given event (the MCP
registry's shape) was never counted, on the reasoning that the pool waits for
its stop at shutdown and the worker is about to be free. A scan that never
checks its scope is not about to be free: it held its slot for the rest of its
run, the queued projects were never failed as never started, and the run was
bounded by neither ``project_timeout`` nor the server's scan timeout. Such a
worker now counts as held once ``_ABANDONED_STOP_GRACE_POLLS`` polls have passed
since its stop was requested; one that comes back inside the grace frees its
slot as before.
"""

import threading

import pytest

from automated_security_helper.core.cancellation import CancelEvent
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

#: Polls of grace for these cases: short enough that a red run ends, long enough
#: that a worker released inside it is seen to come back.
GRACE_POLLS = 4


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
    """
    # raising=False: at a base without the constant the case still measures the
    # behaviour (the queued project never given up on) rather than the attribute.
    monkeypatch.setattr(
        execution_module, "_ABANDONED_STOP_GRACE_POLLS", GRACE_POLLS, raising=False
    )
    release = threading.Event()
    scan = _AScanThatIgnoresItsScope(release)
    monkeypatch.setattr(execution_module, "_scan_one_project", scan)
    events = {"wedged": CancelEvent(), "queued": CancelEvent()}

    end_the_wedged_scan = threading.Timer(1.5, release.set)
    end_the_wedged_scan.start()
    try:
        collected = _run_projects(
            [_project(tmp_path, "wedged"), _project(tmp_path, "queued")],
            _settings(tmp_path, project_timeout=0.2),
            None,
            1,
            cancel_events=events,
        )
    finally:
        end_the_wedged_scan.cancel()
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
        execution_module, "_ABANDONED_STOP_GRACE_POLLS", GRACE_POLLS, raising=False
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
