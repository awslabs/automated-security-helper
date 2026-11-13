"""The never-started reaper does not run in the poll that abandoned a worker.

At a bound of one, with no caller-given event (the CLI's shape), an abandoned
worker counted as holding its slot in the same poll iteration that abandoned
it, so every queued project was failed as never started in the same breath,
before the worker's pool-built cancel event could stop its scan and free the
slot. A scan that checks its scope inside one poll now frees the slot in time,
and the queued project runs on it.
"""

import threading

import pytest

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


def test_a_queued_project_starts_on_a_slot_the_abandon_frees_within_a_poll(
    tmp_path, monkeypatch
):
    """One slot, no caller events: ``wedged`` overruns and honours its scope.

    Before: the reaper ran in the abandon's own poll and failed ``queued`` as
    never started while ``wedged`` was about to return. Now the reaper waits
    one poll, ``wedged``'s stop has freed the slot by then, and ``queued`` runs.
    """
    scan = _AScanThatWaitsForItsCancel()
    release = threading.Event()
    release.set()
    scan.release["queued"] = release
    monkeypatch.setattr(execution_module, "_scan_one_project", scan)

    collected = _run_projects(
        [_project(tmp_path, "wedged"), _project(tmp_path, "queued")],
        _settings(tmp_path, project_timeout=0.2),
        None,
        1,
        cancel_events=None,
    )

    assert _settle(scan, "wedged") == "cancelled"
    assert collected["wedged"].outcome.error.startswith("timed out"), collected
    assert "never started" not in (collected["queued"].outcome.error or ""), (
        "the queued project was reaped in the same poll that abandoned the "
        "wedged one, before its stop could free the slot"
    )
    assert "finished on its own" in (collected["queued"].outcome.error or ""), collected


def test_a_worker_that_never_checks_its_scope_still_frees_the_queue(
    tmp_path, monkeypatch
):
    """Must-not-regress control: a scan that ignores its scope is still written
    off, one poll after the abandon AND after its stop grace has run out, and the
    queued project is failed as never started rather than waited for.

    The grace is shortened here: at its production value (the sandbox stop grace
    plus its margin, over ten seconds) the wedged worker's ten-second wait ends
    INSIDE the grace, the pool reads it as a worker that came back, and the
    queued project starts and returns, so the case measured nothing about the
    reaper. With a sub-second grace the wait outlives it and the write-off is
    what frees the queue.
    """
    release = threading.Event()

    def ignores_its_scope(
        project, settings, factory, abandoned=None, module_names=None
    ):
        if project.key == "wedged":
            release.wait(timeout=10)
        return execution_module._failed_outcome(project, settings, "returned")

    monkeypatch.setattr(execution_module, "_scan_one_project", ignores_its_scope)
    monkeypatch.setattr(execution_module, "_ABANDONED_STOP_GRACE_SECONDS", 0.3)
    try:
        collected = _run_projects(
            [_project(tmp_path, "wedged"), _project(tmp_path, "queued")],
            _settings(tmp_path, project_timeout=0.2),
            None,
            1,
            cancel_events=None,
        )
    finally:
        release.set()

    assert collected["wedged"].outcome.error.startswith("timed out"), collected
    assert "never started" in (collected["queued"].outcome.error or ""), collected
