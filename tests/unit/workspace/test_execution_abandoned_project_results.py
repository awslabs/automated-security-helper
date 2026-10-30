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
  agrees with the FAILED verdict; the discard follows no link at any depth, so a
  link nested under what it removes is unlinked and its target left as it was;
- a project whose future is already done when the poll overruns it keeps its
  completed outcome;
- the commit-or-abandon decision is taken once: a worker that has claimed its
  write cannot be abandoned afterwards, and an abandoned worker cannot claim;
- a scan stopped by its abandon's cancel (``ScanCancelled`` escapes the worker's
  ``except Exception``) has what it wrote before the cancel discarded too;
- a scan stopped by a cancel that is not its abandon (the poll's per-project
  budget cancels one project and the run goes on) records the FAILED outcome
  with ``output_written`` set when its output had been handed, so the masking
  pass rewrites the reports it left, and unset when the cancel came first;
- a scan that saved its files and then raised, with nothing abandoning it,
  claims the gate and keeps what it saved for the masking pass, as every other
  raise that is not an abandon does;
- the discard removes the two things a scan writes, the results file and the
  report directory, and leaves everything else an operator may have kept there;
- a raise AFTER the scan returned (the reduction: the verdict's file reads, the
  results write, the outcome's own validation) is handled by the same arms as a
  raise inside the scan: the outcome is FAILED with ``output_written`` set, the
  gate is claimed, and an abandoned project's saved output is discarded; a config
  refusal raised after the output was handed takes the gate too; and the read-back
  of an abandoned worker whose future raised says so on the project's error.
"""

from __future__ import annotations

import logging
import sys
import threading
from concurrent.futures import Future
from pathlib import Path
from typing import List, Optional

import pytest

from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.workspace import ProjectRunStatus
from automated_security_helper.workspace import execution
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
    _sarif,
    _settings,
)

pytestmark = pytest.mark.unit

PROJECT_TIMEOUT = 0.3

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    _SavesThenRaises.error = RuntimeError("boom")
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    # A class attribute the cases below reassign: back to the default, so a case
    # that forgets to set it does not inherit the previous case's error.
    _SavesThenRaises.error = RuntimeError("boom")


class _DiscardWatch:
    """The one discard of ``expected``, and whether a results file was there to remove."""

    def __init__(self, expected: Path) -> None:
        self.expected = expected
        self.done = threading.Event()
        self.had_results: Optional[bool] = None
        self.other_outputs: List[Path] = []


@pytest.fixture
def discard_watch(monkeypatch):
    """A watch on the real discard of ONE project's output, for the late-worker cases.

    ``_run`` returns with the pool shut down ``wait=False``, so the worker is
    still blocked when it returns and the scan's files do not exist yet. An
    assertion made then passes with or without the discard. The patched discard
    is module-global, so a late worker of another test in the same process could
    reach it too: the watch acts only on the path it was given and passes any
    other through, and it records whether the results file existed right before
    the real discard ran, so "the file is gone" cannot pass because the scan
    never wrote it.
    """

    def watch(expected: Path) -> _DiscardWatch:
        made = _DiscardWatch(expected)
        real = execution._discard_project_output

        def wrapped(project_output):
            if Path(project_output) != made.expected:
                made.other_outputs.append(Path(project_output))
                return real(project_output)
            made.had_results = (
                Path(project_output) / "ash_aggregated_results.json"
            ).exists()
            try:
                real(project_output)
            finally:
                made.done.set()

        monkeypatch.setattr(execution, "_discard_project_output", wrapped)
        return made

    return watch


class _SavesThenRaises(FakeOrchestrator):
    """A scan that saved its results and reports, then ended in *error*.

    ``FakeOrchestrator`` raises before it writes; the cases below need the
    other order, a scan that left files behind on its way out.
    """

    error: BaseException = RuntimeError("boom")

    def execute_scan(self, phases=None):
        (self.output_dir / "reports").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "ash_aggregated_results.json").write_text(
            "{}", encoding="utf-8"
        )
        (self.output_dir / "reports" / "ash.sarif").write_text("{}", encoding="utf-8")
        raise type(self).error


def test_the_output_the_scan_saved_is_removed_after_an_abandon(tmp_path, discard_watch):
    _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"))
    release = threading.Event()
    FakeOrchestrator.behaviour["wedged"] = {
        "block": release,
        "sarif": _sarif(level="error", count=3),
        "save_results": True,
    }
    project_output = tmp_path / "out" / "projects" / "wedged"
    results = project_output / "ash_aggregated_results.json"
    watch = discard_watch(project_output)
    try:
        outcome = _run(tmp_path, plan, project_timeout=PROJECT_TIMEOUT)
        # Let the abandoned worker finish: the scan saves its file and its
        # reports, then the workspace layer sees the abandon.
        release.set()
        finished = watch.done.wait(5.0)
    finally:
        release.set()

    assert finished, "the abandoned worker never ran its discard"
    assert watch.had_results is True, (
        "the scan saved no results file, so there was nothing for the discard to "
        "remove and the assertion below would pass on its own"
    )
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


@needs_symlinks
def test_the_discard_leaves_the_tools_output_and_every_link_alone(tmp_path):
    project_output = tmp_path / "out" / "projects" / "api"
    (project_output / "reports").mkdir(parents=True)
    (project_output / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
    (project_output / "reports" / "ash.sarif").write_text("{}", encoding="utf-8")
    (project_output / "scanners" / "bandit").mkdir(parents=True)
    (project_output / "scanners" / "bandit" / "raw.json").write_text(
        "{}", encoding="utf-8"
    )
    # Not the scan's: a file an operator kept beside the output.
    (project_output / "notes.txt").write_text("kept\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "kept.txt").write_text("outside\n", encoding="utf-8")
    (project_output / "linked").symlink_to(outside, target_is_directory=True)

    execution._discard_project_output(project_output)

    assert not (project_output / "ash_aggregated_results.json").exists()
    assert not (project_output / "reports").exists()
    assert (project_output / "scanners" / "bandit" / "raw.json").exists()
    assert (project_output / "notes.txt").read_text(encoding="utf-8") == "kept\n", (
        "the discard removed a file the scan did not write"
    )
    assert (project_output / "linked").is_symlink()
    assert (outside / "kept.txt").read_text(encoding="utf-8") == "outside\n"


@needs_symlinks
def test_the_discard_goes_through_no_link_at_the_names_it_removes(tmp_path):
    """``reports`` as a link to an outside directory, and the results file as a
    link to an outside file: the two names the discard removes, where a removal
    through the link would reach outside ``projects/<key>/``. Both links are left
    as they are and their targets untouched."""
    project_output = tmp_path / "out" / "projects" / "api"
    project_output.mkdir(parents=True)
    outside = tmp_path / "outside"
    (outside / "reports").mkdir(parents=True)
    (outside / "reports" / "ash.sarif").write_text("kept\n", encoding="utf-8")
    (outside / "results.json").write_text("kept too\n", encoding="utf-8")
    (project_output / "reports").symlink_to(
        outside / "reports", target_is_directory=True
    )
    (project_output / "ash_aggregated_results.json").symlink_to(
        outside / "results.json"
    )

    execution._discard_project_output(project_output)

    assert (project_output / "reports").is_symlink()
    assert (project_output / "ash_aggregated_results.json").is_symlink()
    assert (outside / "reports" / "ash.sarif").read_text(encoding="utf-8") == "kept\n"
    assert (outside / "results.json").read_text(encoding="utf-8") == "kept too\n"


@needs_symlinks
def test_the_discard_follows_no_link_nested_below_the_projects_output(tmp_path):
    """A link below a directory the discard removes is unlinked, never followed.

    The top-level walk skips a link by name; a link nested under ``reports/`` is
    reached by ``shutil.rmtree`` on ``reports/`` itself. This pins that the
    removal unlinks the link entries (a linked file and a linked directory) and
    leaves both targets as they were, so nothing outside ``projects/<key>/`` is
    touched by the discard at any depth.
    """
    project_output = tmp_path / "out" / "projects" / "api"
    reports = project_output / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.sarif").write_text("{}", encoding="utf-8")
    outside = tmp_path / "outside"
    (outside / "dir").mkdir(parents=True)
    (outside / "notes.txt").write_text("kept\n", encoding="utf-8")
    (outside / "dir" / "inner.txt").write_text("kept too\n", encoding="utf-8")
    (reports / "linked-file").symlink_to(outside / "notes.txt")
    (reports / "linked-dir").symlink_to(outside / "dir", target_is_directory=True)

    execution._discard_project_output(project_output)

    assert not reports.exists(), "the report directory survived the discard"
    assert not (reports / "linked-file").is_symlink()
    assert not (reports / "linked-dir").is_symlink()
    assert (outside / "notes.txt").read_text(encoding="utf-8") == "kept\n"
    assert (outside / "dir" / "inner.txt").read_text(encoding="utf-8") == "kept too\n"


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


def test_a_worker_that_raises_claims_the_gate_so_a_later_abandon_cannot_land(
    tmp_path,
):
    """The exception arm takes the decision, as the normal path does.

    A plain ``is_set()`` read left a window: a poll abandon landing after it
    recorded the timeout verdict while the files the scan wrote before it raised
    stayed. With the claim, a poll that comes afterwards finds the decision
    taken (``set()`` is False) and leaves the worker's own FAILED outcome to be
    collected.
    """
    _, plan = _make_workspace(tmp_path, ("broken", "MEDIUM"))
    FakeOrchestrator.behaviour["broken"] = {"raise": RuntimeError("boom")}
    gate = execution._AbandonGate()

    run = execution._scan_one_project(
        plan.projects[0], _settings(tmp_path), FakeOrchestrator.create, gate
    )

    assert run.outcome.status is ProjectRunStatus.FAILED
    assert "boom" in (run.outcome.error or "")
    assert gate.set() is False, (
        "a poll abandon after the worker raised must find the decision taken"
    )


def test_a_worker_that_raises_after_saving_with_the_gate_untaken_keeps_its_output(
    tmp_path,
):
    """The shape the case above leaves open: the scan saved its files and then
    raised, and nothing abandoned it. The worker claims the gate and records
    FAILED, and what the scan saved stays, as for every other raise that is not
    an abandon: the masking pass rewrites it, and a poll abandon landing
    afterwards finds the decision taken, so no discard follows either."""
    _, plan = _make_workspace(tmp_path, ("broken", "MEDIUM"))
    _SavesThenRaises.error = RuntimeError("boom")
    project_output = tmp_path / "out" / "projects" / "broken"
    gate = execution._AbandonGate()

    run = execution._scan_one_project(
        plan.projects[0], _settings(tmp_path), _SavesThenRaises.create, gate
    )

    assert FakeOrchestrator.built, "no orchestrator was built: the scan never ran"
    assert run.outcome.status is ProjectRunStatus.FAILED
    assert "boom" in (run.outcome.error or ""), run.outcome.error
    assert run.output_written is True, (
        "the output was handed before the raise; the masking pass has to cover it"
    )
    assert gate.set() is False, "the worker that raised must have claimed the gate"
    assert (project_output / "ash_aggregated_results.json").exists()
    assert (project_output / "reports" / "ash.sarif").exists()


def test_a_worker_abandoned_before_it_raised_discards_what_the_scan_left(tmp_path):
    """Must-not-regress control: an abandon that came first still discards.

    The scan ran and raised (the error names ``boom`` and an orchestrator was
    built), so the discard measured here is the exception arm's, not an early
    return on an already-abandoned gate.
    """
    _, plan = _make_workspace(tmp_path, ("broken", "MEDIUM"))
    _SavesThenRaises.error = RuntimeError("boom")
    project_output = tmp_path / "out" / "projects" / "broken"
    gate = execution._AbandonGate()
    assert gate.set() is True

    run = execution._scan_one_project(
        plan.projects[0], _settings(tmp_path), _SavesThenRaises.create, gate
    )

    assert FakeOrchestrator.built, "no orchestrator was built: the scan never ran"
    assert run.outcome.status is ProjectRunStatus.FAILED
    assert "boom" in (run.outcome.error or ""), run.outcome.error
    assert not (project_output / "ash_aggregated_results.json").exists()
    assert not (project_output / "reports").exists()


def test_a_worker_stopped_by_its_abandons_cancel_discards_what_the_scan_left(tmp_path):
    """``ScanCancelled`` is a BaseException: the ``except Exception`` arm never
    sees it, and the worker records the project FAILED with the error
    ``cancelled``. The abandon's cancel is the ordinary way an abandoned scan
    stops, so the output it saved before the cancel reached it is discarded as a
    raise's is."""
    _, plan = _make_workspace(tmp_path, ("stopped", "MEDIUM"))
    _SavesThenRaises.error = ScanCancelled("the scan was cancelled")
    project_output = tmp_path / "out" / "projects" / "stopped"
    gate = execution._AbandonGate()
    assert gate.set() is True

    run = execution._scan_one_project(
        plan.projects[0], _settings(tmp_path), _SavesThenRaises.create, gate
    )

    # The scan ran and saved before its cancel: the discard measured here is the
    # cancel arm's, not an early return on the already-abandoned gate.
    assert FakeOrchestrator.built, "no orchestrator was built: the scan never ran"
    assert run.outcome.status is ProjectRunStatus.FAILED
    assert run.outcome.error == "cancelled"
    assert not (project_output / "ash_aggregated_results.json").exists(), (
        "the results file the scan saved before its cancel survived beside the "
        "FAILED verdict"
    )
    assert not (project_output / "reports").exists()


def test_a_cancel_that_is_not_an_abandon_leaves_the_scans_output(tmp_path):
    """Must-not-flag control: a cancel that is not this project's abandon (the
    gate untaken) discards nothing, and the outcome says the output was handed:
    the poll's per-project budget cancels one project while the run goes on to
    write unified results, so the masking pass has to cover what it left."""
    _, plan = _make_workspace(tmp_path, ("stopped", "MEDIUM"))
    _SavesThenRaises.error = ScanCancelled("the project was cancelled")
    project_output = tmp_path / "out" / "projects" / "stopped"
    gate = execution._AbandonGate()

    run = execution._scan_one_project(
        plan.projects[0], _settings(tmp_path), _SavesThenRaises.create, gate
    )

    assert run.outcome.status is ProjectRunStatus.FAILED
    assert run.outcome.error == "cancelled"
    assert (project_output / "ash_aggregated_results.json").exists()
    assert gate.set() is False, "the cancelled worker did not claim its gate"
    assert run.output_written is True, (
        "a project cancelled after its output was handed must be masked like a "
        "project that raised after writing"
    )


class _CancelsBeforeHanding:
    """An orchestrator factory whose construction is where the cancel lands."""

    @classmethod
    def create(cls, **kwargs):
        raise ScanCancelled("the project was cancelled")


def test_a_cancel_before_the_output_was_handed_records_nothing_written(tmp_path):
    """Must-not-flag control for the masking pass: nothing of this run's is under
    projects/<key>/ when the cancel lands before an orchestrator exists, so the
    outcome leaves output_written unset and a previous run's files there alone."""
    _, plan = _make_workspace(tmp_path, ("stopped", "MEDIUM"))
    project_output = tmp_path / "out" / "projects" / "stopped"
    gate = execution._AbandonGate()

    run = execution._scan_one_project(
        plan.projects[0], _settings(tmp_path), _CancelsBeforeHanding.create, gate
    )

    assert run.outcome.status is ProjectRunStatus.FAILED
    assert run.outcome.error == "cancelled"
    assert run.output_written is False
    assert not (project_output / "ash_aggregated_results.json").exists()


class _QueuedFuture:
    """A future whose cancel answers as the sweep's window shapes it."""

    def __init__(self, cancellable: bool) -> None:
        self._cancellable = cancellable
        self.cancel_calls = 0

    def cancel(self) -> bool:
        self.cancel_calls += 1
        return self._cancellable


def test_a_queued_project_the_pool_cancels_is_recorded_never_started():
    gate = execution._AbandonGate()
    future = _QueuedFuture(cancellable=True)

    assert execution._close_never_started(future, gate, "queued") is True
    assert future.cancel_calls == 1
    assert gate.is_set() is True
    assert gate.try_commit() is False


def test_a_project_that_started_in_the_window_is_abandoned_and_logged(caplog):
    """The cancel found it running: abandoned through the gate, and said so."""
    caplog.set_level(logging.WARNING, logger="ash")
    gate = execution._AbandonGate()
    future = _QueuedFuture(cancellable=False)

    assert execution._close_never_started(future, gate, "late") is True
    assert gate.is_set() is True
    assert any(
        "started as the pool was closing" in record.getMessage()
        and "discarded when it returns" in record.getMessage()
        for record in caplog.records
    )


def test_a_project_that_committed_in_the_window_keeps_its_outcome(caplog):
    """The worker claimed its write first: not failed as never started."""
    caplog.set_level(logging.WARNING, logger="ash")
    gate = execution._AbandonGate()
    assert gate.try_commit() is True
    future = _QueuedFuture(cancellable=False)

    assert execution._close_never_started(future, gate, "committed") is False
    assert gate.is_set() is False
    assert any(
        "committed its results before it could be abandoned" in record.getMessage()
        for record in caplog.records
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
            # Waited for, not read: a worker's own exception stays on its future
            # for the loop to collect instead of raising out of the patched wait.
            widened["count"] += 1
            real_wait(list(still_pending), timeout=5.0)
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


# ---------------------------------------------------------------------------
# A raise after the scan returned is handled like a raise inside it
# ---------------------------------------------------------------------------


def _verdict_read_raises(monkeypatch, error: BaseException) -> None:
    """The reduction's first file read fails: it sits before the gate is taken,
    so both the committed and the abandoned shape reach it."""

    def raising(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(execution, "_verdict_results", raising)


class TestARaiseAfterTheScanReturned:
    def test_the_outcome_is_failed_and_its_output_is_marked_for_masking(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: the OSError left ``_scan_one_project`` unguarded and
        the poll recorded a plain FAILED outcome with ``output_written`` False, so
        the reports the scan saved were never re-masked."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(level="error", count=1),
            "save_results": True,
        }
        _verdict_read_raises(monkeypatch, OSError("disk full"))
        gate = execution._AbandonGate()

        run = execution._scan_one_project(
            plan.projects[0], _settings(tmp_path), FakeOrchestrator.create, gate
        )

        assert FakeOrchestrator.built, "no orchestrator was built: the scan never ran"
        assert run.outcome.status is ProjectRunStatus.FAILED
        assert "disk full" in (run.outcome.error or ""), run.outcome.error
        assert run.output_written is True, (
            "the output was handed before the reduction raised; the masking pass "
            "has to cover what the scan saved"
        )
        assert gate.set() is False, "the worker that raised must have claimed the gate"
        # Not an abandon: what the scan saved stays, as it does for a raise inside
        # the scan, and the masking pass rewrites it.
        assert (
            tmp_path / "out" / "projects" / "api" / "ash_aggregated_results.json"
        ).exists()

    def test_an_abandoned_project_has_its_saved_output_discarded(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: the abandon's discard lived only in the arms, which the
        reduction's raise never reached, so the results file stayed beside the
        FAILED verdict."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(level="error", count=1),
            "save_results": True,
        }
        _verdict_read_raises(monkeypatch, OSError("disk full"))
        project_output = tmp_path / "out" / "projects" / "api"
        gate = execution._AbandonGate()
        assert gate.set() is True

        run = execution._scan_one_project(
            plan.projects[0], _settings(tmp_path), FakeOrchestrator.create, gate
        )

        assert FakeOrchestrator.built, "no orchestrator was built: the scan never ran"
        assert run.outcome.status is ProjectRunStatus.FAILED
        assert "disk full" in (run.outcome.error or ""), run.outcome.error
        assert not (project_output / "ash_aggregated_results.json").exists(), (
            "the results file the scan saved survived beside the FAILED verdict"
        )
        assert not (project_output / "reports").exists()
        # The tools' own output is not the scan's to discard.
        assert (project_output / "scanners" / "bandit" / "raw.json").exists()

    def test_a_config_refusal_after_the_output_was_handed_takes_the_gate(
        self, tmp_path
    ):
        """Red at the base: the refusal arm set ``output_written`` and claimed
        nothing, so an abandoned project kept what the scan saved."""
        _, plan = _make_workspace(tmp_path, ("refused", "MEDIUM"))
        _SavesThenRaises.error = ASHConfigValidationError(
            "a scanner section is invalid"
        )
        project_output = tmp_path / "out" / "projects" / "refused"
        gate = execution._AbandonGate()
        assert gate.set() is True

        run = execution._scan_one_project(
            plan.projects[0], _settings(tmp_path), _SavesThenRaises.create, gate
        )

        assert run.outcome.status is ProjectRunStatus.FAILED
        assert run.outcome.invalid_config is True
        assert "a scanner section is invalid" in (run.outcome.error or "")
        assert not (project_output / "ash_aggregated_results.json").exists()
        assert not (project_output / "reports").exists()

    def test_a_config_refusal_with_the_gate_untaken_claims_it(self, tmp_path):
        """Must-not-flag control: the refusal's exit-3 verdict stands; a poll
        abandon landing afterwards finds the decision taken, and the output the
        scan saved stays for the masking pass."""
        _, plan = _make_workspace(tmp_path, ("refused", "MEDIUM"))
        _SavesThenRaises.error = ASHConfigValidationError(
            "a scanner section is invalid"
        )
        project_output = tmp_path / "out" / "projects" / "refused"
        gate = execution._AbandonGate()

        run = execution._scan_one_project(
            plan.projects[0], _settings(tmp_path), _SavesThenRaises.create, gate
        )

        assert run.outcome.invalid_config is True
        assert run.output_written is True
        assert gate.set() is False, "the refused worker must have claimed the gate"
        assert (project_output / "ash_aggregated_results.json").exists()


def test_the_read_back_names_a_worker_whose_future_raised(tmp_path, caplog):
    """Red at the base: the read-back ``continue``d past a raised future and the
    project's error said nothing about what was lost."""
    caplog.set_level(logging.ERROR, logger="ash")
    _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"))
    project = plan.projects[0]
    recorded = execution._failed_outcome(project, _settings(tmp_path), "abandoned")
    future: Future = Future()
    future.set_exception(RuntimeError("the worker fell over"))

    execution._read_back_abandoned_workers(
        {future: project}, {project.key: recorded}, {future: 0.0}
    )

    error = recorded.outcome.error or ""
    assert error.startswith("abandoned; its worker raised RuntimeError"), error
    assert "the worker fell over" in error
    assert "did not reach the workspace masking set" in error
    assert any(
        "its worker raised RuntimeError" in record.getMessage()
        for record in caplog.records
    )
    # Nothing a raised future could have carried is read from it.
    assert recorded.secret_values == set()
    assert recorded.output_written is False
