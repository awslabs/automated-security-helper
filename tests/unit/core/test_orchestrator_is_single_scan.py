# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One ASHScanOrchestrator runs one scan.

The run id is per instance and never refreshed, the scan set is recorded
under it, and ``utils/get_scan_set.scan_set`` with the same run id reads the
recorded pair back instead of walking again (by design, so plugins reread
their own scan's list). A second ``execute_scan`` on the same instance would
therefore silently reuse the first scan's file list: files added since the
first call would never be scanned, with nothing saying so. The supported
shape is a new instance per scan; a second call refuses before any phase
launches.
"""

import inspect
import json
import sys
import threading

from unittest.mock import Mock, patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.core.previous_results import HELD_DIR_NAME
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

_ENGINE = (
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases"
)

PREVIOUS = {
    "reports/ash.sarif": '{"previous": "sarif"}',
    "reports/ash.summary.md": "# previous summary\n",
    "ash_aggregated_results.json": '{"previous": "results"}',
}


def _orchestrator(tmp_path, name):
    source = tmp_path / f"{name}-src"
    source.mkdir(exist_ok=True)
    output = tmp_path / f"{name}-out"
    output.mkdir(exist_ok=True)
    with (
        patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="single-scan"),
        ),
        patch(
            "automated_security_helper.core.orchestrator.scan_set",
            return_value=set(),
        ),
    ):
        return ASHScanOrchestrator(
            source_dir=source,
            output_dir=output,
            config_path=None,
            config_overrides=None,
            no_cleanup=False,
            metadata=None,
            ash_plugin_modules=[],
        )


def test_a_second_execute_scan_on_one_instance_refuses_before_any_launch(
    tmp_path, monkeypatch
):
    """The refusal comes before the wrapper's work: _execute_scan is the only
    path to any phase launch, and it ran exactly once."""
    launches = []

    def _stub(self, phases=None):
        launches.append(phases)
        return Mock(name="results")

    monkeypatch.setattr(ASHScanOrchestrator, "_execute_scan", _stub)
    orch = _orchestrator(tmp_path, "one")

    orch.execute_scan()
    with pytest.raises(ASHValidationError, match="single-scan") as err:
        orch.execute_scan()
    assert type(err.value).__name__ == "OrchestratorAlreadyUsedError"
    assert len(launches) == 1, (
        "the second call reached _execute_scan, so it would have scanned "
        "the first scan's recorded file list"
    )


def test_a_failed_first_scan_also_leaves_the_instance_consumed(tmp_path, monkeypatch):
    """The sentinel is set at the start of the first call: the previous-results
    set-aside and the recorded scan set are that scan's state whether it
    finished or not, so a retry also takes a new instance."""
    launches = []

    def _stub(self, phases=None):
        launches.append(phases)
        raise RuntimeError("the scan failed")

    monkeypatch.setattr(ASHScanOrchestrator, "_execute_scan", _stub)
    orch = _orchestrator(tmp_path, "failed")

    with pytest.raises(RuntimeError):
        orch.execute_scan()
    with pytest.raises(ASHValidationError, match="single-scan"):
        orch.execute_scan()
    assert len(launches) == 1


def test_two_instances_over_a_changed_tree_scan_the_current_tree(tmp_path):
    """The supported shape: each scan builds its own orchestrator, whose fresh
    run id walks the tree as it is now, while the first instance's run id
    reads back the list its scan recorded."""
    first = _orchestrator(tmp_path, "shared")
    source = first.source_dir
    (source / "a.py").write_text("x = 1\n", encoding="utf-8")

    recorded = {str(p) for p in first.scan_set_for_this_run()}
    assert any(p.endswith("a.py") for p in recorded), "the fixture tree was not walked"

    (source / "b.py").write_text("y = 2\n", encoding="utf-8")

    reread = {str(p) for p in first.scan_set_for_this_run()}
    assert reread == recorded, (
        "the same run id must read back the recorded list; if this walked "
        "again, the refusal below guards nothing"
    )

    second = _orchestrator(tmp_path, "shared")
    current = {str(p) for p in second.scan_set_for_this_run()}
    assert any(p.endswith("b.py") for p in current), (
        "a new instance's fresh run id must scan the tree as it is now"
    )


def _snapshot(root):
    """relpath -> file bytes (None for a directory), for every entry under root."""
    out = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        out[rel] = path.read_bytes() if path.is_file() else None
    return out


class _Phases:
    """Stands in for the engine's phases: writes this scan's own report."""

    def __init__(self, output):
        self.output = output
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        reports = self.output / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "ash.sarif").write_text(
            json.dumps({"new": self.calls}), encoding="utf-8"
        )
        return AshAggregatedResults()


def test_a_refusal_leaves_the_first_scans_set_aside_and_results_alone(tmp_path):
    """keep_previous_results with settle_on_success=False is the shape where the
    caller settles later, once the scan counts as having results. A refusal that
    lands between the first scan and that settle must neither put the previous
    results back over the first scan's own nor drop the set-aside; the caller's
    settle afterwards still works on the first scan's state."""
    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    for rel, text in PREVIOUS.items():
        path = output / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    orch = ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=output,
        show_progress=False,
        show_summary=False,
        keep_previous_results=True,
    )
    phases = _Phases(output)
    with patch(_ENGINE, side_effect=phases):
        orch.execute_scan(settle_on_success=False)
    assert phases.calls == 1
    assert (output / HELD_DIR_NAME).is_dir(), "the set-aside was not made"
    before = _snapshot(tmp_path)

    with patch(_ENGINE, side_effect=phases):
        with pytest.raises(ASHValidationError, match="single-scan"):
            orch.execute_scan(settle_on_success=False)
    assert phases.calls == 1
    assert _snapshot(tmp_path) == before, (
        "the refusal moved files: a restore here would put the previous "
        "scan's results back over the first scan's own"
    )

    orch.settle_previous_results(restore=False)
    assert not (output / HELD_DIR_NAME).exists()
    assert json.loads((output / "reports" / "ash.sarif").read_text()) == {"new": 1}
    assert not (output / "reports" / "ash.summary.md").exists()


def _sentinel_line():
    """The line of execute_scan that marks the instance used, read from the
    loaded source, so the schedule below holds threads on the real line."""
    function = inspect.unwrap(ASHScanOrchestrator.execute_scan)
    lines, start = inspect.getsourcelines(function)
    for offset, line in enumerate(lines):
        if line.strip() == "self._scan_executed = True":
            return start + offset
    return None


def test_two_threads_on_one_instance_run_exactly_one_scan(tmp_path, monkeypatch):
    """Deterministic schedule: a per-thread trace holds each thread on the line
    that marks the instance used until the other arrives too, or 3 s pass. With
    the check and the mark under one lock, only one thread can reach that line,
    so the hold times out, that thread's scan runs, and the other refuses. Code
    under test is unmodified; only the interleaving is chosen."""
    entries = []
    entry_lock = threading.Lock()

    def _stub(self, phases=None):
        with entry_lock:
            entries.append(threading.get_ident())
        return Mock(name="results")

    monkeypatch.setattr(ASHScanOrchestrator, "_execute_scan", _stub)
    orch = _orchestrator(tmp_path, "race")
    line = _sentinel_line()
    assert line is not None, (
        "execute_scan no longer marks with 'self._scan_executed = True'; "
        "point this schedule at the new mark"
    )
    code = inspect.unwrap(ASHScanOrchestrator.execute_scan).__code__
    hold = threading.Barrier(2, timeout=3)

    def _local(frame, event, arg):
        if event == "line" and frame.f_lineno == line:
            try:
                hold.wait()
            except threading.BrokenBarrierError:
                pass
        return _local

    def _tracer(frame, event, arg):
        return _local if frame.f_code is code else None

    outcomes = []
    outcome_lock = threading.Lock()
    start = threading.Barrier(2, timeout=10)

    def _run():
        sys.settrace(_tracer)
        try:
            start.wait()
            orch.execute_scan()
            what = "ran"
        except ASHValidationError:
            what = "refused"
        except BaseException as exc:  # noqa: BLE001 -- any other ending is the verdict
            what = f"other:{type(exc).__name__}"
        finally:
            sys.settrace(None)
        with outcome_lock:
            outcomes.append(what)

    threads = [threading.Thread(target=_run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not any(t.is_alive() for t in threads), "a thread did not finish"
    assert sorted(outcomes) == ["ran", "refused"], outcomes
    assert len(entries) == 1, "both threads passed the check and both scanned"
