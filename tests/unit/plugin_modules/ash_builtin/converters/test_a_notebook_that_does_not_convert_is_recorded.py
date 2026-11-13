# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A notebook the jupyter converter could not convert is recorded, and the scan
reads it as lost coverage.

Why this exists
---------------
The converter launches nbconvert once, the way its dependency check chose, so a
run that fails is not repeated with another copy. A notebook that does not
convert is recorded in the converter's row, so the row does not read "No files
to convert" and the completeness gate counts the conversion as incomplete.

Each one is recorded in the row's failed_inputs, with the notebook's path
relative to the scanned tree and why it was not converted, and the gate counts a
converter with any as incomplete conversion. The failures are the ones a uv run
can have (nbconvert exited non-zero or timed out, reported no exit code, the run
raised after it started, it did not start, uv failed itself, or uv was gone when
the conversion ran), a run that exited 0 and wrote nothing, a direct launch the
OS refused, and a copy the check verified that no longer verifies when the
conversion runs; ``FAILURES`` is the list. Each reason says which, and names no
path. Each change is made as convert() starts: the phase runs the dependency
check twice, and a change made after the first check would let the second
choose another route.

The launches are the stand-ins of test_notebook_conversion_launches_one_tool.py,
whose ``world`` fixture this file uses: no program starts.
"""

from __future__ import annotations

import subprocess
from typing import Any, Callable, Dict, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
    incomplete_converters,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from tests.unit.plugin_modules.ash_builtin.converters import (
    test_notebook_conversion_launches_one_tool as launches,
)

pytestmark = pytest.mark.unit

JupyterConverter = launches.JupyterConverter

#: The one-notebook tree, its converter, and a stand-in for every launch.
world = launches.world

#: What the dependency check finds when uv runs nbconvert.
_THROUGH_UV: Dict[str, Any] = {"available": True, "preferred_source": "uv"}


def _a_verified_copy(world) -> Dict[str, Any]:
    return {
        "available": True,
        "preferred_source": "pre_installed",
        "pre_installed_path": str(world.installed),
    }


def _uv_outcome(outcome: str) -> Callable[[Any], None]:
    def change(world) -> None:
        world.uv.outcome = outcome

    return change


def _uv_gone(world) -> None:
    world.uv.available = False


def _uv_writes_nothing(world) -> None:
    """uv's run exits 0 and leaves no converted file."""

    def run_tool(
        tool_name: str, package_name: str, args: List[str], **kwargs: Any
    ) -> subprocess.CompletedProcess:
        argv = ["uv", "tool", "run", "--from", str(package_name), tool_name, *args]
        world.uv.runs.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    world.uv.run_tool = run_tool


def _uv_reports_no_exit_code(world) -> None:
    """uv's run ends with no exit code: a run ASH's own stop cancelled."""

    def run_tool(
        tool_name: str, package_name: str, args: List[str], **kwargs: Any
    ) -> subprocess.CompletedProcess:
        argv = ["uv", "tool", "run", "--from", str(package_name), tool_name, *args]
        world.uv.runs.append(argv)
        return subprocess.CompletedProcess(argv, None, "", "")

    world.uv.run_tool = run_tool


def _direct_reports_no_exit_code(world) -> None:
    world.launches.returncode = None


def _direct_launch_vanishes(world) -> None:
    """The verified copy is gone at launch: the OS refuses the start."""

    def raising(args: Any, *rest: Any, **kwargs: Any):
        raise FileNotFoundError(2, "No such file or directory")

    for name in launches.LAUNCHERS:
        world.monkeypatch.setattr(launches.MODULE, name, raising, raising=False)
    world.monkeypatch.setattr(launches.MODULE.subprocess, "run", raising)


def _uv_fails_itself(world) -> None:
    """uv's run ends with uv's own error: nbconvert never ran."""

    def run_tool(
        tool_name: str, package_name: str, args: List[str], **kwargs: Any
    ) -> subprocess.CompletedProcess:
        argv = ["uv", "tool", "run", "--from", str(package_name), tool_name, *args]
        world.uv.runs.append(argv)
        return subprocess.CompletedProcess(
            argv, 2, "", "error: No solution found when resolving tool dependencies\n"
        )

    world.uv.run_tool = run_tool


def _copy_stops_verifying(world) -> None:
    world.verified["status"] = "unsatisfied"


#: failure -> (what the check finds, what changes as the conversion starts).
FAILURES: Dict[str, Tuple[Callable[[Any], Dict[str, Any]], Callable[[Any], None]]] = {
    "uv-exited-1": (lambda world: _THROUGH_UV, _uv_outcome("exit-1")),
    "uv-timed-out": (lambda world: _THROUGH_UV, _uv_outcome("timed-out")),
    "uv-runner-raised": (
        lambda world: _THROUGH_UV,
        _uv_outcome("raised-after-start"),
    ),
    "uv-did-not-start": (lambda world: _THROUGH_UV, _uv_outcome("not-started")),
    "uv-failed-itself": (lambda world: _THROUGH_UV, _uv_fails_itself),
    "uv-no-exit-code": (lambda world: _THROUGH_UV, _uv_reports_no_exit_code),
    "direct-no-exit-code": (_a_verified_copy, _direct_reports_no_exit_code),
    "direct-could-not-start": (_a_verified_copy, _direct_launch_vanishes),
    "uv-gone-at-conversion": (lambda world: _THROUGH_UV, _uv_gone),
    "uv-exited-0-wrote-nothing": (lambda world: _THROUGH_UV, _uv_writes_nothing),
    "verified-copy-stops-verifying": (_a_verified_copy, _copy_stops_verifying),
}


def _arrange(world, failure: str | None) -> None:
    """The check finds the failure's route; the failure happens as convert() starts."""
    if failure is None:
        launches._installation(world, _THROUGH_UV)
        return
    found, change = FAILURES[failure]
    launches._installation(world, found(world))
    converts = JupyterConverter.convert

    def change_then_convert(self):
        change(world)
        return converts(self)

    world.monkeypatch.setattr(JupyterConverter, "convert", change_then_convert)


def _run_the_phase(world) -> Tuple[AshAggregatedResults, MagicMock]:
    context = world.converter.context
    results = AshAggregatedResults(
        name="test", description="test", ash_config=context.config
    )
    progress = MagicMock()
    progress.add_task.return_value = 0
    phase = ConvertPhase(
        plugins=[JupyterConverter],
        plugin_context=context,
        progress_display=progress,
        asharp_model=results,
    )
    return phase.execute(aggregated_results=results), progress


def _exit_code(results, tmp_path) -> int:
    """The scan's exit code with one scanner that passed, so only conversion gates."""
    metric = MagicMock()
    metric.scanner_name = "bandit"
    metric.status = ScannerStatus.PASSED.value
    metric.actionable = 0
    metric.targets_attempted = 0
    metric.targets_failed = 0
    options = ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out-gate",
        fail_on_incomplete_scanners=True,
    )
    with patch(
        "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
        return_value=[metric],
    ):
        return _compute_exit_code(results, options)


@pytest.mark.parametrize("failure", sorted(FAILURES))
def test_the_converter_records_the_notebook_it_could_not_convert(world, failure):
    _arrange(world, failure)
    assert world.converter.validate_plugin_dependencies() is True

    converted = launches._convert(world)

    assert converted == []
    records = list(getattr(world.converter, "failed_inputs", None) or [])
    assert [record.path for record in records] == ["analysis.ipynb"], records
    assert records[0].reason.strip(), records


#: Where uv could not run nbconvert at all.
_UV_COULD_NOT_RUN = (
    "uv could not run nbconvert, and no other jupyter-nbconvert is run in its place"
)

#: failure -> the reason recorded, by what happened. A run nbconvert made under
#: uv is recorded as the direct route records it: nbconvert exited, or did not
#: finish. A run that raised is one uv could not make.
REASONS: Dict[str, str] = {
    "uv-exited-1": "nbconvert exited with code 1",
    "uv-timed-out": "nbconvert did not finish within 60s",
    "uv-runner-raised": _UV_COULD_NOT_RUN,
    "uv-did-not-start": _UV_COULD_NOT_RUN,
    "uv-failed-itself": _UV_COULD_NOT_RUN,
    "uv-no-exit-code": "nbconvert did not report an exit code",
    "direct-no-exit-code": "nbconvert did not report an exit code",
    "direct-could-not-start": (
        "nbconvert could not be started: No such file or directory"
    ),
    "uv-gone-at-conversion": _UV_COULD_NOT_RUN,
    "uv-exited-0-wrote-nothing": "nbconvert exited 0 but wrote no output",
    "verified-copy-stops-verifying": (
        "the jupyter-nbconvert the dependency check chose cannot be used now, and "
        "no other jupyter-nbconvert is run in its place"
    ),
}


def test_every_failure_has_its_reason():
    assert sorted(REASONS) == sorted(FAILURES)


def test_a_cancelled_scan_stops_the_conversion_and_records_nothing(world):
    """Cancellation is not a failed input. On the converter's route (run_tool
    without results_dir) the runner raises ScanCancelled, and it passes through
    to the scan's own stop handling: the notebook is not recorded as lost
    coverage, and nothing runs in uv's place."""
    from automated_security_helper.core.cancellation import ScanCancelled

    launches._installation(world, {"available": True, "preferred_source": "uv"})
    assert world.converter.validate_plugin_dependencies() is True

    def run_tool(
        tool_name: str, package_name: str, args: List[str], **kwargs: Any
    ) -> subprocess.CompletedProcess:
        world.uv.runs.append(["uv", "tool", "run", tool_name, *args])
        raise ScanCancelled("the server is stopping, so uv was stopped")

    world.uv.run_tool = run_tool

    with pytest.raises(ScanCancelled):
        world.converter.convert()

    assert list(getattr(world.converter, "failed_inputs", None) or []) == []
    assert len(world.uv.runs) == 1, world.uv.runs
    assert world.launches.argvs == []


def test_a_cancel_reported_as_a_response_stops_the_conversion(world):
    """A runner that reports the cancel in its response rather than raising it
    (a ``CancelledProcess``) stops the conversion the same way: the cancel is
    the scan's own stop, never a per-notebook failure, so nothing is recorded
    as lost coverage and the loop does not move to the next notebook."""
    from automated_security_helper.core.cancellation import ScanCancelled
    from automated_security_helper.utils.subprocess_utils import CancelledProcess

    launches._installation(world, _THROUGH_UV)
    assert world.converter.validate_plugin_dependencies() is True

    def run_tool(
        tool_name: str, package_name: str, args: List[str], **kwargs: Any
    ) -> subprocess.CompletedProcess:
        argv = ["uv", "tool", "run", "--from", str(package_name), tool_name, *args]
        world.uv.runs.append(argv)
        return CancelledProcess(argv, None, "", "", "the scan was cancelled")

    world.uv.run_tool = run_tool

    with pytest.raises(ScanCancelled):
        world.converter.convert()

    assert list(getattr(world.converter, "failed_inputs", None) or []) == []
    assert len(world.uv.runs) == 1, world.uv.runs
    assert world.launches.argvs == []


def test_a_kind_this_version_does_not_know_is_recorded_as_tool(world):
    """Recording a failure must not itself fail: a converter plugin outside
    this repository can pass its own kind, and the record is kept with kind
    "tool", which is never accepted, rather than refused after the failure was
    already logged (a refusal would abort convert() and lose every later
    input)."""
    launches._installation(world, _THROUGH_UV)
    assert world.converter.validate_plugin_dependencies() is True

    world.converter.record_failed_input(
        "analysis.ipynb", "its own reason", kind="parse"
    )
    world.converter.record_failed_input("later.ipynb", "a later failure")

    kinds = [record.kind for record in world.converter.failed_inputs]
    assert kinds == ["tool", "tool"], kinds


def test_a_failure_in_ashs_own_io_is_recorded_by_its_type(world):
    """An OSError in ASH's own work before nbconvert runs (a full disk at
    staging, say) is recorded by its type. "nbconvert could not be started"
    says the launch itself failed, and here nothing was launched: that reading
    would send whoever triages the record to the nbconvert installation when
    the disk is the problem."""
    launches._installation(world, _THROUGH_UV)
    assert world.converter.validate_plugin_dependencies() is True

    def no_space(*args: Any, **kwargs: Any):
        raise OSError(28, "No space left on device")

    world.monkeypatch.setattr(launches.MODULE.tempfile, "TemporaryDirectory", no_space)

    converted = launches._convert(world)

    assert converted == []
    (record,) = world.converter.failed_inputs
    assert record.reason == "conversion raised OSError", record.reason
    assert world.uv.runs == []


@pytest.mark.parametrize("failure", sorted(FAILURES))
def test_each_failure_is_recorded_with_its_reason_and_no_path(world, failure):
    """The record names the input; its reason says what happened, by kind, with
    no path: not the notebook's, so a results file does not carry the scanned
    tree's location twice, and not the copy's, a host path."""
    _arrange(world, failure)
    assert world.converter.validate_plugin_dependencies() is True

    launches._convert(world)

    (record,) = world.converter.failed_inputs
    assert record.reason == REASONS[failure], record.reason
    assert str(world.converter.context.source_dir) not in record.reason
    assert str(world.installed) not in record.reason
    assert "/" not in record.reason, record.reason


@pytest.mark.parametrize("failure", sorted(FAILURES))
def test_the_scan_reads_the_notebook_as_lost_coverage(world, failure, tmp_path):
    _arrange(world, failure)

    results, progress = _run_the_phase(world)

    ((name, row),) = results.converter_results.items()
    assert row.converted_paths == []
    assert [record.path for record in row.failed_inputs] == ["analysis.ipynb"]
    # The converter's progress row says what happened rather than what an empty
    # tree gets.
    rows = [
        call.kwargs.get("description", "")
        for call in progress.update_task.call_args_list
        if f"({name})" in call.kwargs.get("description", "")
    ]
    assert rows, progress.update_task.call_args_list
    last = rows[-1]
    assert "No files to convert" not in last, last
    assert "could not be converted" in last, last

    listed = incomplete_converters(results)
    assert [row[0] for row in listed] == [name], listed
    assert "analysis.ipynb" in listed[0][1], listed
    assert _exit_code(results, tmp_path) == 1


def test_a_partial_conversion_shows_both_counts_in_its_progress_row(world):
    """One notebook converts and one does not: the converter's progress row says
    both, rather than the all-converted or the nothing-to-convert text."""
    import json as _json

    source = world.converter.context.source_dir
    good = source / "analysis.ipynb"
    bad = source / "bad.ipynb"
    bad.write_text(_json.dumps(launches.NOTEBOOK), encoding="utf-8")
    world.monkeypatch.setattr(
        launches.MODULE, "scan_set", lambda **kwargs: [str(good), str(bad)]
    )
    launches._installation(world, _THROUGH_UV)

    def run_tool(
        tool_name: str, package_name: str, args: List[str], **kwargs: Any
    ) -> subprocess.CompletedProcess:
        argv = ["uv", "tool", "run", "--from", str(package_name), tool_name, *args]
        world.uv.runs.append(argv)
        # The staged copy carries a fixed name, so the failing run is the second
        # one: the scan set is [good, bad] and convert() keeps that order.
        if len(world.uv.runs) == 2:
            return subprocess.CompletedProcess(argv, 1, "", "")
        launches._write_output([str(a) for a in args])
        return subprocess.CompletedProcess(argv, 0, "", "")

    world.uv.run_tool = run_tool

    results, progress = _run_the_phase(world)

    ((name, row),) = results.converter_results.items()
    assert len(row.converted_paths) == 1
    assert [record.path for record in row.failed_inputs] == ["bad.ipynb"]
    rows = [
        call.kwargs.get("description", "")
        for call in progress.update_task.call_args_list
        if f"({name})" in call.kwargs.get("description", "")
    ]
    assert rows, progress.update_task.call_args_list
    last = rows[-1]
    assert "Converted 1 files, 1 file could not be converted" in last, last
    assert last.startswith("[yellow]"), last


def test_control_a_notebook_that_converts_records_nothing(world, tmp_path):
    _arrange(world, None)

    results, _progress = _run_the_phase(world)

    ((_name, row),) = results.converter_results.items()
    assert len(row.converted_paths) == 1, row
    assert list(getattr(row, "failed_inputs", None) or []) == []
    assert incomplete_converters(results) == []
    assert _exit_code(results, tmp_path) == 0
