# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A phase that raises AFTER the scan still leaves the scan's results file.

The scan phase used to write ``ash_aggregated_results.json`` at its own end, so
a report phase that raised still left the scan's results for a later
``--use-existing``. The one write moved to the orchestrator, after every phase,
which would have left no file at all on such a failure. The orchestrator now
writes what the engine holds before the failure is re-raised, but only when the
scan phase ran to its end: the engine holds its model from construction, so a
failure in the convert phase, or a scan phase that raised midway, must write
nothing (as the base did), not an empty or partial file the MCP progress
tracker would read as a complete scan. Whether the scan phase completed is read
from the phase's own record, the completeness checkpoint it appends as its last
validation step. A cancel is not an Exception and still writes nothing.

The engine here is a stub shaped like the real one: it holds ``_asharp_model``
from construction (the same object the phases mutate) and its ``execute_phases``
mutates that model the way the phases do before it raises.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core import orchestrator as orchestrator_module
from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.core.phases.scan_phase import (
    SCAN_PHASE_COMPLETION_CHECKPOINT,
    scan_phase_completed,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
)

pytestmark = pytest.mark.unit

RESULTS_FILE = "ash_aggregated_results.json"


def _checkpoint(name: str) -> dict:
    return {
        "checkpoint_name": name,
        "timestamp": "2024-01-01T00:00:00",
        "expected_scanners": [],
        "actual_scanners": [],
        "discrepancies": [],
        "errors": [],
        "metadata": {},
    }


class _EngineStub:
    """Holds its model from construction and mutates it as the phases do."""

    def __init__(self, before_raising, raised):
        self._asharp_model = AshAggregatedResults()
        self._before_raising = before_raising
        self._raised = raised

    def execute_phases(self, phases):
        self._before_raising(self._asharp_model)
        raise self._raised


def _scan_phase_ran_to_its_end(model: AshAggregatedResults) -> None:
    # The scan phase's last validation step appends this checkpoint.
    model.validation_checkpoints.append(_checkpoint(SCAN_PHASE_COMPLETION_CHECKPOINT))


def _scan_phase_raised_midway(model: AshAggregatedResults) -> None:
    # A mid-phase checkpoint is on the model; the completeness one never came.
    model.validation_checkpoints.append(_checkpoint("task_queue_validation"))


def _nothing_ran(model: AshAggregatedResults) -> None:
    pass


def _orchestrator(tmp_path: Path, monkeypatch, before_raising, raised):
    source = tmp_path / "proj"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
    orchestrator.config = AshConfig()
    orchestrator.execution_engine = _EngineStub(before_raising, raised)
    monkeypatch.setattr(orchestrator_module, "scan_set", lambda **_kw: [])
    return orchestrator


def test_a_report_phase_failure_leaves_the_scan_results_file(tmp_path, monkeypatch):
    orchestrator = _orchestrator(
        tmp_path,
        monkeypatch,
        _scan_phase_ran_to_its_end,
        RuntimeError("reporter raised"),
    )

    with pytest.raises(RuntimeError, match="reporter raised"):
        orchestrator._execute_scan(phases=["scan", "report"])

    # Red with the single write after the try/except: the re-raise skipped it.
    assert (orchestrator.output_dir / RESULTS_FILE).is_file()


def test_a_convert_phase_failure_writes_no_results_file(tmp_path, monkeypatch):
    orchestrator = _orchestrator(
        tmp_path, monkeypatch, _nothing_ran, RuntimeError("converter raised")
    )

    with pytest.raises(RuntimeError, match="converter raised"):
        orchestrator._execute_scan(phases=["convert", "scan", "report"])

    # Red at the previous tip: the engine's pre-scan, empty model was written.
    assert not (orchestrator.output_dir / RESULTS_FILE).exists()


def test_a_scan_phase_that_raised_midway_writes_no_results_file(tmp_path, monkeypatch):
    orchestrator = _orchestrator(
        tmp_path, monkeypatch, _scan_phase_raised_midway, RuntimeError("scanner raised")
    )

    with pytest.raises(RuntimeError, match="scanner raised"):
        orchestrator._execute_scan(phases=["scan", "report"])

    # Red at the previous tip: the partial model was written.
    assert not (orchestrator.output_dir / RESULTS_FILE).exists()


def test_a_cancel_still_writes_no_results_file(tmp_path, monkeypatch):
    """The control: a cancel is not an Exception and leaves nothing behind."""
    orchestrator = _orchestrator(
        tmp_path, monkeypatch, _scan_phase_ran_to_its_end, ScanCancelled("cancelled")
    )

    with pytest.raises(ScanCancelled):
        orchestrator._execute_scan(phases=["scan", "report"])

    assert not (orchestrator.output_dir / RESULTS_FILE).exists()


def test_a_report_over_existing_results_writes_nothing_on_failure(
    tmp_path, monkeypatch
):
    """The other control: a run that does not own the file never writes it."""
    orchestrator = _orchestrator(
        tmp_path,
        monkeypatch,
        _scan_phase_ran_to_its_end,
        RuntimeError("reporter raised"),
    )

    with pytest.raises(RuntimeError):
        orchestrator._execute_scan(phases=["report"])

    assert not (orchestrator.output_dir / RESULTS_FILE).exists()


def test_the_completion_record_is_the_checkpoint_the_validation_manager_names():
    """The fact the orchestrator reads is the one the scan phase's last step writes."""
    source = inspect.getsource(ScannerValidationManager.ensure_complete_results)
    assert f'checkpoint_name="{SCAN_PHASE_COMPLETION_CHECKPOINT}"' in source

    model = AshAggregatedResults()
    assert scan_phase_completed(model) is False
    model.validation_checkpoints.append(_checkpoint("task_queue_validation"))
    assert scan_phase_completed(model) is False
    model.validation_checkpoints.append(_checkpoint(SCAN_PHASE_COMPLETION_CHECKPOINT))
    assert scan_phase_completed(model) is True
