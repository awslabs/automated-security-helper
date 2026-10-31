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
from the phase's own record, the marker it appends once its last step has
returned. A cancel is not an Exception and still writes nothing.

The engine here is a stub shaped like the real one: it holds ``_asharp_model``
from construction (the same object the phases mutate) and its ``execute_phases``
mutates that model the way the phases do before it raises.

The model read is the engine's ``_results`` first, ``_asharp_model`` second. The
real engine hands ``_results`` from phase to phase and the scan phase may return
a new object; ``_asharp_model`` is synced to it only in the changed-files
narrowing, at the end of the final suppression pass and after the report phase.
A failure between the scan phase's end and that sync (a suppression or metrics
step at the start of the report arm) left ``_asharp_model`` as the model the
engine started with, which carries no completion checkpoint, so the scan's
results were not written although the scan phase had run to its end. A second
stub below replaces ``_results`` the way such a scan phase does.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core import orchestrator as orchestrator_module
from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.exceptions import ASHValidationError
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


class _ReplacingEngineStub:
    """Hands a NEW model along as ``_results``, as a scan phase that returns one.

    ``_asharp_model`` stays the model the engine was constructed with (no
    completion checkpoint), as the real engine's does until its later sync;
    ``_results`` is the model the scan phase finished, and the failure lands
    before the sync.
    """

    def __init__(self, raised, results=...):
        self._asharp_model = AshAggregatedResults()
        self._results = self._asharp_model
        self._raised = raised
        self._replacement = results

    def execute_phases(self, phases):
        if self._replacement is ...:
            finished = AshAggregatedResults()
            finished.metadata.project_name = "finished-by-the-scan-phase"
            _scan_phase_ran_to_its_end(finished)
            self._results = finished
        else:
            self._results = self._replacement
        raise self._raised


def _scan_phase_ran_to_its_end(model: AshAggregatedResults) -> None:
    # The scan phase appends this marker once its last step has returned.
    model.validation_checkpoints.append(_checkpoint(SCAN_PHASE_COMPLETION_CHECKPOINT))


def _scan_phase_raised_midway(model: AshAggregatedResults) -> None:
    # A mid-phase checkpoint is on the model; the completion marker never came.
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

    # _execute_scan wraps a phase's exception as ASHValidationError("Scan
    # execution failed: ..."); the orchestrator's own callers read that type.
    with pytest.raises(ASHValidationError, match="reporter raised"):
        orchestrator._execute_scan(phases=["scan", "report"])

    # Red with the single write after the try/except: the re-raise skipped it.
    assert (orchestrator.output_dir / RESULTS_FILE).is_file()


def test_a_convert_phase_failure_writes_no_results_file(tmp_path, monkeypatch):
    orchestrator = _orchestrator(
        tmp_path, monkeypatch, _nothing_ran, RuntimeError("converter raised")
    )

    with pytest.raises(ASHValidationError, match="converter raised"):
        orchestrator._execute_scan(phases=["convert", "scan", "report"])

    # Red at the previous tip: the engine's pre-scan, empty model was written.
    assert not (orchestrator.output_dir / RESULTS_FILE).exists()


def test_a_scan_phase_that_raised_midway_writes_no_results_file(tmp_path, monkeypatch):
    orchestrator = _orchestrator(
        tmp_path, monkeypatch, _scan_phase_raised_midway, RuntimeError("scanner raised")
    )

    with pytest.raises(ASHValidationError, match="scanner raised"):
        orchestrator._execute_scan(phases=["scan", "report"])

    # Red at the previous tip: the partial model was written.
    assert not (orchestrator.output_dir / RESULTS_FILE).exists()


def test_the_model_the_scan_phase_handed_along_is_the_one_written(
    tmp_path, monkeypatch
):
    """A failure before the engine syncs ``_asharp_model`` to ``_results``."""
    orchestrator = _orchestrator(
        tmp_path, monkeypatch, _nothing_ran, RuntimeError("suppressions raised")
    )
    orchestrator.execution_engine = _ReplacingEngineStub(
        RuntimeError("suppressions raised")
    )

    with pytest.raises(ASHValidationError, match="suppressions raised"):
        orchestrator._execute_scan(phases=["scan", "report"])

    # Red at the previous tip: only _asharp_model was read, it carried no
    # completion checkpoint, and nothing was written.
    written = orchestrator.output_dir / RESULTS_FILE
    assert written.is_file()
    # The file holds the model the scan phase finished, not the engine's
    # construction-time one.
    text = written.read_text(encoding="utf-8")
    assert "finished-by-the-scan-phase" in text
    assert SCAN_PHASE_COMPLETION_CHECKPOINT in text


def test_an_engine_whose_results_are_not_a_model_falls_back_to_its_held_model(
    tmp_path, monkeypatch
):
    """The control for the fallback: ``_results`` that is not a model (None, a
    stub's attribute) is passed over for ``_asharp_model``, as every stub above
    is read."""
    orchestrator = _orchestrator(
        tmp_path, monkeypatch, _nothing_ran, RuntimeError("reporter raised")
    )
    engine = _ReplacingEngineStub(RuntimeError("reporter raised"), results=None)
    _scan_phase_ran_to_its_end(engine._asharp_model)
    orchestrator.execution_engine = engine

    with pytest.raises(ASHValidationError, match="reporter raised"):
        orchestrator._execute_scan(phases=["scan", "report"])

    assert (orchestrator.output_dir / RESULTS_FILE).is_file()


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

    with pytest.raises(ASHValidationError, match="reporter raised"):
        orchestrator._execute_scan(phases=["report"])

    assert not (orchestrator.output_dir / RESULTS_FILE).exists()


def test_a_report_over_loaded_results_leaves_the_saved_file_on_failure(
    tmp_path, monkeypatch
):
    """The --use-existing case: a report over a saved results file that fails
    writes nothing, and the saved file, the user's own results, is unchanged.

    The loaded model carries the earlier scan's completion checkpoint, so the
    write-after-failure would see a finished scan; what keeps it from writing is
    that a run over existing results does not own the results file.
    """
    saved_model = AshAggregatedResults()
    _scan_phase_ran_to_its_end(saved_model)
    saved = tmp_path / "saved-results.json"
    saved.write_text(saved_model.model_dump_json(by_alias=True), encoding="utf-8")
    saved_bytes = saved.read_bytes()
    # The saved model holds no scanner results, which --use-existing refuses as
    # "no scan"; that refusal is another test's, so it is stood down here.
    monkeypatch.setattr(
        orchestrator_module, "existing_results_problem", lambda results: None
    )

    orchestrator = _orchestrator(
        tmp_path,
        monkeypatch,
        _scan_phase_ran_to_its_end,
        RuntimeError("reporter raised"),
    )
    orchestrator.existing_results_path = saved

    with pytest.raises(ASHValidationError, match="reporter raised"):
        orchestrator._execute_scan(phases=["report"])

    assert not (orchestrator.output_dir / RESULTS_FILE).exists()
    assert saved.read_bytes() == saved_bytes


def test_a_report_over_results_at_the_default_location_leaves_them_unchanged(
    tmp_path, monkeypatch
):
    """The same case with the saved results where ``--use-existing`` reads them by
    default, the results file of the output directory: the very file a write after
    the failure would overwrite, so the assertion is on its bytes, not on a path
    that must not exist."""
    monkeypatch.setattr(
        orchestrator_module, "existing_results_problem", lambda results: None
    )
    orchestrator = _orchestrator(
        tmp_path,
        monkeypatch,
        _scan_phase_ran_to_its_end,
        RuntimeError("reporter raised"),
    )
    saved_model = AshAggregatedResults()
    _scan_phase_ran_to_its_end(saved_model)
    saved = orchestrator.output_dir / RESULTS_FILE
    saved.write_text(saved_model.model_dump_json(by_alias=True), encoding="utf-8")
    saved_bytes = saved.read_bytes()
    orchestrator.existing_results_path = saved

    with pytest.raises(ASHValidationError, match="reporter raised"):
        orchestrator._execute_scan(phases=["report"])

    assert saved.read_bytes() == saved_bytes


def test_the_completion_marker_is_not_the_completeness_checkpoint():
    """The fact the orchestrator reads is the one the scan phase's last step writes.

    That record is a marker of the phase's own, written once its last step has
    returned. The completeness checkpoint the real manager returns is NOT it:
    that checkpoint is appended inside the completeness pass's
    try, which swallows the pass's errors, so its presence says the pass
    finished, not that the phase did. A model that holds every validation
    checkpoint but the marker reads as not completed; the marker alone reads as
    completed.
    """
    manager = ScannerValidationManager(plugin_context=MagicMock())
    checkpoint = manager.ensure_complete_results(AshAggregatedResults())
    assert checkpoint.checkpoint_name == "result_completeness"
    assert checkpoint.checkpoint_name != SCAN_PHASE_COMPLETION_CHECKPOINT

    model = AshAggregatedResults()
    assert scan_phase_completed(model) is False
    model.validation_checkpoints.append(_checkpoint("task_queue_validation"))
    model.validation_checkpoints.append(_checkpoint(checkpoint.checkpoint_name))
    assert scan_phase_completed(model) is False
    model.validation_checkpoints.append(_checkpoint(SCAN_PHASE_COMPLETION_CHECKPOINT))
    assert scan_phase_completed(model) is True
