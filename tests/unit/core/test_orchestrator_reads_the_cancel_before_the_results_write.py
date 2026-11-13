# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancel that lands between the last phase and the results write leaves no file.

The engine checks the cancel only before each phase, and its finally block runs
the completion handlers and the metrics rebuild after the report phase, so a
cancel can land once every phase is done and before ``execute_scan`` writes
``ash_aggregated_results.json``. The write is preceded by a cancel read (and
followed by one that removes a file written across a cancel), so such a scan
ends as ScanCancelled with no results file, which is what the CLI's and the MCP
runner's "ended without results" reading expects. The scan-phase check that
guarded the old write site went with the move of the write; this pins the read
that replaced it.

The engine here is a stub shaped like the real one: it holds its model from
construction, finishes the scan phase (the completeness checkpoint) and sets the
cancel event before it returns normally.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core import orchestrator as orchestrator_module
from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
)
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.core.phases.scan_phase import (
    SCAN_PHASE_COMPLETION_CHECKPOINT,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

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


class _FinishingEngine:
    """Finishes the scan phase, sets the cancel, returns its model as the engine does."""

    def __init__(self, event: CancelEvent):
        self._asharp_model = AshAggregatedResults()
        self._event = event

    def execute_phases(self, phases):
        self._asharp_model.validation_checkpoints.append(
            _checkpoint(SCAN_PHASE_COMPLETION_CHECKPOINT)
        )
        self._event.set()
        return self._asharp_model


def test_a_cancel_set_after_the_last_phase_writes_no_results_file(
    tmp_path, monkeypatch
):
    source = tmp_path / "proj"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    event = CancelEvent()
    orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
    orchestrator.config = AshConfig()
    orchestrator.execution_engine = _FinishingEngine(event)
    monkeypatch.setattr(orchestrator_module, "scan_set", lambda **_kw: [])

    with cancel_scope(event):
        with pytest.raises(ScanCancelled):
            orchestrator.execute_scan(phases=["scan", "report"])

    # The read before the write: no file, and the scan ended as cancelled.
    assert not (output / RESULTS_FILE).exists()


def test_the_control_writes_the_file_when_no_cancel_lands(tmp_path, monkeypatch):
    source = tmp_path / "proj"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    event = CancelEvent()
    orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
    orchestrator.config = AshConfig()
    engine = _FinishingEngine(event)
    engine._event = CancelEvent()  # set on an event no scope reads
    orchestrator.execution_engine = engine
    monkeypatch.setattr(orchestrator_module, "scan_set", lambda **_kw: [])

    with cancel_scope(event):
        orchestrator.execute_scan(phases=["scan", "report"])

    assert (output / RESULTS_FILE).is_file()
