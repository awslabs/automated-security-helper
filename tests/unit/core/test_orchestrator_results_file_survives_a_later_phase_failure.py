# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A phase that raises after the scan still leaves the scan's results file.

The scan phase used to write ``ash_aggregated_results.json`` at its own end, so
a report phase that raised still left the scan's results for a later
``--use-existing``. The one write moved to the orchestrator, after every phase,
which would have left no file at all on such a failure. The orchestrator now
writes what the engine holds before the failure is re-raised. A cancel is not
an Exception and still writes nothing.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core import orchestrator as orchestrator_module
from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

RESULTS_FILE = "ash_aggregated_results.json"


def _orchestrator_whose_engine_raises(tmp_path: Path, monkeypatch, raised):
    source = tmp_path / "proj"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
    orchestrator.config = AshConfig()
    engine = MagicMock()
    engine._asharp_model = AshAggregatedResults()
    engine.execute_phases.side_effect = raised
    orchestrator.execution_engine = engine
    monkeypatch.setattr(orchestrator_module, "scan_set", lambda **_kw: [])
    return orchestrator


def test_a_report_phase_failure_leaves_the_scan_results_file(tmp_path, monkeypatch):
    orchestrator = _orchestrator_whose_engine_raises(
        tmp_path, monkeypatch, RuntimeError("reporter raised")
    )

    with pytest.raises(RuntimeError, match="reporter raised"):
        orchestrator._execute_scan(phases=["scan", "report"])

    # Red at the previous tip: the write sat after the try/except, so the
    # re-raise skipped it and nothing was on disk.
    assert (orchestrator.output_dir / RESULTS_FILE).is_file()


def test_a_cancel_still_writes_no_results_file(tmp_path, monkeypatch):
    """The control: a cancel is not an Exception and leaves nothing behind."""
    orchestrator = _orchestrator_whose_engine_raises(
        tmp_path, monkeypatch, ScanCancelled("cancelled")
    )

    with pytest.raises(ScanCancelled):
        orchestrator._execute_scan(phases=["scan", "report"])

    assert not (orchestrator.output_dir / RESULTS_FILE).exists()


def test_a_report_over_existing_results_writes_nothing_on_failure(
    tmp_path, monkeypatch
):
    """The other control: a run that does not own the file never writes it."""
    orchestrator = _orchestrator_whose_engine_raises(
        tmp_path, monkeypatch, RuntimeError("reporter raised")
    )

    with pytest.raises(RuntimeError):
        orchestrator._execute_scan(phases=["report"])

    assert not (orchestrator.output_dir / RESULTS_FILE).exists()
