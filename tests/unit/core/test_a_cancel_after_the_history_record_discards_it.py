# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancel that escapes the results write after the history record discards it.

Why these tests exist
---------------------
``_write_results_file`` reads the cancel once more after the file is written and
appends the run's history record only when that read passes. A cancel that lands
after the record is appended and before ``execute_scan`` returns (an interrupt in
the write step's tail, or a check added after the record later) left the record
in ``history/`` with no caller able to remove it: the caller's ``results`` name
is never bound when ``execute_scan`` raises, so ``ash trend`` showed the
taken-back run as a completed one. ``execute_scan``'s arm around the write now
discards what ``_record_history`` recorded before it re-raises.

The engine is a stub and the cancel is injected right after the real write step
ran, standing for an exception raised in that window.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core import orchestrator as orchestrator_module
from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.core.previous_results import HELD_DIR_NAME
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

RESULTS_NAME = "ash_aggregated_results.json"


def _orchestrator_recording_history(tmp_path, monkeypatch) -> ASHScanOrchestrator:
    source = tmp_path / "proj"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    (output / RESULTS_NAME).write_text("previous results", encoding="utf-8")
    orchestrator = ASHScanOrchestrator(
        source_dir=source, output_dir=output, keep_previous_results=True
    )
    orchestrator.config = AshConfig.model_validate(
        {"global_settings": {"history": {"enabled": True}}}
    )
    engine = MagicMock()
    engine.execute_phases.return_value = AshAggregatedResults()
    orchestrator.execution_engine = engine
    monkeypatch.setattr(orchestrator_module, "scan_set", lambda **_kw: [])
    orchestrator._set_previous_results_aside()
    assert (output / HELD_DIR_NAME / RESULTS_NAME).is_file()
    return orchestrator


def _cancel_right_after_the_write_step(monkeypatch) -> None:
    """Raise the cancel once the real write step, record included, has run."""
    real = ASHScanOrchestrator._write_results_file

    def write(self, phases, results):
        real(self, phases, results)
        raise ScanCancelled("cancelled after the record, for the test")

    monkeypatch.setattr(ASHScanOrchestrator, "_write_results_file", write)


def _record_names(output: Path) -> list[str]:
    history = output / "history"
    if not history.is_dir():
        return []
    return sorted(p.name for p in history.iterdir())


def test_a_cancel_after_the_record_discards_it(tmp_path, monkeypatch) -> None:
    orchestrator = _orchestrator_recording_history(tmp_path, monkeypatch)
    output = Path(orchestrator.output_dir)
    _cancel_right_after_the_write_step(monkeypatch)

    with pytest.raises(ScanCancelled):
        orchestrator.execute_scan(phases=["scan"])

    # Red at the base: the record of the taken-back run stayed in history/,
    # so ``ash trend`` showed the cancelled run as a completed one.
    assert _record_names(output) == []
    # The previous results were put back, as for any cancel at the write.
    assert (output / RESULTS_NAME).read_text(encoding="utf-8") == "previous results"
    assert not (output / HELD_DIR_NAME).exists()


def test_a_scan_that_finished_keeps_its_record(tmp_path, monkeypatch) -> None:
    """The control: a run no cancel took back stays a point in the history."""
    orchestrator = _orchestrator_recording_history(tmp_path, monkeypatch)
    output = Path(orchestrator.output_dir)

    results = orchestrator.execute_scan(phases=["scan"])

    assert _record_names(output) == [f"{results.metadata.report_id}.json"]
    assert not (output / HELD_DIR_NAME).exists()
