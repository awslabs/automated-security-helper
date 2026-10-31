# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancel at the results-file write puts the previous results back.

Why these tests exist
---------------------
With ``keep_previous_results`` the previous scan's results are set aside while a
scan runs. ``execute_scan`` puts them back when the phases fail or are cancelled,
and drops them when the scan has its own results and ``settle_on_success`` is
True. The results-file write sits outside the arm that puts them back, so that a
caller that settles them itself (``settle_on_success=False``) finds them held.
A caller that asked the orchestrator to settle (the default) has nothing later
that does, and a cancel read at the write left its previous results in the held
directory with no results file beside them.

The engine is a stub and the cancel is injected at the two reads inside
``_write_results_file``.

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


def _orchestrator_with_previous_results(tmp_path, monkeypatch) -> ASHScanOrchestrator:
    source = tmp_path / "proj"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    (output / RESULTS_NAME).write_text("previous results", encoding="utf-8")
    orchestrator = ASHScanOrchestrator(
        source_dir=source, output_dir=output, keep_previous_results=True
    )
    orchestrator.config = AshConfig()
    engine = MagicMock()
    engine.execute_phases.return_value = AshAggregatedResults()
    orchestrator.execution_engine = engine
    monkeypatch.setattr(orchestrator_module, "scan_set", lambda **_kw: [])
    orchestrator._set_previous_results_aside()
    assert (output / HELD_DIR_NAME / RESULTS_NAME).is_file()
    return orchestrator


def _cancel_at_the_write(monkeypatch, which_read: int) -> None:
    """Make the *which_read*-th cancellation read inside the write raise.

    1 is the read before the file is written, 2 the read after.
    """
    real = ASHScanOrchestrator._write_results_file
    reads: list[int] = []

    def read() -> None:
        reads.append(1)
        if len(reads) == which_read:
            raise ScanCancelled("cancelled for the test")

    def write(self, phases, results):
        monkeypatch.setattr(orchestrator_module, "raise_if_cancelled", read)
        return real(self, phases, results)

    monkeypatch.setattr(ASHScanOrchestrator, "_write_results_file", write)


@pytest.mark.parametrize("which_read", [1, 2], ids=["before-the-write", "after-it"])
def test_a_cancel_at_the_write_puts_the_previous_results_back(
    tmp_path, monkeypatch, which_read
):
    orchestrator = _orchestrator_with_previous_results(tmp_path, monkeypatch)
    output = Path(orchestrator.output_dir)
    _cancel_at_the_write(monkeypatch, which_read)

    with pytest.raises(ScanCancelled):
        orchestrator.execute_scan(phases=["scan"])

    # Red at the base: the previous results stayed in the held directory and
    # the top level held no results at all.
    assert (output / RESULTS_NAME).read_text(encoding="utf-8") == "previous results"
    assert not (output / HELD_DIR_NAME).exists()


def test_with_settle_on_success_false_the_caller_still_finds_them_held(
    tmp_path, monkeypatch
):
    """The control: the caller that settles them itself is not pre-empted."""
    orchestrator = _orchestrator_with_previous_results(tmp_path, monkeypatch)
    output = Path(orchestrator.output_dir)
    _cancel_at_the_write(monkeypatch, 1)

    with pytest.raises(ScanCancelled):
        orchestrator.execute_scan(phases=["scan"], settle_on_success=False)

    assert (output / HELD_DIR_NAME / RESULTS_NAME).read_text(
        encoding="utf-8"
    ) == "previous results"
    assert not (output / RESULTS_NAME).exists()
