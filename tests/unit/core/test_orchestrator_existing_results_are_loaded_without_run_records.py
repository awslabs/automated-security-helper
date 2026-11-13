# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The model built for a report over existing results holds no earlier run's records.

Why these tests exist
---------------------
The report phase reads a "reports written" record on the results as the record of
this process's own earlier report phase, and counts the files it names as written
by this run. That holds because every model loaded from a file has had the run
records an earlier run left about itself removed (``without_run_records``). The
reload in ``_execute_scan`` removes them; ``_build_engine``, which loads the same
file first and hands the model to the engine, did not. The model is replaced by
the reload before a phase runs, so no run reached the gap, but the guarantee the
report phase relies on was kept at one site and not the other. Both now remove
them.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.inner_run_outcome import (
    REPORTS_WRITTEN_CHECKPOINT,
)

pytestmark = pytest.mark.unit

KEPT = {"type": "scanner_check", "metadata": {"note": "not a run record"}}
RECORD = {
    "type": REPORTS_WRITTEN_CHECKPOINT,
    "metadata": {"formats": {"ash.sarif": "sarif"}},
}


def _engine_model(tmp_path, checkpoints):
    source = tmp_path / "proj"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    saved = AshAggregatedResults()
    saved.validation_checkpoints = list(checkpoints)
    existing = tmp_path / "existing.json"
    existing.write_text(saved.model_dump_json(), encoding="utf-8")
    orchestrator = ASHScanOrchestrator(
        source_dir=source, output_dir=output, existing_results_path=existing
    )

    orchestrator._build_engine(AshConfig())

    return orchestrator.execution_engine._asharp_model


def test_a_reports_written_record_is_not_carried_into_the_engine(tmp_path):
    model = _engine_model(tmp_path, [RECORD, KEPT])

    types = [item.get("type") for item in model.validation_checkpoints]
    # Red at the base: the earlier run's record was on the model.
    assert REPORTS_WRITTEN_CHECKPOINT not in types


def test_the_other_checkpoints_are_kept(tmp_path):
    """The control: only the run records are removed."""
    model = _engine_model(tmp_path, [RECORD, KEPT])

    types = [item.get("type") for item in model.validation_checkpoints]
    assert "scanner_check" in types
