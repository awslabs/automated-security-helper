# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run under ``--ignore-suppressions`` records that fact in the results' metadata.

Why this exists
---------------
The unused-suppressions reporter reads ``metadata.suppressions_ignored`` beside its
own context's flag, so a results file re-rendered later by ``ash report`` (whose
context carries no flag) still says the suppressions were not evaluated instead of
listing every entry as unused. Nothing wrote that field: the engine applied the
flag in every phase and recorded it nowhere. The engine now records it on the
results before the phases run, so a run that stops at the scan phase carries it
too. The control is a run without the flag, which records nothing.

The scan phase is a stand-in that returns the results unchanged; no scanner runs.

The reporter reads the field off a results FILE a later ``ash report`` loaded, so
the in-memory record is not the whole claim: the field has to survive
``save_model`` and ``AshAggregatedResults.from_json``. ``ReportMetadata`` keeps
unknown keys (``extra="allow"``) and ``save_model`` dumps the whole model, so the
round trip is expected to hold; the two round-trip tests pin that it does, and
their control pins that a normal run's file carries no such key.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


class _ScanPhaseThatRunsNothing:
    def __init__(self, **kwargs):
        self._completed_scanners = []
        self._shard_assignment = None

    def execute(self, aggregated_results=None, **kwargs):
        return aggregated_results


def _scan_only(tmp_path: Path, monkeypatch, ignore_suppressions: bool):
    monkeypatch.setattr(
        "automated_security_helper.core.execution_engine.ScanPhase",
        _ScanPhaseThatRunsNothing,
    )
    source = tmp_path / "src"
    source.mkdir()
    engine = ScanExecutionEngine(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            config=get_default_config(),
            ignore_suppressions=ignore_suppressions,
        ),
        show_progress=False,
        show_summary=False,
    )
    return engine.execute_phases(phases=["scan"])


def test_an_ignored_run_records_the_flag_on_the_results(tmp_path, monkeypatch):
    results = _scan_only(tmp_path, monkeypatch, ignore_suppressions=True)

    assert results.metadata.suppressions_ignored is True
    dumped = results.model_dump(mode="json")
    assert dumped["metadata"]["suppressions_ignored"] is True, sorted(
        dumped["metadata"]
    )


def test_a_normal_run_records_nothing(tmp_path, monkeypatch):
    """Control: without the flag the field is absent, so a later report run reads
    its own context."""
    results = _scan_only(tmp_path, monkeypatch, ignore_suppressions=False)

    assert getattr(results.metadata, "suppressions_ignored", None) is None
    assert "suppressions_ignored" not in results.model_dump(mode="json")["metadata"]


def _saved_and_reloaded(results, saved_dir: Path):
    """The results written by ``save_model`` and read back the way ``ash report``
    reads a results file: ``(the file's parsed JSON, the reloaded model)``."""
    saved_dir.mkdir(parents=True, exist_ok=True)
    results.save_model(saved_dir)
    text = (saved_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
    return json.loads(text), AshAggregatedResults.from_json(text)


def test_the_flag_survives_the_saved_results_file(tmp_path, monkeypatch):
    """What a later ``ash report`` run reads is the file, not this run's model."""
    results = _scan_only(tmp_path, monkeypatch, ignore_suppressions=True)

    on_disk, reloaded = _saved_and_reloaded(results, tmp_path / "saved")

    assert on_disk["metadata"]["suppressions_ignored"] is True, sorted(
        on_disk["metadata"]
    )
    # The reporter's own read of a reloaded model (unused_suppressions_reporter).
    assert getattr(reloaded.metadata, "suppressions_ignored", None) is True


def test_a_normal_runs_saved_file_carries_no_flag(tmp_path, monkeypatch):
    """Control for the round trip: the key is absent on disk and after reload."""
    results = _scan_only(tmp_path, monkeypatch, ignore_suppressions=False)

    on_disk, reloaded = _saved_and_reloaded(results, tmp_path / "saved")

    assert "suppressions_ignored" not in on_disk["metadata"]
    assert getattr(reloaded.metadata, "suppressions_ignored", None) is None
