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
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.execution_engine import ScanExecutionEngine

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
