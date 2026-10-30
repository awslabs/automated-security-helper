# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The engine's construction-time selection refusal defers what only ScanPhase can judge.

``ensure_initialized`` refuses a ``--scanners`` allowlist that matches no
registered scanner, before any directory is cleared. It compares the names the
scanner classes declare. Two shapes used to be refused there wrongly. A scanner
class that declares no name (the documented unparametrized plugin pattern) has
its selectable name only as ``config.name`` on an instance the phase constructs,
so the engine keyed it by its lowercased class name and refused the configured
name the phase accepts, making the scanner unselectable. And a request naming a
community scanner whose module this run did not load was refused as a spelling
error; it is still refused here, before anything is cleared, but with the one
text the phase also raises (core.scanner_selection.community_scanner_refusal),
which names the module to add and any misspelled name beside it, and only when
some scanner class is in scope to judge the names against.

The last test pins the other engine-level fix in this file's subject: a report
over existing results keeps the stored scan's timing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

_ENGINE_MODULE = "automated_security_helper.core.execution_engine"


class _NameField:
    default = "bandit"


class _NamedConfig:
    model_fields = {"name": _NameField()}


class _ConfigField:
    annotation = _NamedConfig


class _NamedScanner:
    """Declares its name the way a scanner's own config class does."""

    model_fields = {"config": _ConfigField()}


class _UnnamedScanner:
    """Declares no name: its selectable name is config.name on an instance."""

    model_fields: dict = {}


def _engine(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    context = PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="selection-defers"),
    )
    with patch("automated_security_helper.plugins.loader.load_internal_plugins"):
        engine = ScanExecutionEngine(
            context=context,
            show_progress=False,
            show_summary=False,
            asharp_model=AshAggregatedResults(),
        )
    engine.progress_display = MagicMock()
    engine.progress_display.live = None
    return engine


def _reinitialize(engine, requested, scanner_classes):
    engine.plugins["scanner"] = list(scanner_classes)
    engine._init_enabled_scanners = list(requested)
    engine._initialized = False
    engine.ensure_initialized()


def test_an_unnamed_scanner_in_scope_defers_the_refusal_to_the_phase(tmp_path):
    """Red before the fix: refused as matching no scanner."""
    engine = _engine(tmp_path)

    _reinitialize(engine, ["custom-name"], [_NamedScanner, _UnnamedScanner])

    assert engine._initialized is True


def test_a_community_scanner_whose_module_is_not_loaded_is_refused_naming_the_module(
    tmp_path,
):
    """Red before the fix: refused as a spelling error, with no module hint
    (and, for one cut, not refused at all until the phase)."""
    engine = _engine(tmp_path)

    with pytest.raises(ScannerSelectionError, match="ash_snyk_plugins") as refused:
        _reinitialize(engine, ["snyk-code"], [_NamedScanner])

    assert "community scanner" in str(refused.value)
    assert "--ash-plugin-modules" in str(refused.value)


def test_a_misspelled_name_is_named_beside_the_unloaded_community_scanner(
    tmp_path,
):
    """Red before the fix: the refusal named the community scanner only, so the
    operator added the module and was refused again for the misspelling."""
    engine = _engine(tmp_path)

    with pytest.raises(ScannerSelectionError) as refused:
        _reinitialize(engine, ["snyk-code", "bandt"], [_NamedScanner])

    text = str(refused.value)
    assert "ash_snyk_plugins" in text
    assert "bandt" in text
    assert "check the spelling" in text


def test_no_registered_scanner_defers_every_refusal_to_the_phase(tmp_path):
    """Red before the fix: with no scanner class in scope the community hint
    ran on an empty declared set and refused the request, where the phase and
    refuse_selection_matching_no_scanner skip a registry with nothing in it."""
    engine = _engine(tmp_path)

    _reinitialize(engine, ["snyk-code"], [])

    assert engine._initialized is True


def test_a_declared_name_beside_an_unloaded_community_scanner_is_not_refused(
    tmp_path,
):
    """Control: the request resolves to something; the phase warns about the rest."""
    engine = _engine(tmp_path)

    _reinitialize(engine, ["bandit", "snyk-code"], [_NamedScanner])

    assert engine._initialized is True


def test_a_name_matching_no_declared_scanner_is_still_refused(tmp_path):
    """Control: every class declares a name and none is a community scanner."""
    engine = _engine(tmp_path)

    with pytest.raises(ScannerSelectionError):
        _reinitialize(engine, ["no-such-scanner"], [_NamedScanner])


def test_a_declared_name_is_still_selectable(tmp_path):
    engine = _engine(tmp_path)

    _reinitialize(engine, ["bandit"], [_NamedScanner])

    assert engine._initialized is True


class _StubPhase:
    def __init__(self, **kwargs):
        self._completed_scanners = []
        self._shard_assignment = None

    def execute(self, **kwargs):
        return kwargs.get("aggregated_results")


def _run(engine, phases):
    with (
        patch(f"{_ENGINE_MODULE}.ConvertPhase", _StubPhase),
        patch(f"{_ENGINE_MODULE}.ScanPhase", _StubPhase),
        patch(f"{_ENGINE_MODULE}.ReportPhase", _StubPhase),
        patch(f"{_ENGINE_MODULE}.InspectPhase", _StubPhase),
        patch(
            f"{_ENGINE_MODULE}.populate_metrics_from_unified_source",
            side_effect=lambda aggregated_results: aggregated_results,
        ),
        patch(f"{_ENGINE_MODULE}.display_metrics_table"),
    ):
        return engine.execute_phases(phases=phases)


def test_a_report_over_existing_results_keeps_the_stored_scan_timing(tmp_path):
    """Red before the fix: the report run's clock overwrote the stored timing."""
    engine = _engine(tmp_path)
    stored_start = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    stored_end = datetime(2024, 1, 2, 3, 9, 5, tzinfo=timezone.utc)
    stats = engine._asharp_model.metadata.summary_stats
    stats.start = stored_start
    stats.end = stored_end
    stats.duration = 300.0

    results = _run(engine, ["report"])

    assert results.metadata.summary_stats.start == stored_start
    assert results.metadata.summary_stats.end == stored_end
    assert results.metadata.summary_stats.duration == 300.0


def test_a_run_that_scans_stamps_its_own_timing(tmp_path):
    """Control: a scan replaces whatever the model carried."""
    engine = _engine(tmp_path)
    stale = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    engine._asharp_model.metadata.summary_stats.start = stale

    results = _run(engine, ["scan"])

    assert results.metadata.summary_stats.start != stale
    assert results.metadata.summary_stats.end is not None
