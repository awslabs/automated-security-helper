# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The engine's run records and lifecycle, as the low findings read them.

What each test pins, and what it read at the base before the fix:

* a run built without a configuration records the default it substitutes
  (``results.ash_config`` was None beside a run that used ASH's defaults), and a
  model a caller passed keeps the configuration it records (the backfill stamped
  this run's configuration onto a loaded model whose ash_config was null);
* ``get_scanner`` finds a scanner by its declared name and honors
  ``check_enabled`` (it matched the lowercased class name only, and never read
  the parameter), finds it by its configured name and judges the selection by it
  (the renamed scanner the phase runs was "not found" and refused), and refuses a
  scanner its section disables (the phase records it SKIPPED);
* the construction-time selection refusal compares the names the scan phase
  matches, the configured section's name first (a scanner the configuration
  renamed was refused as a misspelling);
* a Ctrl-C while an EXECUTION_START handler runs stops the Live display (it
  escaped before the try whose finally is the only stop() site);
* a Ctrl-C while the ERROR handlers run is an interrupted run (the finally
  notified EXECUTION_COMPLETE and printed the closing banner);
* a run whose phase raised is reported as failed (the banner, the completion
  event's message and the metrics table all said it completed);
* the final metrics table cannot replace the run's result (an exception from the
  rendering propagated out of the finally);
* the aggregated suppression pass sees every finding before --changed-files-only
  narrows them (the narrowing ran first, so a matching suppression read unused);
* the report phase renders a model whose summary carries the scan's timing (the
  stamp sat in the finally, after the reporters ran), and a report-only run over
  results that already carry a scan's timing keeps it through both stamps.
"""

from __future__ import annotations

from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
)

pytestmark = pytest.mark.unit

_ENGINE_MODULE = "automated_security_helper.core.execution_engine"
_PLUGINS_PACKAGE = "automated_security_helper.plugins"
_SARIF_UTILS = "automated_security_helper.utils.sarif_utils"
_CHANGED_FILES = "automated_security_helper.utils.changed_files"


class _StubPhase:
    def __init__(self, **kwargs):
        self._completed_scanners = []
        self._shard_assignment = None

    def execute(self, **kwargs):
        return kwargs.get("aggregated_results")


class _RaisingScanPhase(_StubPhase):
    def execute(self, **kwargs):
        raise RuntimeError("the scan phase broke")


def _engine(
    tmp_path, config: Optional[AshConfig] = "default", own_model: bool = False, **kwargs
):
    """An engine over a fresh passed-in model, or (``own_model``) over the model
    the engine builds for itself in ``__init__``."""
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context_kwargs = {
        "source_dir": source_dir,
        "output_dir": output_dir,
        "work_dir": tmp_path / "work",
    }
    if config == "default":
        context_kwargs["config"] = AshConfig(project_name="run-records")
    elif config is not None:
        context_kwargs["config"] = config
    context = PluginContext(**context_kwargs)
    if not own_model:
        kwargs["asharp_model"] = AshAggregatedResults()
    with patch("automated_security_helper.plugins.loader.load_internal_plugins"):
        engine = ScanExecutionEngine(
            context=context,
            show_progress=False,
            show_summary=False,
            **kwargs,
        )
    engine.progress_display = MagicMock()
    engine.progress_display.live = None
    return engine


def _manager() -> AshPluginManager:
    return AshPluginManager(
        plugin_library=AshPluginLibrary(
            converters={}, scanners={}, reporters={}, event_handlers={}
        )
    )


def _program_handler(record, raises=None):
    """A handler defined outside the plugin namespace, as a program's is."""

    def on_event(**kwargs):
        record.append(kwargs)
        if raises is not None:
            raise raises

    on_event.__module__ = "embedding_program.hooks"
    return on_event


def _run(engine, phases, manager, scan_phase=_StubPhase, report_phase=_StubPhase):
    with (
        patch(f"{_ENGINE_MODULE}.ConvertPhase", _StubPhase),
        patch(f"{_ENGINE_MODULE}.ScanPhase", scan_phase),
        patch(f"{_ENGINE_MODULE}.ReportPhase", report_phase),
        patch(f"{_ENGINE_MODULE}.InspectPhase", _StubPhase),
        patch(f"{_PLUGINS_PACKAGE}.ash_plugin_manager", manager),
        patch(
            f"{_ENGINE_MODULE}.populate_metrics_from_unified_source",
            side_effect=lambda aggregated_results: aggregated_results,
        ),
        patch(f"{_ENGINE_MODULE}.display_metrics_table"),
        patch(
            f"{_SARIF_UTILS}.apply_suppressions_to_sarif",
            side_effect=lambda sarif_report, **kwargs: sarif_report,
        ),
        patch(
            "automated_security_helper.utils.suppression_matcher."
            "warn_unmatched_directory_suppressions"
        ),
    ):
        return engine.execute_phases(phases=phases)


# ---------------------------------------------------------------------------
# The configuration the results record
# ---------------------------------------------------------------------------


def test_a_run_without_a_configuration_records_the_default_it_ran_with(tmp_path):
    """Red before the fix: the model took ash_config=None at construction and the
    default AshConfig was substituted into the context only."""
    engine = _engine(tmp_path, config=None, own_model=True)

    assert isinstance(engine._context.config, AshConfig)
    assert engine._asharp_model.ash_config is engine._context.config


def test_a_model_a_caller_passed_keeps_the_configuration_it_records(tmp_path):
    """A passed-in model (one loaded from an existing results file, a library
    caller's own) records the configuration of the scan that produced it; a
    results file whose ash_config is null loads as None, and stamping this run's
    configuration onto it misattributed the scan. Red at the base: the backfill
    tested ``ash_config is None`` alone, so the passed model took the default."""
    engine = _engine(tmp_path, config=None)

    assert isinstance(engine._context.config, AshConfig)
    assert engine._asharp_model.ash_config is None


# ---------------------------------------------------------------------------
# get_scanner
# ---------------------------------------------------------------------------


class _DeclaredConfig:
    model_fields = {"name": MagicMock(default="fake-scan")}


class _ConfigField:
    annotation = Optional[_DeclaredConfig]


class _FakeScanner:
    model_fields = {"config": _ConfigField()}

    def __init__(self, context=None, config=None):
        self.context = context
        self.config = config


def test_get_scanner_finds_a_scanner_by_its_declared_name(tmp_path):
    """Red before the fix: only the lowercased class name matched, so the name
    every other surface uses raised 'not found'."""
    engine = _engine(tmp_path)
    engine.plugins["scanner"] = [_FakeScanner]

    assert isinstance(engine.get_scanner("fake-scan"), _FakeScanner)
    assert isinstance(engine.get_scanner("_FakeScanner"), _FakeScanner)


def test_get_scanner_refuses_an_excluded_scanner_when_check_enabled(tmp_path):
    """Red before the fix: check_enabled was never read and the excluded
    scanner was returned."""
    engine = _engine(tmp_path, excluded_scanners=["fake-scan"])
    engine.plugins["scanner"] = [_FakeScanner]

    with pytest.raises(ValueError, match="not enabled"):
        engine.get_scanner("_FakeScanner")
    # The documented opt-out still builds it.
    assert isinstance(
        engine.get_scanner("_FakeScanner", check_enabled=False), _FakeScanner
    )


def test_get_scanner_refuses_a_scanner_the_allowlist_leaves_out(tmp_path):
    engine = _engine(tmp_path)
    engine.plugins["scanner"] = [_FakeScanner]
    engine._init_enabled_scanners = ["other-scanner"]

    with pytest.raises(ValueError, match="does not name it"):
        engine.get_scanner("fake-scan")


def _renamed_section(self, plugin_type, plugin_name):
    if plugin_type == "scanner" and plugin_name == "fake-scan":
        return {"name": "renamed-scan", "enabled": True}
    return None


def test_get_scanner_finds_a_scanner_by_its_configured_name(tmp_path, monkeypatch):
    """The configured section's name is the one ScanPhase selects and reports the
    scanner by, and the one ensure_initialized judges --scanners against. Red at
    the base: get_scanner compared the declared and class names only, so the
    configured name was "not found" and, with an allowlist naming it, the declared
    name was refused as unselected although the phase runs that scanner."""
    engine = _engine(tmp_path)
    monkeypatch.setattr(AshConfig, "get_plugin_config", _renamed_section)
    engine.plugins["scanner"] = [_FakeScanner]

    assert isinstance(engine.get_scanner("renamed-scan"), _FakeScanner)

    engine._init_enabled_scanners = ["renamed-scan"]
    assert isinstance(engine.get_scanner("fake-scan"), _FakeScanner)


def test_get_scanner_refuses_a_scanner_excluded_by_its_configured_name(
    tmp_path, monkeypatch
):
    """The reverse: an exclusion naming the configured name leaves the scanner
    out of the phase, so a lookup by any of its names is refused."""
    engine = _engine(tmp_path, excluded_scanners=["renamed-scan"])
    monkeypatch.setattr(AshConfig, "get_plugin_config", _renamed_section)
    engine.plugins["scanner"] = [_FakeScanner]

    with pytest.raises(ValueError, match="exclusion list"):
        engine.get_scanner("fake-scan")


def test_get_scanner_judges_the_selection_by_the_configured_name_alone(
    tmp_path, monkeypatch
):
    """ScanPhase matches --scanners and --exclude-scanners against the configured
    name, so a renamed scanner an exclusion names by its declared name still runs
    there. Red at the base: the lookup judged every spelling the scanner answers
    to, so it refused the scanner the phase runs and let through the one the phase
    leaves out."""
    monkeypatch.setattr(AshConfig, "get_plugin_config", _renamed_section)

    excluded_by_declared_name = _engine(tmp_path, excluded_scanners=["fake-scan"])
    excluded_by_declared_name.plugins["scanner"] = [_FakeScanner]
    assert isinstance(
        excluded_by_declared_name.get_scanner("renamed-scan"), _FakeScanner
    )

    left_out_by_allowlist = _engine(tmp_path)
    left_out_by_allowlist.plugins["scanner"] = [_FakeScanner]
    left_out_by_allowlist._init_enabled_scanners = ["fake-scan"]
    with pytest.raises(ValueError, match="does not name it"):
        left_out_by_allowlist.get_scanner("renamed-scan")


def test_get_scanner_refuses_a_scanner_its_section_disables(tmp_path, monkeypatch):
    """ScanPhase records a scanner whose section says enabled: false as SKIPPED,
    so check_enabled refuses it; the documented opt-out still builds it."""
    engine = _engine(tmp_path)

    def disabled_section(self, plugin_type, plugin_name):
        if plugin_type == "scanner" and plugin_name == "fake-scan":
            return {"enabled": False}
        return None

    monkeypatch.setattr(AshConfig, "get_plugin_config", disabled_section)
    engine.plugins["scanner"] = [_FakeScanner]

    with pytest.raises(ValueError, match="disables it"):
        engine.get_scanner("fake-scan")
    assert isinstance(
        engine.get_scanner("fake-scan", check_enabled=False), _FakeScanner
    )


# ---------------------------------------------------------------------------
# The construction-time selection refusal compares the phase's names
# ---------------------------------------------------------------------------


def test_a_configured_scanner_name_is_selectable_at_construction(tmp_path, monkeypatch):
    """Red before the fix: the refusal compared the declared names only, so an
    allowlist naming the configured name was refused as matching nothing."""
    engine = _engine(tmp_path)

    def section(self, plugin_type, plugin_name):
        if plugin_type == "scanner" and plugin_name == "fake-scan":
            return {"name": "renamed-scan", "enabled": True}
        return None

    monkeypatch.setattr(AshConfig, "get_plugin_config", section)
    engine.plugins["scanner"] = [_FakeScanner]
    engine._init_enabled_scanners = ["renamed-scan"]
    engine._initialized = False

    engine.ensure_initialized()  # does not raise

    assert engine._selectable_scanner_name(_FakeScanner) == "renamed-scan"


def test_an_allowlist_matching_no_name_is_still_refused(tmp_path, monkeypatch):
    """Control: with no configured rename, a name that matches nothing refuses."""
    engine = _engine(tmp_path)
    monkeypatch.setattr(AshConfig, "get_plugin_config", lambda self, t, n: None)
    engine.plugins["scanner"] = [_FakeScanner]
    engine._init_enabled_scanners = ["nonexistent-scan"]
    engine._initialized = False

    with pytest.raises(ScannerSelectionError):
        engine.ensure_initialized()


# ---------------------------------------------------------------------------
# Interrupts around the handlers
# ---------------------------------------------------------------------------


def test_an_interrupt_in_a_start_handler_stops_the_display(tmp_path):
    """Red before the fix: the start notification ran before the try whose
    finally stops the display, so a Ctrl-C there left it running."""
    engine = _engine(tmp_path)
    engine.progress_display.live = object()
    manager = _manager()
    manager.subscribe(
        AshEventType.EXECUTION_START, _program_handler([], raises=KeyboardInterrupt())
    )

    with pytest.raises(KeyboardInterrupt):
        _run(engine, ["convert"], manager)

    engine.progress_display.stop.assert_called_once_with(interrupted=True)


def test_an_interrupt_in_an_error_handler_is_an_interrupted_run(tmp_path):
    """Red before the fix: the interrupt escaped the except arm with the flag
    unset, so EXECUTION_COMPLETE was notified over an interrupted run."""
    engine = _engine(tmp_path)
    manager = _manager()
    completed = []
    manager.subscribe(
        AshEventType.ERROR, _program_handler([], raises=KeyboardInterrupt())
    )
    manager.subscribe(AshEventType.EXECUTION_COMPLETE, _program_handler(completed))

    with pytest.raises(KeyboardInterrupt):
        _run(engine, ["scan"], manager, scan_phase=_RaisingScanPhase)

    assert completed == []


# ---------------------------------------------------------------------------
# A failed run says so
# ---------------------------------------------------------------------------


def test_a_failed_run_is_reported_as_failed(tmp_path):
    """Red before the fix: the completion event said 'completed', the banner
    said 'Completed', and the metrics table was rendered over partial results."""
    engine = _engine(tmp_path)
    engine.show_summary = True
    manager = _manager()
    completed = []
    manager.subscribe(AshEventType.EXECUTION_COMPLETE, _program_handler(completed))

    with (
        patch(f"{_ENGINE_MODULE}.ASH_LOGGER") as logger,
        pytest.raises(RuntimeError, match="the scan phase broke"),
    ):
        _run(engine, ["scan"], manager, scan_phase=_RaisingScanPhase)

    assert len(completed) == 1
    event = completed[0]
    assert event["succeeded"] is False
    assert "failed after" in event["message"]
    assert event["phase"] == "execution"
    assert event["plugin_context"] is engine._context
    infos = " ".join(str(c.args[0]) for c in logger.info.call_args_list)
    assert "ASH Security Scan Failed after" in infos
    assert "ASH Security Scan Completed" not in infos


class _ExitingScanPhase(_StubPhase):
    def execute(self, **kwargs):
        raise SystemExit(3)


def test_a_run_ended_by_an_exit_is_reported_as_failed(tmp_path):
    """Red before the fix: a SystemExit from a phase is neither an Exception nor
    an interrupt, so the completion event said the run succeeded and the banner
    said it completed while the exit was still propagating."""
    engine = _engine(tmp_path)
    engine.show_summary = True
    manager = _manager()
    completed = []
    manager.subscribe(AshEventType.EXECUTION_COMPLETE, _program_handler(completed))

    with (
        patch(f"{_ENGINE_MODULE}.ASH_LOGGER") as logger,
        pytest.raises(SystemExit) as raised,
    ):
        _run(engine, ["scan"], manager, scan_phase=_ExitingScanPhase)

    assert raised.value.code == 3
    assert len(completed) == 1
    assert completed[0]["succeeded"] is False
    assert "failed after" in completed[0]["message"]
    infos = " ".join(str(c.args[0]) for c in logger.info.call_args_list)
    assert "ASH Security Scan Failed after" in infos
    assert "ASH Security Scan Completed" not in infos


def test_a_completed_run_still_says_so(tmp_path):
    """Control: the message and the banner of a run that completed are unchanged."""
    engine = _engine(tmp_path)
    manager = _manager()
    completed = []
    manager.subscribe(AshEventType.EXECUTION_COMPLETE, _program_handler(completed))

    with patch(f"{_ENGINE_MODULE}.ASH_LOGGER") as logger:
        _run(engine, ["convert"], manager)

    assert completed[0]["succeeded"] is True
    assert "completed in" in completed[0]["message"]
    infos = " ".join(str(c.args[0]) for c in logger.info.call_args_list)
    assert "ASH Security Scan Completed in" in infos


def test_the_metrics_table_cannot_fail_a_completed_run(tmp_path):
    """Red before the fix: the rendering ran unguarded inside the finally, so its
    exception replaced the run's result."""
    engine = _engine(tmp_path)
    engine.show_summary = True

    with (
        patch(f"{_ENGINE_MODULE}.ConvertPhase", _StubPhase),
        patch(f"{_PLUGINS_PACKAGE}.ash_plugin_manager", _manager()),
        patch(
            f"{_ENGINE_MODULE}.populate_metrics_from_unified_source",
            side_effect=lambda aggregated_results: aggregated_results,
        ),
        patch(
            f"{_ENGINE_MODULE}.display_metrics_table",
            side_effect=RuntimeError("no terminal"),
        ),
        patch(f"{_ENGINE_MODULE}.ASH_LOGGER") as logger,
    ):
        results = engine.execute_phases(phases=["convert"])

    assert results is engine._results
    errors = " ".join(str(c.args[0]) for c in logger.error.call_args_list)
    assert "no terminal" in errors


# ---------------------------------------------------------------------------
# The suppression pass runs before the changed-files narrowing
# ---------------------------------------------------------------------------


def test_suppressions_are_applied_before_the_changed_files_narrowing(tmp_path):
    """Red before the fix: the narrowing ran first, so a suppression matching
    only a finding outside the changed files was recorded as unused."""
    engine = _engine(tmp_path)
    engine.restrict_to_changed_files({tmp_path / "source" / "changed.py"})
    order = []

    def suppress(sarif_report, **kwargs):
        order.append("suppress")
        return sarif_report

    def narrow(results, changed_files, source_dir, **kwargs):
        order.append("narrow")
        return results

    with (
        patch(f"{_ENGINE_MODULE}.ScanPhase", _StubPhase),
        patch(f"{_PLUGINS_PACKAGE}.ash_plugin_manager", _manager()),
        patch(
            f"{_ENGINE_MODULE}.populate_metrics_from_unified_source",
            side_effect=lambda aggregated_results: aggregated_results,
        ),
        patch(f"{_SARIF_UTILS}.apply_suppressions_to_sarif", side_effect=suppress),
        patch(f"{_CHANGED_FILES}.filter_results_to_changed_files", side_effect=narrow),
        patch(
            "automated_security_helper.utils.suppression_matcher."
            "warn_unmatched_directory_suppressions"
        ),
    ):
        engine.execute_phases(phases=["scan"])

    assert order == ["suppress", "narrow"]


# ---------------------------------------------------------------------------
# The reporters see the scan's timing
# ---------------------------------------------------------------------------


def test_the_report_phase_renders_a_model_that_carries_the_scan_timing(tmp_path):
    """Red before the fix: the timing was stamped in the finally, after the
    report phase, so every report of a fresh scan carried start None."""
    engine = _engine(tmp_path)
    seen = {}

    class _CapturingReportPhase(_StubPhase):
        def execute(self, **kwargs):
            stats = kwargs["aggregated_results"].metadata.summary_stats
            seen["start"] = stats.start
            seen["end"] = stats.end
            seen["duration"] = stats.duration
            return kwargs["aggregated_results"]

    _run(engine, ["scan", "report"], _manager(), report_phase=_CapturingReportPhase)

    assert seen["start"] is not None
    assert seen["end"] is not None
    assert seen["duration"] >= 0.0
    # The finally still stamps the final values over them.
    assert engine._results.metadata.summary_stats.end >= seen["end"]


def test_a_report_over_existing_results_keeps_their_timing(tmp_path):
    """Control for the restamp: a report-only run over results that already
    carry a scan's start, end and duration leaves all three as they were, at
    the report phase and in the finally. (The stamp over fresh results in a
    report-only run is pinned by test_execution_engine_lifecycle.py's
    TestExecutePhasesDuration, which reads red when the final stamp skips
    the pre-report one.)"""
    from datetime import datetime, timedelta, timezone

    engine = _engine(tmp_path)
    stats = engine._results.metadata.summary_stats
    stats.start = datetime(2025, 6, 1, 8, 0, 0, tzinfo=timezone.utc)
    stats.end = stats.start + timedelta(seconds=90)
    stats.duration = 90.0
    seen = {}

    class _CapturingReportPhase(_StubPhase):
        def execute(self, **kwargs):
            summary = kwargs["aggregated_results"].metadata.summary_stats
            seen["start"], seen["end"] = summary.start, summary.end
            return kwargs["aggregated_results"]

    result = _run(engine, ["report"], _manager(), report_phase=_CapturingReportPhase)

    assert seen == {"start": stats.start, "end": stats.end}
    final = result.metadata.summary_stats
    assert (final.start, final.end, final.duration) == (
        datetime(2025, 6, 1, 8, 0, 0, tzinfo=timezone.utc),
        datetime(2025, 6, 1, 8, 1, 30, tzinfo=timezone.utc),
        90.0,
    )
