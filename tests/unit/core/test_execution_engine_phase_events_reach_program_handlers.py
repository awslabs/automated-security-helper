# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Phase events reach the handlers the program running the scan subscribed.

``ScanExecutionEngine`` notifies EXECUTION_START and EXECUTION_COMPLETE through
``loader.scan_handler_filter``, which admits the scan's own plugin handlers and
every handler defined outside ASH's plugin namespace: the documented
``ash_plugin_manager.subscribe(event, handler)`` pattern of a program embedding
ASH. The phases the engine builds take the same filter as their ``plugin_scope``,
so SCAN_START, SCAN_COMPLETE and every *_PHASE_START and *_PHASE_COMPLETE event
reach the same handlers. Before this, the engine overwrote each phase's scope with
``loader.plugins_of``, which admits the plugin namespace only, so a program's
handler saw the two execution events and never a phase event.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
)

pytestmark = pytest.mark.unit

_ENGINE_MODULE = "automated_security_helper.core.execution_engine"
_PHASE_MODULE = "automated_security_helper.base.engine_phase"


class _ConvertLikePhase(EnginePhase):
    """A real EnginePhase in the convert slot: it notifies its phase events."""

    @property
    def phase_name(self) -> str:
        return "convert"

    def _execute_phase(
        self, aggregated_results, python_based_plugins_only=False, **kwargs
    ):
        return aggregated_results


def _handler_in(module: str, received: list):
    def on_event(**kwargs):
        received.append(kwargs.get("phase"))

    on_event.__module__ = module
    return on_event


def _engine(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    context = PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="phase-events"),
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


def _run_convert(engine, manager):
    with (
        patch(f"{_ENGINE_MODULE}.ConvertPhase", _ConvertLikePhase),
        patch(f"{_PHASE_MODULE}.ash_plugin_manager", manager),
        patch(
            f"{_ENGINE_MODULE}.populate_metrics_from_unified_source",
            side_effect=lambda aggregated_results: aggregated_results,
        ),
        patch(f"{_ENGINE_MODULE}.display_metrics_table"),
    ):
        engine.execute_phases(phases=["convert"])


def _manager():
    return AshPluginManager(
        plugin_library=AshPluginLibrary(
            converters={}, scanners={}, reporters={}, event_handlers={}
        )
    )


def test_a_phase_event_reaches_a_handler_the_program_subscribed(tmp_path):
    """A handler defined outside the plugin namespace is notified of a phase event.

    Red before the fix: the phase's scope was ``plugins_of``, which admits only
    classes and handlers of the plugin namespace, so ``received`` stayed empty.
    """
    engine = _engine(tmp_path)
    manager = _manager()
    received: list = []
    manager.subscribe(
        AshEventType.CONVERT_PHASE_START,
        _handler_in("zz_calling_program.hooks", received),
    )

    _run_convert(engine, manager)

    assert received == ["convert"]


def test_a_phase_event_still_skips_another_scans_plugin_handler(tmp_path):
    """Control: a handler of a plugin module this scan did not name stays out."""
    engine = _engine(tmp_path)
    manager = _manager()
    received: list = []
    manager.subscribe(
        AshEventType.CONVERT_PHASE_START,
        _handler_in("zz_other_ash_plugins.events", received),
    )

    _run_convert(engine, manager)

    assert received == []


def test_the_phase_scope_is_the_engines_handler_filter(tmp_path):
    """The engine hands each phase its handler filter and overwrites nothing."""
    engine = _engine(tmp_path)
    built: list = []

    class _Recording(_ConvertLikePhase):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            built.append(self)

    with (
        patch(f"{_ENGINE_MODULE}.ConvertPhase", _Recording),
        patch(f"{_PHASE_MODULE}.ash_plugin_manager", _manager()),
        patch(
            f"{_ENGINE_MODULE}.populate_metrics_from_unified_source",
            side_effect=lambda aggregated_results: aggregated_results,
        ),
        patch(f"{_ENGINE_MODULE}.display_metrics_table"),
    ):
        engine.execute_phases(phases=["convert"])

    assert len(built) == 1
    assert built[0].plugin_scope is engine._handler_filter
