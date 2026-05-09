"""Regression tests verifying that all three phase classes call filter_enabled_plugins."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_plugin_context(tmp_path):
    ctx = MagicMock()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("x = 1")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    ctx.source_dir = source_dir
    ctx.work_dir = work_dir
    ctx.output_dir = output_dir
    ctx.config = MagicMock()
    ctx.config.get_plugin_config.return_value = MagicMock(enabled=True, name="mock")
    ctx.config.output_formats = []
    ctx.ignore_suppressions = False
    ctx.cached_source_files = []
    return ctx


@pytest.fixture
def mock_progress(tmp_path):
    display = MagicMock()
    display.add_task.return_value = 1
    return display


@pytest.fixture
def agg():
    return AshAggregatedResults()


def _make_plugin_class(name="MockPlugin"):
    """Return a MagicMock that looks like a plugin class."""
    cls = MagicMock(name=name)
    cls.__name__ = name
    instance = MagicMock()
    instance.__class__ = cls
    instance.__class__.__name__ = name
    cfg = MagicMock()
    cfg.enabled = True
    cfg.name = name.lower()
    cfg.extension = "txt"
    instance.config = cfg
    instance.is_python_only.return_value = True
    instance.validate_plugin_dependencies.return_value = True
    instance.convert.return_value = []
    instance.report.return_value = None
    instance.dependencies_satisfied = True
    cls.return_value = instance
    return cls


# ---------------------------------------------------------------------------
# ConvertPhase
# ---------------------------------------------------------------------------


def test_convert_phase_uses_filter_enabled_plugins(
    mock_plugin_context, mock_progress, agg
):
    """ConvertPhase._execute_phase must call self.filter_enabled_plugins."""
    plugin_cls = _make_plugin_class("CvtPlugin")
    phase = ConvertPhase(
        plugin_context=mock_plugin_context,
        plugins=[plugin_cls],
        progress_display=mock_progress,
    )

    with patch.object(
        ConvertPhase,
        "filter_enabled_plugins",
        wraps=phase.filter_enabled_plugins,
    ) as spy:
        phase._execute_phase(aggregated_results=agg)

    spy.assert_called_once()
    args, kwargs = spy.call_args
    # plugin_instances should contain the pre-created instance
    plugin_instances = kwargs.get("plugin_instances") or (args[0] if args else None)
    assert plugin_instances is not None, "filter_enabled_plugins called without plugin_instances"
    assert len(plugin_instances) == 1


# ---------------------------------------------------------------------------
# ReportPhase
# ---------------------------------------------------------------------------


def test_report_phase_uses_filter_enabled_plugins(
    mock_plugin_context, mock_progress, agg, tmp_path
):
    """ReportPhase._execute_phase must call self.filter_enabled_plugins."""
    plugin_cls = _make_plugin_class("RptPlugin")
    phase = ReportPhase(
        plugin_context=mock_plugin_context,
        plugins=[plugin_cls],
        progress_display=mock_progress,
    )

    with patch.object(
        ReportPhase,
        "filter_enabled_plugins",
        wraps=phase.filter_enabled_plugins,
    ) as spy:
        phase._execute_phase(
            report_dir=tmp_path / "reports",
            aggregated_results=agg,
        )

    spy.assert_called_once()
    args, kwargs = spy.call_args
    plugin_instances = kwargs.get("plugin_instances") or (args[0] if args else None)
    assert plugin_instances is not None, "filter_enabled_plugins called without plugin_instances"
    assert len(plugin_instances) == 1


# ---------------------------------------------------------------------------
# ScanPhase
# ---------------------------------------------------------------------------


def test_scan_phase_uses_filter_enabled_plugins(
    mock_plugin_context, mock_progress, agg
):
    """ScanPhase._execute_phase must call self.filter_enabled_plugins."""
    plugin_cls = _make_plugin_class("ScnPlugin")
    # Make the instance look like a scanner
    instance = plugin_cls.return_value
    instance.dependencies_satisfied = True

    phase = ScanPhase(
        plugin_context=mock_plugin_context,
        plugins=[plugin_cls],
        progress_display=mock_progress,
    )

    # Stub out the executor so we don't need real scanner infrastructure
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
    ) as MockExecutor:
        executor_instance = MagicMock()
        executor_instance.completed_scanners = []
        executor_instance.run_parallel.return_value = agg
        executor_instance.run_sequential.return_value = agg
        MockExecutor.return_value = executor_instance

        with patch.object(
            ScanPhase,
            "filter_enabled_plugins",
            wraps=phase.filter_enabled_plugins,
        ) as spy:
            try:
                phase._execute_phase(
                    aggregated_results=agg,
                    python_based_plugins_only=False,
                )
            except Exception:
                pass  # We only care that the helper was called

    spy.assert_called()
