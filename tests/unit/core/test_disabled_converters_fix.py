"""Regression test for #197: disabling all converters must not crash reporting."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults


def _make_plugin_context(tmp_path: Path):
    """Build a minimal PluginContext whose paths exist on disk."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    work = output / "work"
    # Deliberately do NOT create work/ -- simulates the state when all
    # converters are disabled and the directory was never populated.

    ctx = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=work,
        config=AshConfig(project_name="test-disabled-converters"),
    )
    return ctx


def _stub_progress():
    """Return a progress display stub that accepts any method call."""
    progress = MagicMock()
    progress.add_task.return_value = 0
    return progress


# --------------------------------------------------------------------------- #
# Convert phase with zero enabled converters
# --------------------------------------------------------------------------- #
class TestConvertPhaseNoConverters:
    """ConvertPhase must return cleanly when the converter list is empty."""

    def test_empty_converter_list_returns_aggregated_results(self, tmp_path):
        ctx = _make_plugin_context(tmp_path)
        agg = AshAggregatedResults(
            name="test", description="test", ash_config=ctx.config
        )
        phase = ConvertPhase(
            plugins=[],
            plugin_context=ctx,
            progress_display=_stub_progress(),
            asharp_model=agg,
        )
        result = phase.execute(aggregated_results=agg)
        assert isinstance(result, AshAggregatedResults)

    def test_all_converters_disabled_returns_aggregated_results(self, tmp_path):
        """Simulate converters present but all disabled via config."""
        ctx = _make_plugin_context(tmp_path)

        # Create a fake converter class whose config says enabled=False
        fake_config = MagicMock()
        fake_config.enabled = False

        fake_converter_cls = MagicMock()
        fake_converter_cls.__name__ = "FakeConverter"
        fake_instance = MagicMock()
        fake_instance.config = fake_config
        fake_converter_cls.return_value = fake_instance

        agg = AshAggregatedResults(
            name="test", description="test", ash_config=ctx.config
        )
        phase = ConvertPhase(
            plugins=[fake_converter_cls],
            plugin_context=ctx,
            progress_display=_stub_progress(),
            asharp_model=agg,
        )
        result = phase.execute(aggregated_results=agg)
        assert isinstance(result, AshAggregatedResults)


# --------------------------------------------------------------------------- #
# Report phase when no scan results exist (converter-less flow)
# --------------------------------------------------------------------------- #
class TestReportPhaseNoConvertedFiles:
    """ReportPhase must produce output even when no converters ran."""

    def test_report_phase_handles_no_converted_files(self, tmp_path):
        """When all converters are disabled the report phase must still
        complete without crashing on missing converted files."""
        ctx = _make_plugin_context(tmp_path)
        reports_dir = ctx.output_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        agg = AshAggregatedResults(
            name="test", description="test", ash_config=ctx.config
        )
        # No converter_results recorded -- simulates disabled converters
        assert len(agg.converter_results) == 0

        phase = ReportPhase(
            plugins=[],  # no reporter plugins either -- simplest path
            plugin_context=ctx,
            progress_display=_stub_progress(),
            asharp_model=agg,
        )
        result = phase.execute(
            aggregated_results=agg,
            report_dir=reports_dir,
        )
        assert isinstance(result, AshAggregatedResults)

    def test_report_phase_with_reporter_and_no_converted_files(self, tmp_path):
        """A reporter plugin must receive aggregated_results even when
        converter_results is empty and produce output without error."""
        ctx = _make_plugin_context(tmp_path)
        reports_dir = ctx.output_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        agg = AshAggregatedResults(
            name="test", description="test", ash_config=ctx.config
        )

        # Build a minimal fake reporter class
        fake_config = MagicMock()
        fake_config.enabled = True
        fake_config.name = "FakeReporter"
        fake_config.extension = "txt"

        fake_reporter_cls = MagicMock()
        fake_reporter_cls.__name__ = "FakeReporter"
        fake_instance = MagicMock()
        fake_instance.config = fake_config
        fake_instance.is_python_only.return_value = True
        fake_instance.report.return_value = "no findings"
        fake_reporter_cls.return_value = fake_instance

        phase = ReportPhase(
            plugins=[fake_reporter_cls],
            plugin_context=ctx,
            progress_display=_stub_progress(),
            asharp_model=agg,
        )
        result = phase.execute(
            aggregated_results=agg,
            report_dir=reports_dir,
        )
        assert isinstance(result, AshAggregatedResults)
        # The reporter should have been called exactly once
        fake_instance.report.assert_called_once_with(agg)
        # And the report file should exist
        assert (reports_dir / "ash.txt").read_text() == "no findings"
