"""Tests for C2 bug fix: --output-formats CLI flag threading through to ReportPhase."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.enums import ExportFormat


class TestOutputFormatsThreading:
    """Verify that output_formats flows from orchestrator -> engine -> report phase."""

    def test_engine_stores_output_formats(self, tmp_path):
        """ScanExecutionEngine must accept and store output_formats."""
        from automated_security_helper.core.execution_engine import ScanExecutionEngine
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig

        ctx = PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "output",
            work_dir=tmp_path / "work",
            config=AshConfig(),
        )
        formats = [ExportFormat.CSV, ExportFormat.HTML]

        engine = ScanExecutionEngine(
            context=ctx,
            output_formats=formats,
        )

        assert engine._output_formats == formats

    def test_engine_defaults_output_formats_to_empty(self, tmp_path):
        """When output_formats is not passed, it defaults to an empty list."""
        from automated_security_helper.core.execution_engine import ScanExecutionEngine
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig

        ctx = PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "output",
            work_dir=tmp_path / "work",
            config=AshConfig(),
        )

        engine = ScanExecutionEngine(context=ctx)

        assert engine._output_formats == []

    @patch(
        "automated_security_helper.core.execution_engine.ReportPhase"
    )
    def test_execute_phases_passes_output_formats_to_report(
        self, mock_report_cls, tmp_path
    ):
        """execute_phases must pass cli_output_formats from engine._output_formats."""
        from automated_security_helper.core.execution_engine import ScanExecutionEngine
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig

        ctx = PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "output",
            work_dir=tmp_path / "work",
            config=AshConfig(),
        )
        (tmp_path / "output" / "reports").mkdir(parents=True, exist_ok=True)

        formats = [ExportFormat.SARIF, ExportFormat.JUNITXML]
        engine = ScanExecutionEngine(
            context=ctx,
            output_formats=formats,
            show_progress=False,
        )

        # Stub internals so execute_phases doesn't blow up on missing plugins
        mock_report_instance = MagicMock()
        mock_report_instance.execute.return_value = engine._asharp_model
        mock_report_cls.return_value = mock_report_instance

        engine._initialized = True
        engine._results = engine._asharp_model

        engine.execute_phases(phases=["report"])

        # The critical assertion: cli_output_formats kwarg must carry our formats
        mock_report_instance.execute.assert_called_once()
        call_kwargs = mock_report_instance.execute.call_args.kwargs
        assert call_kwargs["cli_output_formats"] == formats
