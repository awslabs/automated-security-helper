"""Tests for core/phases/convert_phase.py — covers ConvertPhase initialization and execution logic."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults

AshAggregatedResults.model_rebuild()


@pytest.fixture
def mock_context(tmp_path):
    ctx = MagicMock()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    ctx.source_dir = source_dir
    ctx.output_dir = output_dir
    ctx.work_dir = work_dir
    ctx.config = MagicMock()
    ctx.config.get_plugin_config.return_value = None
    return ctx


class TestConvertPhaseInit:
    """Tests for ConvertPhase initialization."""

    def test_phase_name(self, mock_context):
        phase = ConvertPhase(plugin_context=mock_context, plugins=[])
        assert phase.phase_name == "convert"

    def test_init_with_plugins(self, mock_context):
        mock_plugin = MagicMock()
        phase = ConvertPhase(plugin_context=mock_context, plugins=[mock_plugin])
        assert len(phase.plugins) == 1


class TestConvertPhaseExecution:
    """Tests for _execute_phase."""

    def test_execute_with_no_converters(self, mock_context):
        phase = ConvertPhase(
            plugin_context=mock_context,
            plugins=[],
            progress_display=MagicMock(),
        )
        mock_results = MagicMock(spec=AshAggregatedResults)
        mock_results.converter_results = {}

        result = phase._execute_phase(aggregated_results=mock_results)
        assert result is not None

    def test_execute_with_disabled_converter(self, mock_context):
        mock_cls = MagicMock()
        mock_cls.__name__ = "TestConverter"

        mock_instance = MagicMock()
        mock_instance.config.enabled = False
        mock_cls.return_value = mock_instance

        phase = ConvertPhase(
            plugin_context=mock_context,
            plugins=[mock_cls],
            progress_display=MagicMock(),
        )
        mock_results = MagicMock(spec=AshAggregatedResults)
        mock_results.converter_results = {}

        result = phase._execute_phase(aggregated_results=mock_results)
        assert result is not None

    def test_execute_python_only_filter(self, mock_context):
        mock_cls = MagicMock()
        mock_cls.__name__ = "RubyConverter"

        mock_instance = MagicMock()
        mock_instance.config.enabled = True
        mock_instance.is_python_only.return_value = False
        mock_cls.return_value = mock_instance

        phase = ConvertPhase(
            plugin_context=mock_context,
            plugins=[mock_cls],
            progress_display=MagicMock(),
        )
        mock_results = MagicMock(spec=AshAggregatedResults)
        mock_results.converter_results = {}

        result = phase._execute_phase(
            aggregated_results=mock_results, python_based_plugins_only=True
        )
        assert result is not None

    def test_execute_with_enabled_converter(self, mock_context):
        mock_cls = MagicMock()
        mock_cls.__name__ = "JupyterConverter"

        mock_instance = MagicMock()
        mock_instance.config.enabled = True
        mock_instance.config.name = "jupyter"
        mock_instance.is_python_only.return_value = True
        mock_instance.validate_plugin_dependencies.return_value = True
        mock_instance.convert.return_value = [Path("/tmp/converted.py")]  # nosec B108
        mock_cls.return_value = mock_instance

        phase = ConvertPhase(
            plugin_context=mock_context,
            plugins=[mock_cls],
            progress_display=MagicMock(),
        )
        mock_results = MagicMock(spec=AshAggregatedResults)
        mock_results.converter_results = {}

        result = phase._execute_phase(aggregated_results=mock_results)
        assert result is not None

    def test_execute_handles_converter_error(self, mock_context):
        mock_cls = MagicMock()
        mock_cls.__name__ = "BrokenConverter"

        mock_instance = MagicMock()
        mock_instance.config.enabled = True
        mock_instance.config.name = "broken"
        mock_instance.is_python_only.return_value = True
        mock_instance.validate_plugin_dependencies.return_value = True
        mock_instance.convert.side_effect = RuntimeError("convert failed")
        mock_cls.return_value = mock_instance

        phase = ConvertPhase(
            plugin_context=mock_context,
            plugins=[mock_cls],
            progress_display=MagicMock(),
        )
        mock_results = MagicMock(spec=AshAggregatedResults)
        mock_results.converter_results = {}

        # Should not raise
        result = phase._execute_phase(aggregated_results=mock_results)
        assert result is not None

    def test_execute_handles_instantiation_error(self, mock_context):
        mock_cls = MagicMock()
        mock_cls.__name__ = "FailInit"
        mock_cls.side_effect = RuntimeError("init failed")

        phase = ConvertPhase(
            plugin_context=mock_context,
            plugins=[mock_cls],
            progress_display=MagicMock(),
        )
        mock_results = MagicMock(spec=AshAggregatedResults)
        mock_results.converter_results = {}

        # Should not raise
        result = phase._execute_phase(aggregated_results=mock_results)
        assert result is not None
