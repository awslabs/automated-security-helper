"""Tests for InspectPhase."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults

# Rebuild models so AshAggregatedResults is fully defined
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

from automated_security_helper.core.phases.inspect_phase import InspectPhase


@pytest.fixture
def mock_plugin_context(tmp_path):
    """Create a mock plugin context with a real output_dir."""
    ctx = MagicMock()
    ctx.output_dir = tmp_path / "output"
    ctx.output_dir.mkdir(parents=True, exist_ok=True)
    return ctx


@pytest.fixture
def inspect_phase(mock_plugin_context):
    """Create an InspectPhase instance with mocked dependencies."""
    phase = InspectPhase(plugin_context=mock_plugin_context)
    phase.initialize_progress = MagicMock()
    phase.update_progress = MagicMock()
    return phase


class TestInspectPhase:
    """Tests for InspectPhase."""

    def test_phase_name(self, inspect_phase):
        """phase_name returns 'inspect'."""
        assert inspect_phase.phase_name == "inspect"

    @patch(
        "automated_security_helper.utils.sarif_field_analysis.analyze_sarif_fields"
    )
    def test_execute_phase_success(self, mock_analyze, inspect_phase):
        """Successful execution calls analyze_sarif_fields and returns results."""
        model = AshAggregatedResults()

        result = inspect_phase._execute_phase(aggregated_results=model)

        assert result is model
        mock_analyze.assert_called_once()
        # Verify the output_dir argument is the analysis subdirectory
        call_kwargs = mock_analyze.call_args[1]
        assert "analysis" in call_kwargs["output_dir"]

    @patch(
        "automated_security_helper.utils.sarif_field_analysis.analyze_sarif_fields"
    )
    def test_execute_phase_creates_analysis_dir(self, mock_analyze, inspect_phase):
        """The analysis subdirectory is created during execution."""
        model = AshAggregatedResults()
        analysis_dir = inspect_phase.plugin_context.output_dir / "analysis"

        # Directory shouldn't exist yet
        assert not analysis_dir.exists()

        inspect_phase._execute_phase(aggregated_results=model)

        # Directory should be created
        assert analysis_dir.exists()

    @patch(
        "automated_security_helper.utils.sarif_field_analysis.analyze_sarif_fields",
        side_effect=RuntimeError("analysis failed"),
    )
    def test_execute_phase_handles_exception(self, mock_analyze, inspect_phase):
        """Exception during analysis is caught; phase still returns results."""
        model = AshAggregatedResults()

        result = inspect_phase._execute_phase(aggregated_results=model)

        # Should not raise; returns model
        assert result is model
        # Progress should still reach 100
        inspect_phase.update_progress.assert_called_with(
            100, "Inspection phase complete"
        )

    @patch(
        "automated_security_helper.utils.sarif_field_analysis.analyze_sarif_fields"
    )
    def test_progress_updates_on_success(self, mock_analyze, inspect_phase):
        """Progress updates are called in sequence during success."""
        model = AshAggregatedResults()

        inspect_phase._execute_phase(aggregated_results=model)

        calls = inspect_phase.update_progress.call_args_list
        percentages = [c[0][0] for c in calls]
        assert percentages == [10, 30, 90, 100]
