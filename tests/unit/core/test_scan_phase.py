"""Tests for core/phases/scan_phase.py — covers ScanPhase initialization and validation manager usage."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.models.scanner_validation import ScannerValidationManager

# Rebuild model to handle forward references
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


class TestScanPhaseInit:
    """Tests for ScanPhase initialization."""

    def test_init_creates_validation_manager(self, mock_context):
        phase = ScanPhase(plugin_context=mock_context, plugins=[])
        assert isinstance(phase.validation_manager, ScannerValidationManager)

    def test_phase_name(self, mock_context):
        phase = ScanPhase(plugin_context=mock_context, plugins=[])
        assert phase.phase_name == "scan"

    def test_init_with_plugins(self, mock_context):
        mock_plugin = MagicMock()
        phase = ScanPhase(plugin_context=mock_context, plugins=[mock_plugin])
        assert len(phase.plugins) == 1

    def test_init_with_none_plugins(self, mock_context):
        phase = ScanPhase(plugin_context=mock_context, plugins=None)
        assert phase.plugins == []

    def test_validation_manager_has_context(self, mock_context):
        phase = ScanPhase(plugin_context=mock_context, plugins=[])
        assert phase.validation_manager.plugin_context == mock_context
