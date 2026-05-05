"""Tests for core/execution_engine.py — covers ScanExecutionEngine initialization."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ExecutionStrategy


@pytest.fixture
def engine_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()

    ctx = PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )
    return ctx


class TestScanExecutionEngineInit:
    """Tests for ScanExecutionEngine initialization."""

    def test_basic_construction(self, engine_context):
        engine = ScanExecutionEngine(
            context=engine_context,
            show_progress=False,
        )
        assert engine is not None

    def test_with_enabled_scanners(self, engine_context):
        engine = ScanExecutionEngine(
            context=engine_context,
            enabled_scanners=["bandit", "checkov"],
            show_progress=False,
        )
        assert engine is not None

    def test_with_excluded_scanners(self, engine_context):
        engine = ScanExecutionEngine(
            context=engine_context,
            excluded_scanners=["cfn-nag"],
            show_progress=False,
        )
        assert engine is not None

    def test_sequential_strategy(self, engine_context):
        engine = ScanExecutionEngine(
            context=engine_context,
            strategy=ExecutionStrategy.SEQUENTIAL,
            show_progress=False,
        )
        assert engine is not None

    def test_python_based_plugins_only(self, engine_context):
        engine = ScanExecutionEngine(
            context=engine_context,
            python_based_plugins_only=True,
            show_progress=False,
        )
        assert engine is not None

    def test_simple_mode(self, engine_context):
        engine = ScanExecutionEngine(
            context=engine_context,
            simple_mode=True,
            show_progress=False,
        )
        assert engine is not None
