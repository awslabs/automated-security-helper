"""Tests for core/orchestrator.py — covers ASHScanOrchestrator initialization and configuration."""

from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.core.enums import ExecutionStrategy, ExportFormat
from automated_security_helper.config.ash_config import AshConfig


class TestOrchestratorInit:
    """Tests for ASHScanOrchestrator initialization."""

    def test_default_construction(self, tmp_path):
        """Test that orchestrator can be constructed with minimal args."""
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        output.mkdir()

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ), patch(
            "automated_security_helper.core.orchestrator.scan_set",
            return_value=set(),
        ):
            orch = ASHScanOrchestrator(
                source_dir=source,
                output_dir=output,
                config_path=None,
                config_overrides=None,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )
            assert orch.source_dir == source
            assert orch.output_dir == output
            assert orch.strategy == ExecutionStrategy.PARALLEL

    def test_strategy_sequential(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        output.mkdir()

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ), patch(
            "automated_security_helper.core.orchestrator.scan_set",
            return_value=set(),
        ):
            orch = ASHScanOrchestrator(
                source_dir=source,
                output_dir=output,
                strategy=ExecutionStrategy.SEQUENTIAL,
                config_path=None,
                config_overrides=None,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )
            assert orch.strategy == ExecutionStrategy.SEQUENTIAL

    def test_enabled_scanners(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        output.mkdir()

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ), patch(
            "automated_security_helper.core.orchestrator.scan_set",
            return_value=set(),
        ):
            orch = ASHScanOrchestrator(
                source_dir=source,
                output_dir=output,
                enabled_scanners=["bandit", "checkov"],
                config_path=None,
                config_overrides=None,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )
            assert orch.enabled_scanners == ["bandit", "checkov"]

    def test_excluded_scanners(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        output.mkdir()

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ), patch(
            "automated_security_helper.core.orchestrator.scan_set",
            return_value=set(),
        ):
            orch = ASHScanOrchestrator(
                source_dir=source,
                output_dir=output,
                excluded_scanners=["cfn-nag"],
                config_path=None,
                config_overrides=None,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )
            assert orch.excluded_scanners == ["cfn-nag"]

    def test_offline_mode(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        output.mkdir()

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ), patch(
            "automated_security_helper.core.orchestrator.scan_set",
            return_value=set(),
        ):
            orch = ASHScanOrchestrator(
                source_dir=source,
                output_dir=output,
                offline=True,
                config_path=None,
                config_overrides=None,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )
            assert orch.offline is True

    def test_python_based_plugins_only(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        output.mkdir()

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ), patch(
            "automated_security_helper.core.orchestrator.scan_set",
            return_value=set(),
        ):
            orch = ASHScanOrchestrator(
                source_dir=source,
                output_dir=output,
                python_based_plugins_only=True,
                config_path=None,
                config_overrides=None,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )
            assert orch.python_based_plugins_only is True
