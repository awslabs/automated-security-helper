# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner whose own check raises is a failure, and the scan phase writes no results file.

* Under ``--python-only``, a selected scanner whose ``is_python_only`` raised was
  dropped by the shared filter like an excluded one and recorded SKIPPED as not
  Python-only, invisible to the completeness gate. It is recorded ERROR.
* The scan phase wrote ash_aggregated_results.json at its own end, before the
  engine's changed-files narrowing, final suppression pass, metrics rebuild and
  report phase; the MCP progress tracker reads the file's existence as the scan
  being complete. The orchestrator writes it once every phase has run, and the
  phase writes nothing.

The fixtures mirror ``tests/unit/core/phases/test_phases_scan_phase.py``.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


@pytest.fixture
def mock_plugin_context(tmp_path):
    ctx = MagicMock()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('hello')")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    ctx.source_dir = source_dir
    ctx.work_dir = work_dir
    ctx.output_dir = output_dir
    ctx.config = MagicMock()
    ctx.config.get_plugin_config.return_value = None
    ctx.config.global_settings.ignore_paths = []
    ctx.ignore_suppressions = False
    ctx.cached_source_files = []
    ctx.plugin_load_record = {}
    return ctx


def _make_scanner_class(name: str):
    plugin_cls = MagicMock()
    plugin_cls.__name__ = name
    plugin_instance = MagicMock()
    plugin_instance.__class__ = plugin_cls
    plugin_instance.__class__.__name__ = name
    config = MagicMock()
    config.name = name
    config.enabled = True
    config.options.severity_threshold = "HIGH"
    plugin_instance.config = config
    plugin_instance.validate_plugin_dependencies.return_value = True
    plugin_instance.dependencies_satisfied = True
    plugin_instance.is_python_only.return_value = True
    plugin_instance.errors = []
    plugin_instance.output = []
    plugin_instance.exit_code = 0
    plugin_instance.start_time = datetime(2024, 1, 1, 10, 0, 0)
    plugin_instance.end_time = datetime(2024, 1, 1, 10, 0, 5)
    plugin_instance.context = None
    plugin_cls.return_value = plugin_instance
    return plugin_cls, plugin_instance


@pytest.fixture
def scan_phase(mock_plugin_context):
    display = MagicMock()
    display.add_task.return_value = 1
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerValidationManager"
    ) as MockValMgr:
        mock_val_mgr = MagicMock(spec=ScannerValidationManager)
        mock_val_mgr.validate_registered_scanners.return_value = None
        mock_val_mgr.validate_scanner_enablement.return_value = None
        checkpoint = MagicMock()
        checkpoint.get_missing_scanners.return_value = []
        checkpoint.get_unexpected_scanners.return_value = []
        checkpoint.has_issues.return_value = False
        checkpoint.checkpoint_name = "test"
        checkpoint.timestamp = datetime(2024, 1, 1)
        checkpoint.expected_scanners = []
        checkpoint.actual_scanners = []
        checkpoint.discrepancies = []
        checkpoint.errors = []
        checkpoint.metadata = {}
        mock_val_mgr.validate_task_queue.return_value = checkpoint
        mock_val_mgr.validate_execution_completion.return_value = checkpoint
        mock_val_mgr.ensure_complete_results.return_value = checkpoint
        mock_val_mgr.report_execution_discrepancies.return_value = {}
        mock_val_mgr.report_result_completeness.return_value = {}
        MockValMgr.return_value = mock_val_mgr
        phase = ScanPhase(
            plugin_context=mock_plugin_context, plugins=[], progress_display=display
        )
        phase.validation_manager = mock_val_mgr
        return phase


class TestARaisingPythonOnlyCheckIsAFailure:
    def test_the_scanner_is_recorded_error_not_skipped(self, scan_phase):
        plugin_cls, plugin_instance = _make_scanner_class("flaky")
        plugin_instance.is_python_only.side_effect = RuntimeError("cannot tell")
        scan_phase.plugins = [plugin_cls]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            python_based_plugins_only=True,
            parallel=False,
        )

        row = results.scanner_results["flaky"]
        # Red at the base: SKIPPED, excluded, "not a Python-only scanner".
        assert row.status == ScannerStatus.ERROR
        assert row.excluded is False

    def test_a_scanner_that_is_not_python_only_is_still_skipped(self, scan_phase):
        """The control: an answered check that says no is the exclusion it was."""
        plugin_cls, plugin_instance = _make_scanner_class("native")
        plugin_instance.is_python_only.return_value = False
        scan_phase.plugins = [plugin_cls]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            python_based_plugins_only=True,
            parallel=False,
        )

        row = results.scanner_results["native"]
        assert row.status == ScannerStatus.SKIPPED
        assert row.excluded is True


class TestTheScanPhaseWritesNoResultsFile:
    def test_nothing_is_written_at_the_phases_end(
        self, scan_phase, mock_plugin_context
    ):
        scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        # Red at the base: the phase saved the model here.
        assert not (
            mock_plugin_context.output_dir / "ash_aggregated_results.json"
        ).exists()
