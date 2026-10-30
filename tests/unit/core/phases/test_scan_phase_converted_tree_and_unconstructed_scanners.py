# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan phase's preparation steps record what happened instead of guessing or aborting.

Five preparation defects, each pinned by one test that is red on the tree that
carried it:

* The converted tree was scanned only when some name under ``work_dir``
  contained a dot (``rglob("*.*")``), so an archive whose extracted members
  carry no extension was converted and never scanned.
* The source-tree walk called ``Path.is_file`` on every entry outside any
  guard, so one symlink whose target cannot be stat'ed aborted the scan.
* A scanner whose constructor raised was recorded ERROR even when the operator
  excluded it, or the configuration disabled it, so the completeness gate
  failed a run that ran everything it selected.
* The scanner tracker refuses a name that is empty or ends in "Scanner" with a
  ValueError, which escaped the phase and aborted the whole scan for one plugin.
* The built-in plugin package failing to import was recorded under a key with
  no scanner-region marker and resolved no built-in class, so no roster was
  recorded and the loss passed every completeness check.

The fixtures mirror ``tests/unit/core/phases/test_phases_scan_phase.py``.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import (
    _BUILTIN_PLUGIN_MODULE_PREFIX,
    ScanPhase,
)
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


@pytest.fixture
def mock_progress_display():
    display = MagicMock()
    display.add_task.return_value = 1
    return display


def _make_scanner_class(name: str, enabled: bool = True):
    plugin_cls = MagicMock()
    plugin_cls.__name__ = name

    plugin_instance = MagicMock()
    plugin_instance.__class__ = plugin_cls
    plugin_instance.__class__.__name__ = name
    config = MagicMock()
    config.name = name
    config.enabled = enabled
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
    return plugin_cls


@pytest.fixture
def scan_phase(mock_plugin_context, mock_progress_display):
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
            plugin_context=mock_plugin_context,
            plugins=[],
            progress_display=mock_progress_display,
        )
        phase.validation_manager = mock_val_mgr
        return phase


class TestTheConvertedTreeIsScannedWhateverItsNames:
    def test_a_converted_tree_of_extensionless_files_is_scanned(
        self, scan_phase, mock_plugin_context
    ):
        # An archive of extensionless members: no name under work_dir has a dot.
        extracted = mock_plugin_context.work_dir / "bundle" / "Dockerfile"
        extracted.parent.mkdir()
        extracted.write_text("FROM scratch\n")

        scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        # Red at the base: rglob("*.*") found no dotted name, so False.
        assert scan_phase._include_work_dir is True
        assert str(extracted) in mock_plugin_context.cached_source_files

    def test_an_empty_converted_tree_is_still_left_out(
        self, scan_phase, mock_plugin_context
    ):
        """The control: nothing under work_dir means nothing to scan there."""
        scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )
        assert scan_phase._include_work_dir is False


class TestAnUnstatableEntryDoesNotAbortTheScan:
    def test_a_denied_stat_in_the_source_walk_is_skipped(
        self, scan_phase, mock_plugin_context, monkeypatch
    ):
        denied = mock_plugin_context.source_dir / "denied-target"
        denied.write_text("x")
        original_is_file = Path.is_file
        refusals = {"count": 0}

        # The stub keeps Path.is_file's signature (follow_symlinks on 3.12+), so
        # a caller passing it reaches the stub instead of a TypeError.
        def is_file_or_denied(self: Path, *args, **kwargs) -> bool:
            if self.name == "denied-target":
                refusals["count"] += 1
                raise PermissionError(13, "Permission denied", str(self))
            return original_is_file(self, *args, **kwargs)

        monkeypatch.setattr(Path, "is_file", is_file_or_denied)

        # Red at the base: the PermissionError escaped the walk.
        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        # The walk reached the refused entry: otherwise the assertions below hold
        # for a walk that never stat'ed it, and the test measures nothing.
        assert refusals["count"] >= 1, "the source walk never stat'ed denied-target"
        assert isinstance(results, AshAggregatedResults)
        cached = mock_plugin_context.cached_source_files
        assert str(mock_plugin_context.source_dir / "app.py") in cached
        assert str(denied) not in cached


class TestAnUnconstructedScannerIsRecordedByItsSelection:
    def test_an_excluded_scanner_whose_constructor_raises_is_skipped(self, scan_phase):
        boom = MagicMock(side_effect=RuntimeError("constructor failed"))
        boom.__name__ = "boom_scanner"
        scan_phase.plugins = [boom]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            excluded_scanners=["boom_scanner"],
            parallel=False,
        )

        row = results.scanner_results["boom_scanner"]
        # Red at the base: ERROR, excluded False.
        assert row.status == ScannerStatus.SKIPPED
        assert row.excluded is True

    def test_a_disabled_scanner_whose_constructor_raises_is_skipped(
        self, scan_phase, mock_plugin_context
    ):
        mock_plugin_context.config.get_plugin_config.return_value = {
            "name": "off_scanner",
            "enabled": False,
        }
        boom = MagicMock(side_effect=RuntimeError("constructor failed"))
        boom.__name__ = "off_scanner"
        scan_phase.plugins = [boom]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        row = results.scanner_results["off_scanner"]
        assert row.status == ScannerStatus.SKIPPED
        assert row.excluded is True

    def test_a_selected_scanner_whose_constructor_raises_is_still_an_error(
        self, scan_phase
    ):
        """The control: selected and unconstructed is the failure it always was."""
        boom = MagicMock(side_effect=RuntimeError("constructor failed"))
        boom.__name__ = "boom_scanner"
        scan_phase.plugins = [boom]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        row = results.scanner_results["boom_scanner"]
        assert row.status == ScannerStatus.ERROR
        assert row.excluded is False


class TestATrackerRefusedNameDoesNotAbortTheScan:
    def test_the_refused_scanner_is_recorded_error_and_the_others_go_on(
        self, scan_phase
    ):
        def refuse_class_shaped_names(scanner_name, **_state):
            if scanner_name == "FooScanner":
                raise ValueError("Scanner name looks like a class name: 'FooScanner'")

        scan_phase.validation_manager.update_scanner_state.side_effect = (
            refuse_class_shaped_names
        )
        scan_phase.plugins = [
            _make_scanner_class("FooScanner"),
            _make_scanner_class("bandit"),
        ]

        # Red at the base: the ValueError escaped the registration loop.
        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            excluded_scanners=["bandit"],
            parallel=False,
        )

        assert results.scanner_results["FooScanner"].status == ScannerStatus.ERROR
        assert results.scanner_results["FooScanner"].excluded is False
        # The other scanner was processed (here: recorded as the exclusion asked).
        assert results.scanner_results["bandit"].status == ScannerStatus.SKIPPED


class TestALostBuiltinPackageIsLoud:
    def test_the_roster_and_an_error_row_are_recorded(
        self, scan_phase, mock_plugin_context
    ):
        # A real config, for the declared roster; no built-in class resolved.
        mock_plugin_context.config = AshConfig()
        failure = MagicMock()
        failure.recorded = "ModuleNotFoundError: No module named 'yaml'"
        mock_plugin_context.plugin_load_record = {
            _BUILTIN_PLUGIN_MODULE_PREFIX: failure
        }
        scan_phase.plugins = []

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        # Red at the base: no row (the key has no ".scanners" marker) and no
        # roster (no class from the built-in package was handed to the phase).
        row = results.scanner_results[_BUILTIN_PLUGIN_MODULE_PREFIX]
        assert row.status == ScannerStatus.ERROR
        # The roster is the config's declared scanners under the names their rows
        # carry (the field alias, "detect-secrets"), not just any non-empty list.
        assert "bandit" in results.metadata.expected_scanners
        assert "detect-secrets" in results.metadata.expected_scanners
