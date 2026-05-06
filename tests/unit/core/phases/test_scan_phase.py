"""Unit tests for ScanPhase execution loop, error handling, and result aggregation."""

from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ExecutionPhase, ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.models.scan_results_container import ScanResultsContainer

# Pydantic forward references need explicit rebuild for models with deferred refs
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_plugin_context(tmp_path):
    """Minimal plugin context stub with required paths."""
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
    return ctx


@pytest.fixture
def mock_progress_display():
    """Stub progress display that records calls."""
    display = MagicMock()
    display.add_task.return_value = 1
    return display


@pytest.fixture
def mock_aggregated_results(tmp_path):
    """Fresh AshAggregatedResults for each test."""
    return AshAggregatedResults()


def _make_scanner_plugin(name="test_scanner", enabled=True, deps_satisfied=True, python_only=True):
    """Factory for scanner plugin mocks."""
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

    plugin_instance.validate_plugin_dependencies.return_value = deps_satisfied
    plugin_instance.dependencies_satisfied = deps_satisfied
    plugin_instance.is_python_only.return_value = python_only
    plugin_instance.errors = []
    plugin_instance.output = []
    plugin_instance.exit_code = 0
    plugin_instance.start_time = datetime(2024, 1, 1, 10, 0, 0)
    plugin_instance.end_time = datetime(2024, 1, 1, 10, 0, 5)
    plugin_instance.context = None

    return plugin_cls, plugin_instance


def _make_scanner_class(name="test_scanner", enabled=True, deps_satisfied=True, python_only=True):
    """Create a callable scanner class mock that returns an instance when called."""
    plugin_cls, plugin_instance = _make_scanner_plugin(name, enabled, deps_satisfied, python_only)
    plugin_cls.return_value = plugin_instance
    plugin_cls.__name__ = name
    return plugin_cls


@pytest.fixture
def scan_phase(mock_plugin_context, mock_progress_display):
    """ScanPhase with mocked dependencies."""
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerValidationManager"
    ) as MockValMgr:
        mock_val_mgr = MagicMock()
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
        mock_val_mgr.validate_result_completeness.return_value = checkpoint
        mock_val_mgr.report_execution_discrepancies.return_value = {}
        MockValMgr.return_value = mock_val_mgr

        phase = ScanPhase(
            plugin_context=mock_plugin_context,
            plugins=[],
            progress_display=mock_progress_display,
        )
        phase.validation_manager = mock_val_mgr
        return phase


# ---------------------------------------------------------------------------
# Tests: Main execution loop (_execute_phase)
# ---------------------------------------------------------------------------


class TestExecutePhaseLoop:
    """Tests for the main _execute_phase method."""

    def test_empty_plugins_returns_results(self, scan_phase, mock_aggregated_results):
        """When no plugins are provided, phase completes with empty results."""
        scan_phase.plugins = []

        result = scan_phase._execute_phase(
            aggregated_results=mock_aggregated_results,
            parallel=False,
        )

        assert isinstance(result, AshAggregatedResults)

    def test_scanner_excluded_via_excluded_scanners_param(
        self, scan_phase, mock_plugin_context, mock_aggregated_results, mock_progress_display
    ):
        """Scanner in excluded_scanners list is marked SKIPPED."""
        scanner_cls = _make_scanner_class("bandit", enabled=True)
        scan_phase.plugins = [scanner_cls]

        result = scan_phase._execute_phase(
            aggregated_results=mock_aggregated_results,
            excluded_scanners=["bandit"],
            parallel=False,
        )

        assert "bandit" in result.scanner_results
        assert result.scanner_results["bandit"].status == ScannerStatus.SKIPPED
        assert result.scanner_results["bandit"].excluded is True

    def test_scanner_missing_dependencies_marked_missing(
        self, scan_phase, mock_plugin_context, mock_aggregated_results
    ):
        """Scanner with unsatisfied deps is marked MISSING."""
        scanner_cls = _make_scanner_class("grype", enabled=True, deps_satisfied=False)
        scan_phase.plugins = [scanner_cls]

        result = scan_phase._execute_phase(
            aggregated_results=mock_aggregated_results,
            parallel=False,
        )

        assert "grype" in result.scanner_results
        assert result.scanner_results["grype"].status == ScannerStatus.MISSING
        assert result.scanner_results["grype"].dependencies_satisfied is False

    def test_scanner_disabled_via_config_is_skipped(
        self, scan_phase, mock_aggregated_results
    ):
        """Scanner with config.enabled=False is excluded."""
        scanner_cls = _make_scanner_class("disabled_scanner", enabled=False)
        scan_phase.plugins = [scanner_cls]

        result = scan_phase._execute_phase(
            aggregated_results=mock_aggregated_results,
            parallel=False,
        )

        assert "disabled_scanner" in result.scanner_results
        assert result.scanner_results["disabled_scanner"].status == ScannerStatus.SKIPPED

    def test_enabled_scanner_filter_narrows_execution(
        self, scan_phase, mock_aggregated_results
    ):
        """Only scanners in enabled_scanners list run."""
        scanner_a = _make_scanner_class("alpha", enabled=True)
        scanner_b = _make_scanner_class("beta", enabled=True)
        scan_phase.plugins = [scanner_a, scanner_b]

        # Mock the execution to prevent actual scanning
        scan_phase._execute_scanners_sequential = MagicMock(return_value=mock_aggregated_results)

        result = scan_phase._execute_phase(
            aggregated_results=mock_aggregated_results,
            enabled_scanners=["alpha"],
            parallel=False,
        )

        # beta should be excluded because it's not in the enabled_scanners list
        assert "beta" in result.scanner_results
        assert result.scanner_results["beta"].status == ScannerStatus.SKIPPED

    def test_python_based_plugins_only_filter(
        self, scan_phase, mock_aggregated_results
    ):
        """python_based_plugins_only=True excludes non-python scanners."""
        py_scanner = _make_scanner_class("pyscan", enabled=True, python_only=True)
        shell_scanner = _make_scanner_class("shellscan", enabled=True, python_only=False)
        scan_phase.plugins = [py_scanner, shell_scanner]

        scan_phase._execute_scanners_sequential = MagicMock(return_value=mock_aggregated_results)

        result = scan_phase._execute_phase(
            aggregated_results=mock_aggregated_results,
            python_based_plugins_only=True,
            parallel=False,
        )

        assert "shellscan" in result.scanner_results
        assert result.scanner_results["shellscan"].status == ScannerStatus.SKIPPED


# ---------------------------------------------------------------------------
# Tests: Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Tests for error handling paths."""

    def test_execute_phase_propagates_exception(self, scan_phase, mock_aggregated_results):
        """Unhandled exceptions in _execute_phase are re-raised."""
        scan_phase.plugins = []
        # Force an error by making progress_display.add_task raise
        scan_phase.progress_display.add_task.side_effect = RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            scan_phase._execute_phase(
                aggregated_results=mock_aggregated_results,
                parallel=False,
            )

    def test_scanner_instantiation_failure_continues(
        self, scan_phase, mock_aggregated_results
    ):
        """If a scanner class raises during instantiation, other scanners still run."""
        bad_cls = MagicMock()
        bad_cls.__name__ = "bad_scanner"
        bad_cls.side_effect = TypeError("cannot init")

        good_cls = _make_scanner_class("good_scanner", enabled=True)
        scan_phase.plugins = [bad_cls, good_cls]

        scan_phase._execute_scanners_sequential = MagicMock(return_value=mock_aggregated_results)

        # Should not raise, just log the error and continue
        result = scan_phase._execute_phase(
            aggregated_results=mock_aggregated_results,
            parallel=False,
        )
        assert isinstance(result, AshAggregatedResults)

    def test_safe_execute_scanner_catches_exceptions(self, scan_phase):
        """_safe_execute_scanner wraps exceptions into failure containers."""
        scanner_plugin = MagicMock()
        scanner_plugin.__class__.__name__ = "exploder"
        scanner_plugin.config.name = "exploder"

        # Initialize state that _execute_scanner expects
        scan_phase._completed_scanners = []

        # Make _execute_scanner raise
        scan_phase._execute_scanner = MagicMock(side_effect=RuntimeError("scanner crash"))

        results = scan_phase._safe_execute_scanner(
            scanner_name="exploder",
            scanner_plugin=scanner_plugin,
            scan_targets=[{"path": Path("/tmp"), "type": "source"}],  # nosec B108
        )

        assert len(results) == 1
        assert results[0].status == ScannerStatus.FAILED
        assert "scanner crash" in str(results[0].raw_results)

    def test_sequential_scanner_failure_continues_others(
        self, scan_phase, mock_aggregated_results
    ):
        """In sequential mode, one scanner failing does not stop subsequent scanners."""
        scan_phase._scanner_tasks = [
            ("failing_scanner", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
            ("passing_scanner", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
        ]

        call_order = []

        def side_effect_fn(scanner_name, scanner_plugin, scan_targets):
            call_order.append(scanner_name)
            if scanner_name == "failing_scanner":
                raise RuntimeError("fail")
            return [ScanResultsContainer(scanner_name=scanner_name, status=ScannerStatus.PASSED)]

        scan_phase._safe_execute_scanner = side_effect_fn
        scan_phase._process_results = MagicMock(return_value=mock_aggregated_results)

        result = scan_phase._execute_scanners_sequential(
            aggregated_results=mock_aggregated_results
        )

        # Both scanners should have been attempted
        assert len(call_order) == 2


# ---------------------------------------------------------------------------
# Tests: Progress tracking
# ---------------------------------------------------------------------------


class TestProgressTracking:
    """Tests for progress display interactions."""

    def test_progress_initialized_during_execution(
        self, scan_phase, mock_aggregated_results, mock_progress_display
    ):
        """Progress display receives add_task and update_task calls."""
        scan_phase.plugins = []

        scan_phase._execute_phase(
            aggregated_results=mock_aggregated_results,
            parallel=False,
        )

        mock_progress_display.add_task.assert_called()
        mock_progress_display.update_task.assert_called()

    def test_sequential_scanner_creates_per_scanner_task(
        self, scan_phase, mock_aggregated_results, mock_progress_display
    ):
        """Each scanner gets its own progress task in sequential mode."""
        scan_phase._scanner_tasks = [
            ("scanner_a", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
            ("scanner_b", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
        ]
        scan_phase._safe_execute_scanner = MagicMock(
            return_value=[ScanResultsContainer(scanner_name="x", status=ScannerStatus.PASSED)]
        )
        scan_phase._process_results = MagicMock(return_value=mock_aggregated_results)

        scan_phase._execute_scanners_sequential(aggregated_results=mock_aggregated_results)

        # add_task called once per scanner
        assert mock_progress_display.add_task.call_count >= 2

    def test_completed_scanners_count_in_progress(
        self, scan_phase, mock_aggregated_results
    ):
        """After execution, the final progress update reflects completed scanner count."""
        scan_phase.plugins = []

        scan_phase._execute_phase(
            aggregated_results=mock_aggregated_results,
            parallel=False,
        )

        # The final update_progress should mention 0 scanners executed (no plugins)
        calls = [str(c) for c in scan_phase.progress_display.update_task.call_args_list]
        # Check that 100% progress was reached
        final_calls = [c for c in calls if "100" in c]
        assert len(final_calls) > 0


# ---------------------------------------------------------------------------
# Tests: Scanner execution (_execute_scanner)
# ---------------------------------------------------------------------------


class TestExecuteScanner:
    """Tests for _execute_scanner single-scanner execution."""

    def test_successful_scan_returns_container_list(self, scan_phase):
        """A scanner that returns a dict result produces a container list."""
        _, plugin = _make_scanner_plugin("trivy")
        plugin.scan.return_value = {
            "status": "success",
            "severity_counts": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
        }

        scan_phase._global_ignore_paths = []
        scan_phase._completed_scanners = []
        scan_phase.plugin_context.output_dir = Path("/tmp/out")  # nosec B108

        results = scan_phase._execute_scanner(
            scanner_name="trivy",
            scanner_plugin=plugin,
            scan_targets=[{"path": scan_phase.plugin_context.source_dir, "type": "source"}],
        )

        assert len(results) == 1
        assert results[0].scanner_name == "trivy"
        assert results[0].severity_counts["critical"] == 1
        assert results[0].severity_counts["high"] == 2

    def test_scanner_exception_produces_error_container(self, scan_phase):
        """If scan() raises, result contains error info."""
        _, plugin = _make_scanner_plugin("broken")
        plugin.scan.side_effect = OSError("disk full")

        scan_phase._global_ignore_paths = []
        scan_phase._completed_scanners = []

        results = scan_phase._execute_scanner(
            scanner_name="broken",
            scanner_plugin=plugin,
            scan_targets=[{"path": scan_phase.plugin_context.source_dir, "type": "source"}],
        )

        assert len(results) == 1
        assert results[0].status == ScannerStatus.ERROR

    def test_scanner_skips_nonexistent_target(self, scan_phase, tmp_path):
        """Targets that don't exist are skipped silently."""
        _, plugin = _make_scanner_plugin("checker")

        scan_phase._global_ignore_paths = []
        scan_phase._completed_scanners = []

        results = scan_phase._execute_scanner(
            scanner_name="checker",
            scanner_plugin=plugin,
            scan_targets=[{"path": tmp_path / "nonexistent", "type": "source"}],
        )

        # No container produced for non-existent path
        assert len(results) == 0
        plugin.scan.assert_not_called()

    def test_scanner_duration_calculated(self, scan_phase):
        """Duration is computed from start_time and end_time."""
        _, plugin = _make_scanner_plugin("timed")
        plugin.start_time = datetime(2024, 6, 1, 12, 0, 0)
        plugin.end_time = datetime(2024, 6, 1, 12, 0, 10)
        plugin.scan.return_value = {"status": "success"}

        scan_phase._global_ignore_paths = []
        scan_phase._completed_scanners = []

        results = scan_phase._execute_scanner(
            scanner_name="timed",
            scanner_plugin=plugin,
            scan_targets=[{"path": scan_phase.plugin_context.source_dir, "type": "source"}],
        )

        assert len(results) == 1
        assert results[0].duration == 10.0

    @pytest.mark.parametrize(
        "severity_counts,threshold,expected_status",
        [
            ({"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}, "HIGH", ScannerStatus.FAILED),
            ({"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}, "HIGH", ScannerStatus.FAILED),
            ({"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}, "HIGH", ScannerStatus.PASSED),
            ({"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}, "MEDIUM", ScannerStatus.FAILED),
            ({"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0}, "LOW", ScannerStatus.FAILED),
            ({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1}, "ALL", ScannerStatus.FAILED),
            ({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "HIGH", ScannerStatus.PASSED),
        ],
    )
    def test_status_determined_by_threshold(
        self, scan_phase, severity_counts, threshold, expected_status
    ):
        """Scanner status is FAILED or PASSED based on severity threshold."""
        _, plugin = _make_scanner_plugin("threshold_test")
        plugin.config.options.severity_threshold = threshold
        plugin.scan.return_value = {"status": "success", "severity_counts": severity_counts}

        scan_phase._global_ignore_paths = []
        scan_phase._completed_scanners = []

        results = scan_phase._execute_scanner(
            scanner_name="threshold_test",
            scanner_plugin=plugin,
            scan_targets=[{"path": scan_phase.plugin_context.source_dir, "type": "source"}],
        )

        assert results[0].status == expected_status


# ---------------------------------------------------------------------------
# Tests: Parallel execution
# ---------------------------------------------------------------------------


class TestParallelExecution:
    """Tests for _execute_scanners_parallel."""

    def test_parallel_falls_back_to_sequential_for_single_scanner(
        self, scan_phase, mock_aggregated_results
    ):
        """With only one scanner task, parallel delegates to sequential."""
        scan_phase._scanner_tasks = [
            ("solo", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
        ]
        scan_phase._max_workers = 4
        scan_phase._execute_scanners_sequential = MagicMock(return_value=mock_aggregated_results)

        result = scan_phase._execute_scanners_parallel(
            aggregated_results=mock_aggregated_results
        )

        scan_phase._execute_scanners_sequential.assert_called_once()

    def test_parallel_submits_multiple_scanners(
        self, scan_phase, mock_aggregated_results
    ):
        """Multiple scanners are submitted to thread pool."""
        scan_phase._scanner_tasks = [
            ("scanner_1", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
            ("scanner_2", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
            ("scanner_3", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
        ]
        scan_phase._max_workers = 2

        # Make _safe_execute_scanner return passing results
        scan_phase._safe_execute_scanner = MagicMock(
            return_value=[ScanResultsContainer(scanner_name="x", status=ScannerStatus.PASSED)]
        )
        scan_phase._process_results = MagicMock(return_value=mock_aggregated_results)

        with patch(
            "automated_security_helper.core.phases.scan_phase.ThreadPoolExecutor"
        ) as MockPool:
            mock_executor = MagicMock()
            MockPool.return_value.__enter__ = MagicMock(return_value=mock_executor)
            MockPool.return_value.__exit__ = MagicMock(return_value=False)

            # Mock futures
            mock_future = MagicMock()
            mock_future.result.return_value = [
                ScanResultsContainer(scanner_name="x", status=ScannerStatus.PASSED)
            ]
            mock_future.scanner_info = {"name": "scanner_1", "task_key": "scanner_1_task"}
            mock_executor.submit.return_value = mock_future

            with patch(
                "automated_security_helper.core.phases.scan_phase.as_completed",
                return_value=[mock_future, mock_future, mock_future],
            ):
                result = scan_phase._execute_scanners_parallel(
                    aggregated_results=mock_aggregated_results
                )

            # ThreadPoolExecutor should be called with max_workers
            MockPool.assert_called_once_with(max_workers=2)

    def test_parallel_handles_future_exception(
        self, scan_phase, mock_aggregated_results
    ):
        """Exceptions from futures are caught and create failure containers."""
        scan_phase._scanner_tasks = [
            ("crash_scan", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
            ("good_scan", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
        ]
        scan_phase._max_workers = 2
        scan_phase._process_results = MagicMock(return_value=mock_aggregated_results)

        with patch(
            "automated_security_helper.core.phases.scan_phase.ThreadPoolExecutor"
        ) as MockPool:
            mock_executor = MagicMock()
            MockPool.return_value.__enter__ = MagicMock(return_value=mock_executor)
            MockPool.return_value.__exit__ = MagicMock(return_value=False)

            failing_future = MagicMock()
            failing_future.result.side_effect = RuntimeError("thread crash")
            failing_future.scanner_info = {"name": "crash_scan", "task_key": "crash_scan_task"}

            passing_future = MagicMock()
            passing_future.result.return_value = [
                ScanResultsContainer(scanner_name="good_scan", status=ScannerStatus.PASSED)
            ]
            passing_future.scanner_info = {"name": "good_scan", "task_key": "good_scan_task"}

            mock_executor.submit.side_effect = [failing_future, passing_future]

            with patch(
                "automated_security_helper.core.phases.scan_phase.as_completed",
                return_value=[failing_future, passing_future],
            ):
                result = scan_phase._execute_scanners_parallel(
                    aggregated_results=mock_aggregated_results
                )

            # _process_results should have been called for both failure and success
            assert scan_phase._process_results.call_count >= 2


# ---------------------------------------------------------------------------
# Tests: Result aggregation (_process_results)
# ---------------------------------------------------------------------------


class TestProcessResults:
    """Tests for _process_results."""

    def test_sarif_results_merged_into_aggregated(
        self, scan_phase, mock_aggregated_results
    ):
        """SARIF reports are merged into the aggregated sarif model."""
        from automated_security_helper.schemas.sarif_schema_model import SarifReport

        mock_sarif = MagicMock(spec=SarifReport)
        mock_sarif.runs = [MagicMock()]
        mock_sarif.runs[0].results = []

        # Patch isinstance checks to recognize our mock as SarifReport
        # and bypass model_dump which fails on mocks
        original_process = scan_phase._process_results

        with patch(
            "automated_security_helper.core.phases.scan_phase.sanitize_sarif_paths",
            return_value=mock_sarif,
        ), patch(
            "automated_security_helper.core.phases.scan_phase.apply_suppressions_to_sarif",
            return_value=mock_sarif,
        ):
            mock_sarif.attach_scanner_details = MagicMock()

            # Use a real AshAggregatedResults but mock its sarif attribute
            mock_aggregated_results.sarif = MagicMock()
            mock_aggregated_results.additional_reports = {}

            # Create container with mock sarif -- we need to bypass model_dump
            # by patching the container's serialization
            container = MagicMock()
            container.scanner_name = "sarif_scanner"
            container.target_type = "source"
            container.raw_results = mock_sarif
            container.metadata = {}
            container.start_time = None
            container.end_time = None
            container.duration = None
            container.exit_code = 0
            container.model_dump.return_value = {
                "scanner_name": "sarif_scanner",
                "target_type": "source",
                "status": "passed",
            }

            result = scan_phase._process_results(
                results=container,
                aggregated_results=mock_aggregated_results,
            )

        mock_aggregated_results.sarif.merge_sarif_report.assert_called_once()

    def test_dict_results_stored_in_additional_reports(
        self, scan_phase, mock_aggregated_results
    ):
        """Dictionary raw results go into additional_reports."""
        container = ScanResultsContainer(
            scanner_name="dict_scanner",
            target_type="source",
            raw_results={"custom": "data", "count": 42},
        )

        result = scan_phase._process_results(
            results=container,
            aggregated_results=mock_aggregated_results,
        )

        assert "dict_scanner" in result.additional_reports
        assert "source" in result.additional_reports["dict_scanner"]

    def test_excluded_scanner_container_processed(
        self, scan_phase, mock_aggregated_results
    ):
        """Excluded scanner containers are stored properly."""
        container = ScanResultsContainer(
            scanner_name="excluded_one",
            target_type="source",
            excluded=True,
            status=ScannerStatus.SKIPPED,
            duration=None,
        )

        result = scan_phase._process_results(
            results=container,
            aggregated_results=mock_aggregated_results,
        )

        assert "excluded_one" in result.additional_reports


# ---------------------------------------------------------------------------
# Tests: Phase properties and initialization
# ---------------------------------------------------------------------------


class TestPhaseProperties:
    """Tests for basic phase properties."""

    def test_phase_name_is_scan(self, scan_phase):
        assert scan_phase.phase_name == "scan"

    def test_scanner_tasks_cleaned_up_after_execution(
        self, scan_phase, mock_aggregated_results
    ):
        """_scanner_tasks is reset in the finally block."""
        scan_phase.plugins = []

        scan_phase._execute_phase(
            aggregated_results=mock_aggregated_results,
            parallel=False,
        )

        assert scan_phase._scanner_tasks == []

    def test_scanner_tasks_cleaned_up_on_exception(
        self, scan_phase, mock_aggregated_results
    ):
        """_scanner_tasks is reset even when an exception occurs."""
        scan_phase.plugins = []
        scan_phase.progress_display.add_task.side_effect = ValueError("oops")

        with pytest.raises(ValueError):
            scan_phase._execute_phase(
                aggregated_results=mock_aggregated_results,
                parallel=False,
            )

        assert scan_phase._scanner_tasks == []


# ---------------------------------------------------------------------------
# Tests: Sequential execution details
# ---------------------------------------------------------------------------


class TestSequentialExecution:
    """Tests for _execute_scanners_sequential behavior."""

    def test_none_results_creates_failure_container(
        self, scan_phase, mock_aggregated_results
    ):
        """When _safe_execute_scanner returns None, a failure container is created."""
        scan_phase._scanner_tasks = [
            ("none_scanner", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
        ]
        scan_phase._safe_execute_scanner = MagicMock(return_value=None)
        scan_phase._process_results = MagicMock(return_value=mock_aggregated_results)

        result = scan_phase._execute_scanners_sequential(
            aggregated_results=mock_aggregated_results
        )

        # _process_results should have been called with a FAILED container
        call_args = scan_phase._process_results.call_args
        container = call_args[1]["results"] if "results" in call_args[1] else call_args[0][0]
        assert container.status == ScannerStatus.FAILED

    def test_completed_count_increments_for_each_scanner(
        self, scan_phase, mock_aggregated_results
    ):
        """completed counter advances regardless of success/failure."""
        scan_phase._scanner_tasks = [
            ("s1", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
            ("s2", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
            ("s3", MagicMock(), [{"path": Path("/tmp"), "type": "source"}]),  # nosec B108
        ]

        call_order = []

        def mock_safe_exec(scanner_name, scanner_plugin, scan_targets):
            call_order.append(scanner_name)
            if scanner_name == "s2":
                raise RuntimeError("s2 failed")
            return [ScanResultsContainer(scanner_name=scanner_name, status=ScannerStatus.PASSED)]

        scan_phase._safe_execute_scanner = mock_safe_exec
        scan_phase._process_results = MagicMock(return_value=mock_aggregated_results)

        scan_phase._execute_scanners_sequential(aggregated_results=mock_aggregated_results)

        # All three scanners should have been attempted
        assert call_order == ["s1", "s2", "s3"]


# ---------------------------------------------------------------------------
# Tests: Metrics extraction
# ---------------------------------------------------------------------------


class TestMetricsExtraction:
    """Tests for _extract_metrics_from_sarif."""

    def test_extract_metrics_returns_counts_and_total(self, scan_phase):
        """Metrics extraction returns severity dict and total count."""
        with patch(
            "automated_security_helper.core.phases.scan_phase.get_severity_metrics_from_sarif"
        ) as mock_get:
            mock_metrics = MagicMock()
            mock_metrics.suppressed = 2
            mock_metrics.critical = 1
            mock_metrics.high = 3
            mock_metrics.medium = 5
            mock_metrics.low = 2
            mock_metrics.info = 1
            mock_get.return_value = mock_metrics

            mock_sarif = MagicMock()
            severity_counts, total = scan_phase._extract_metrics_from_sarif(mock_sarif)

            assert severity_counts["critical"] == 1
            assert severity_counts["high"] == 3
            assert severity_counts["medium"] == 5
            assert total == 14  # 1+3+5+2+1+2


# ---------------------------------------------------------------------------
# Tests: Work directory inclusion
# ---------------------------------------------------------------------------


class TestWorkDirHandling:
    """Tests for work directory file inclusion logic."""

    def test_work_dir_included_when_has_files(
        self, scan_phase, mock_plugin_context, mock_aggregated_results
    ):
        """Work dir files are included in source_files when work_dir has content."""
        # Add a file to work_dir
        work_file = mock_plugin_context.work_dir / "converted.tf"
        work_file.write_text("resource {}")

        scanner_cls = _make_scanner_class("tf_scan", enabled=True)
        scan_phase.plugins = [scanner_cls]
        scan_phase._execute_scanners_sequential = MagicMock(return_value=mock_aggregated_results)

        scan_phase._execute_phase(
            aggregated_results=mock_aggregated_results,
            parallel=False,
        )

        # Scanner tasks should include work_dir targets
        if scan_phase._scanner_tasks:
            # At least one task should have a "converted" type target
            pass  # Tasks are cleared in finally, but _include_work_dir should be True
        assert scan_phase._include_work_dir is True

    def test_work_dir_excluded_when_empty(
        self, scan_phase, mock_plugin_context, mock_aggregated_results
    ):
        """Empty work_dir results in _include_work_dir=False."""
        scan_phase.plugins = []

        scan_phase._execute_phase(
            aggregated_results=mock_aggregated_results,
            parallel=False,
        )

        assert scan_phase._include_work_dir is False
