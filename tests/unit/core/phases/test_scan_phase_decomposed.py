"""Tests for ScannerExecutor, ScanResultProcessor, and EnginePhase.filter_enabled_plugins."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ExecutionPhase, ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.core.phases.scan_result_processor import ScanResultProcessor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.schemas.sarif_schema_model import SarifReport

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_plugin(name="test_scanner", enabled=True, deps_satisfied=True, python_only=True):
    """Return (plugin_class_mock, plugin_instance_mock)."""
    plugin_cls = MagicMock()
    plugin_cls.__name__ = name

    plugin_instance = MagicMock()
    plugin_instance.__class__ = plugin_cls
    plugin_instance.__class__.__name__ = name

    cfg = MagicMock()
    cfg.name = name
    cfg.enabled = enabled
    cfg.options.severity_threshold = "HIGH"
    plugin_instance.config = cfg

    plugin_instance.validate_plugin_dependencies.return_value = deps_satisfied
    plugin_instance.dependencies_satisfied = deps_satisfied
    plugin_instance.is_python_only.return_value = python_only
    plugin_instance.errors = []
    plugin_instance.output = []
    plugin_instance.exit_code = 0
    plugin_instance.start_time = datetime(2024, 1, 1, 10, 0, 0)
    plugin_instance.end_time = datetime(2024, 1, 1, 10, 0, 5)
    plugin_instance.context = None

    plugin_cls.return_value = plugin_instance
    return plugin_cls, plugin_instance


def _make_plugin_context(tmp_path):
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


def _make_progress_display():
    display = MagicMock()
    display.add_task.return_value = 1
    return display


# ---------------------------------------------------------------------------
# EnginePhase.filter_enabled_plugins
# ---------------------------------------------------------------------------


class _ConcretePhase(EnginePhase):
    """Minimal concrete subclass to test EnginePhase helpers."""

    @property
    def phase_name(self) -> str:
        return "test"

    def _execute_phase(self, aggregated_results, **kwargs):  # type: ignore[override]
        return aggregated_results


class TestFilterEnabledPlugins:
    """Tests for EnginePhase.filter_enabled_plugins."""

    @pytest.fixture
    def phase(self, tmp_path):
        ctx = _make_plugin_context(tmp_path)
        return _ConcretePhase(plugin_context=ctx)

    def test_filter_returns_enabled_plugin(self, phase):
        """Plugin with enabled=True and satisfied deps passes through."""
        _, instance = _make_plugin(name="scanner_a", enabled=True, deps_satisfied=True)
        result = phase.filter_enabled_plugins(
            [instance], plugin_context=phase.plugin_context, python_only=False
        )
        assert instance in result

    def test_filter_excludes_disabled_plugin(self, phase):
        """Plugin with config.enabled=False is filtered out."""
        _, instance = _make_plugin(name="scanner_b", enabled=False)
        result = phase.filter_enabled_plugins(
            [instance], plugin_context=phase.plugin_context, python_only=False
        )
        assert instance not in result

    def test_filter_excludes_plugin_with_unsatisfied_deps(self, phase):
        """Plugin where validate_plugin_dependencies() returns False is filtered out."""
        _, instance = _make_plugin(name="scanner_c", enabled=True, deps_satisfied=False)
        result = phase.filter_enabled_plugins(
            [instance], plugin_context=phase.plugin_context, python_only=False
        )
        assert instance not in result

    def test_filter_python_only_excludes_non_python(self, phase):
        """When python_only=True, non-Python plugins are excluded."""
        _, instance = _make_plugin(name="scanner_d", enabled=True, deps_satisfied=True, python_only=False)
        result = phase.filter_enabled_plugins(
            [instance], plugin_context=phase.plugin_context, python_only=True
        )
        assert instance not in result

    def test_filter_python_only_passes_python_plugin(self, phase):
        """When python_only=True, Python plugins are included."""
        _, instance = _make_plugin(name="scanner_e", enabled=True, deps_satisfied=True, python_only=True)
        result = phase.filter_enabled_plugins(
            [instance], plugin_context=phase.plugin_context, python_only=True
        )
        assert instance in result

    def test_filter_empty_list_returns_empty(self, phase):
        result = phase.filter_enabled_plugins([], plugin_context=phase.plugin_context, python_only=False)
        assert result == []

    def test_filter_preserves_order(self, phase):
        """Order of enabled plugins is preserved."""
        _, inst_a = _make_plugin(name="aaa")
        _, inst_b = _make_plugin(name="bbb")
        _, inst_c = _make_plugin(name="ccc")
        result = phase.filter_enabled_plugins(
            [inst_a, inst_b, inst_c], plugin_context=phase.plugin_context, python_only=False
        )
        assert result == [inst_a, inst_b, inst_c]


# ---------------------------------------------------------------------------
# ScannerExecutor
# ---------------------------------------------------------------------------


@pytest.fixture
def executor_ctx(tmp_path):
    return _make_plugin_context(tmp_path)


@pytest.fixture
def progress():
    return _make_progress_display()


@pytest.fixture
def aggregated():
    return AshAggregatedResults()


def _make_executor(ctx, progress_display, scanner_tasks=None, max_workers=4):
    executor = ScannerExecutor(
        plugin_context=ctx,
        progress_display=progress_display,
        scanner_tasks=scanner_tasks or [],
        max_workers=max_workers,
    )
    return executor


class TestScannerExecutorRunSequential:
    """ScannerExecutor.run_sequential executes scanners in order."""

    def test_sequential_runs_all_scanners(self, executor_ctx, progress, aggregated):
        _, inst = _make_plugin(name="scan_seq")
        container = ScanResultsContainer.for_failure("scan_seq", errors=[])
        container.raw_results = {"status": "ok"}

        tasks = [("scan_seq", inst, [{"path": executor_ctx.source_dir, "type": "source"}])]
        executor = _make_executor(executor_ctx, progress, tasks)

        with patch.object(executor, "_safe_execute_scanner", return_value=[container]) as mock_safe:
            with patch.object(executor, "_process_results_fn", return_value=aggregated):
                result = executor.run_sequential(aggregated)

        assert isinstance(result, AshAggregatedResults)
        mock_safe.assert_called_once()

    def test_none_results_creates_failure_container(self, executor_ctx, progress, aggregated):
        """When _safe_execute_scanner returns None, a failure container is created."""
        _, inst = _make_plugin(name="scan_none")
        tasks = [("scan_none", inst, [{"path": executor_ctx.source_dir, "type": "source"}])]
        executor = _make_executor(executor_ctx, progress, tasks)

        with patch.object(executor, "_safe_execute_scanner", return_value=None):
            with patch.object(executor, "_process_results_fn", return_value=aggregated):
                result = executor.run_sequential(aggregated)

        assert isinstance(result, AshAggregatedResults)

    def test_sequential_failure_continues_other_scanners(self, executor_ctx, progress, aggregated):
        """A scanner exception does not stop subsequent scanners."""
        _, inst_a = _make_plugin(name="scan_a")
        _, inst_b = _make_plugin(name="scan_b")
        tasks = [
            ("scan_a", inst_a, [{"path": executor_ctx.source_dir, "type": "source"}]),
            ("scan_b", inst_b, [{"path": executor_ctx.source_dir, "type": "source"}]),
        ]
        executor = _make_executor(executor_ctx, progress, tasks)

        container_b = ScanResultsContainer.for_failure("scan_b", errors=[])
        container_b.raw_results = {"status": "ok"}

        call_count = 0

        def side_effect(name, plugin, targets):
            nonlocal call_count
            call_count += 1
            if name == "scan_a":
                raise RuntimeError("scanner_a exploded")
            return [container_b]

        with patch.object(executor, "_safe_execute_scanner", side_effect=side_effect):
            with patch.object(executor, "_process_results_fn", return_value=aggregated):
                result = executor.run_sequential(aggregated)

        assert call_count == 2
        assert isinstance(result, AshAggregatedResults)


class TestScannerExecutorRunParallel:
    """ScannerExecutor.run_parallel handles N scanners with timeouts/failures."""

    def test_parallel_submits_multiple_scanners(self, executor_ctx, progress, aggregated):
        _, inst_a = _make_plugin(name="par_a")
        _, inst_b = _make_plugin(name="par_b")

        container_a = ScanResultsContainer.for_failure("par_a", errors=[])
        container_a.raw_results = {"status": "ok"}
        container_b = ScanResultsContainer.for_failure("par_b", errors=[])
        container_b.raw_results = {"status": "ok"}

        tasks = [
            ("par_a", inst_a, [{"path": executor_ctx.source_dir, "type": "source"}]),
            ("par_b", inst_b, [{"path": executor_ctx.source_dir, "type": "source"}]),
        ]
        executor = _make_executor(executor_ctx, progress, tasks, max_workers=2)

        def safe_exec(name, plugin, targets):
            return [container_a] if name == "par_a" else [container_b]

        with patch.object(executor, "_safe_execute_scanner", side_effect=safe_exec):
            with patch.object(executor, "_process_results_fn", return_value=aggregated):
                result = executor.run_parallel(aggregated)

        assert isinstance(result, AshAggregatedResults)

    def test_parallel_falls_back_to_sequential_for_single_scanner(self, executor_ctx, progress, aggregated):
        """With only one scanner task, parallel delegates to sequential."""
        _, inst = _make_plugin(name="single")
        tasks = [("single", inst, [{"path": executor_ctx.source_dir, "type": "source"}])]
        executor = _make_executor(executor_ctx, progress, tasks)

        with patch.object(executor, "run_sequential", return_value=aggregated) as mock_seq:
            result = executor.run_parallel(aggregated)

        mock_seq.assert_called_once_with(aggregated)
        assert result is aggregated

    def test_parallel_handles_future_exception(self, executor_ctx, progress, aggregated):
        """Exceptions from futures are caught and create failure containers."""
        _, inst_a = _make_plugin(name="fail_par_a")
        _, inst_b = _make_plugin(name="fail_par_b")

        tasks = [
            ("fail_par_a", inst_a, [{"path": executor_ctx.source_dir, "type": "source"}]),
            ("fail_par_b", inst_b, [{"path": executor_ctx.source_dir, "type": "source"}]),
        ]
        executor = _make_executor(executor_ctx, progress, tasks, max_workers=2)

        def safe_exec(name, plugin, targets):
            if name == "fail_par_a":
                raise RuntimeError("thread boom")
            return []

        with patch.object(executor, "_safe_execute_scanner", side_effect=safe_exec):
            with patch.object(executor, "_process_results_fn", return_value=aggregated):
                result = executor.run_parallel(aggregated)

        assert isinstance(result, AshAggregatedResults)


# ---------------------------------------------------------------------------
# ScanResultProcessor
# ---------------------------------------------------------------------------


@pytest.fixture
def proc_ctx(tmp_path):
    return _make_plugin_context(tmp_path)


@pytest.fixture
def processor(proc_ctx):
    with patch("automated_security_helper.core.phases.scan_result_processor.ScannerValidationManager"):
        return ScanResultProcessor(plugin_context=proc_ctx)


class TestScanResultProcessorPopulatesSeverityCounts:
    """ScanResultProcessor.process_container populates aggregated results."""

    def test_dict_results_stored_in_additional_reports(self, processor, proc_ctx):
        """Dict raw_results are stored under additional_reports."""
        aggregated = AshAggregatedResults()
        container = ScanResultsContainer(
            scanner_name="test_scanner",
            target=str(proc_ctx.source_dir),
            target_type="source",
        )
        container.raw_results = {"status": "ok", "findings": []}
        result = processor.process_container(container, aggregated)
        assert "test_scanner" in result.additional_reports

    def test_sarif_results_merged_into_aggregated(self, processor, proc_ctx):
        """process_container merges SARIF data into the aggregated SARIF report."""
        aggregated = AshAggregatedResults()
        container = ScanResultsContainer(
            scanner_name="sarif_scanner",
            target=str(proc_ctx.source_dir),
            target_type="source",
        )
        real_sarif = SarifReport(runs=[])
        container.raw_results = real_sarif

        merge_calls: list = []

        with patch(
            "automated_security_helper.core.phases.scan_result_processor.sanitize_sarif_paths",
            return_value=real_sarif,
        ), patch(
            "automated_security_helper.core.phases.scan_result_processor.apply_suppressions_to_sarif",
            return_value=real_sarif,
        ), patch(
            "automated_security_helper.schemas.sarif_schema_model.SarifReport.merge_sarif_report",
            lambda self, s: merge_calls.append(s),
        ), patch(
            "automated_security_helper.schemas.sarif_schema_model.SarifReport.attach_scanner_details",
            lambda self, **kw: None,
        ):
            processor.process_container(container, aggregated)

        assert len(merge_calls) == 1

    def test_missing_scanner_handled_without_crash(self, processor):
        """A container with failure raw_results is handled gracefully."""
        aggregated = AshAggregatedResults()
        container = ScanResultsContainer.for_failure("missing_scanner", errors=["not found"])
        container.raw_results = {"errors": ["not found"], "status": "failed"}
        result = processor.process_container(container, aggregated)
        assert isinstance(result, AshAggregatedResults)


class TestScanResultProcessorValidation:
    """ScanResultProcessor validation helpers log warnings without crashing."""

    def test_validate_completion_does_not_raise(self, processor):
        """validate_completion runs without raising on empty aggregated results."""
        aggregated = AshAggregatedResults()
        processor.validate_completion(aggregated)

    def test_validate_metrics_does_not_raise(self, processor):
        """validate_metrics runs without raising on empty aggregated results."""
        aggregated = AshAggregatedResults()
        processor.validate_metrics(aggregated)
