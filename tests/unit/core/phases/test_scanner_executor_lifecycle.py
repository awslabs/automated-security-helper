"""Tests for ScannerExecutor's per-target result handling and run loops.

Covers _execute_scanner's raw-result shapes (SARIF, dict severity counts, dict
findings, None, falsy), duration computation, notification failures, and the
None-results and process-failure branches of run_sequential/run_parallel.
"""

import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

_EXEC_MODULE = "automated_security_helper.core.phases.scanner_executor"
_EVENTS_MODULE = "automated_security_helper.plugins.events"


class _ScannerConfig(ScannerPluginConfigBase):
    name: str = "scripted"


class _ScriptedScanner(ScannerPluginBase):
    """A real ScannerPluginBase whose scan() replays a scripted outcome.

    A real subclass rather than MagicMock(spec=ScannerPluginBase): pydantic v2
    strips model fields off the class, so a class-level spec rejects .config,
    .errors, .output, .start_time and .exit_code -- every attribute
    ScannerExecutor actually reads. A bare Mock() would accept them all and any
    typo besides, which is the defect this repo already shipped once.
    """

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self,
        target,
        target_type=None,
        global_ignore_paths=None,
        config=None,
        *args,
        **kwargs,
    ):
        self.scan_calls.append(
            {
                "target": target,
                "target_type": target_type,
                "global_ignore_paths": global_ignore_paths,
            }
        )
        outcome = self.scripted_result
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _make_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    (source_dir / "app.py").write_text("print('x')\n")
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    work_dir = tmp_path / "work"
    work_dir.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


def _make_scanner(context, scripted_result=None, enabled=True, threshold="MEDIUM"):
    config = _ScannerConfig(enabled=enabled)
    config.options.severity_threshold = threshold
    scanner = _ScriptedScanner(config=config, context=context)
    scanner.scan_calls = []
    scanner.scripted_result = scripted_result
    scanner.start_time = datetime(2026, 1, 1, 10, 0, 0)
    scanner.end_time = datetime(2026, 1, 1, 10, 0, 7)
    scanner.exit_code = 0
    return scanner


def _make_executor(context, scanner_tasks=None, **kwargs):
    return ScannerExecutor(
        plugin_context=context,
        progress_display=MagicMock(),
        scanner_tasks=scanner_tasks or [],
        **kwargs,
    )


def _targets(context):
    return [{"path": context.source_dir, "type": "source"}]


def _broken_events_module():
    """Make `from automated_security_helper.plugins.events import ...` raise.

    A None entry in sys.modules makes the import statement raise ImportError,
    which is how the executor's `except Exception: pass` guards around those
    lazy imports become reachable without reaching into the executor itself.
    """
    return patch.dict(sys.modules, {_EVENTS_MODULE: None})


class TestNotify:
    """_notify isolates the caller from subscriber failures."""

    def test_subscriber_exception_is_logged_and_swallowed(self, tmp_path):
        def _explode(event_type, **kwargs):
            raise RuntimeError("subscriber exploded")

        executor = _make_executor(_make_context(tmp_path), notify_fn=_explode)

        with patch(f"{_EXEC_MODULE}.ASH_LOGGER") as mock_logger:
            executor._notify("SOME_EVENT", scanner="x")

        assert mock_logger.error.called
        assert "subscriber exploded" in str(mock_logger.error.call_args.args[0])

    def test_absent_notify_fn_is_a_no_op(self, tmp_path):
        executor = _make_executor(_make_context(tmp_path))
        executor._notify("SOME_EVENT")

    def test_process_results_defaults_to_passthrough(self, tmp_path):
        """With no process_results_fn wired, the aggregated model is returned as-is."""
        executor = _make_executor(_make_context(tmp_path))
        aggregated = AshAggregatedResults()
        container = MagicMock()
        assert executor._process_results_fn(container, aggregated) is aggregated


class TestExecuteScannerRawResultShapes:
    """_execute_scanner normalizes each raw_results shape it can receive."""

    def test_disabled_scanner_is_not_run_and_yields_failure_results(self, tmp_path):
        """A disabled scanner is skipped and its container records the miss."""
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(ctx, scripted_result=SarifReport(runs=[]), enabled=False)
        executor = _make_executor(ctx)

        with patch(f"{_EXEC_MODULE}.ASH_LOGGER") as mock_logger:
            results = executor._execute_scanner("scripted", scanner, _targets(ctx))

        assert scanner.scan_calls == [], "a disabled scanner must not be invoked"
        assert len(results) == 1
        assert results[0].raw_results["status"] == "failed"
        assert results[0].raw_results["exception"] == "Scanner returned None"
        assert any(
            "is not enabled" in str(c.args[0])
            for c in mock_logger.warning.call_args_list
        )

    def test_falsy_result_is_recorded_but_missing_status_is_overwritten(self, tmp_path):
        """A scanner returning False is flagged MISSING, then re-graded to PASSED.

        This pins current behavior rather than endorsing it. _execute_scanner sets
        status=MISSING for a falsy return (the documented "plugin is missing
        dependencies" case), but the threshold re-grade a few lines later only
        preserves ERROR, so MISSING is discarded and the run reports PASSED.
        """
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(ctx, scripted_result=False)
        executor = _make_executor(ctx)

        results = executor._execute_scanner("scripted", scanner, _targets(ctx))

        assert len(results) == 1
        assert results[0].status == ScannerStatus.PASSED
        assert results[0].status != ScannerStatus.MISSING

    def test_nonexistent_target_is_skipped(self, tmp_path):
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(ctx, scripted_result=SarifReport(runs=[]))
        executor = _make_executor(ctx)

        results = executor._execute_scanner(
            "scripted",
            scanner,
            [{"path": tmp_path / "does_not_exist", "type": "source"}],
        )

        assert results == []
        assert scanner.scan_calls == []

    def test_missing_config_raises(self, tmp_path):
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(ctx)
        scanner.config = None
        executor = _make_executor(ctx)

        with pytest.raises(ValueError, match="has no config"):
            executor._execute_scanner("scripted", scanner, _targets(ctx))

    def test_sarif_result_is_sanitized_suppressed_and_counted(self, tmp_path):
        """A SARIF return is path-sanitized, suppression-filtered, then counted."""
        ctx = _make_context(tmp_path)
        report = SarifReport(runs=[])
        scanner = _make_scanner(ctx, scripted_result=report)
        executor = _make_executor(ctx)

        counts = ScannerSeverityCount(
            critical=1, high=2, medium=3, low=0, info=0, suppressed=4
        )

        with patch(
            f"{_EXEC_MODULE}.sanitize_sarif_paths", return_value=report
        ) as mock_sanitize, patch(
            f"{_EXEC_MODULE}.apply_suppressions_to_sarif", return_value=report
        ) as mock_suppress, patch(
            "automated_security_helper.utils.sarif_utils.get_severity_metrics_from_sarif",
            return_value=counts,
        ):
            results = executor._execute_scanner("scripted", scanner, _targets(ctx))

        mock_sanitize.assert_called_once_with(report, ctx.source_dir)
        mock_suppress.assert_called_once()
        container = results[0]
        assert container.severity_counts is counts
        # finding_count is total + suppressed, so suppressed findings still count.
        assert container.finding_count == counts.total + 4

    def test_sarif_suppressions_skipped_when_ignore_suppressions_set(self, tmp_path):
        ctx = _make_context(tmp_path)
        ctx.ignore_suppressions = True
        report = SarifReport(runs=[])
        scanner = _make_scanner(ctx, scripted_result=report)
        executor = _make_executor(ctx)

        with patch(f"{_EXEC_MODULE}.sanitize_sarif_paths", return_value=report), patch(
            f"{_EXEC_MODULE}.apply_suppressions_to_sarif"
        ) as mock_suppress, patch(
            "automated_security_helper.utils.sarif_utils.get_severity_metrics_from_sarif",
            return_value=ScannerSeverityCount(),
        ):
            executor._execute_scanner("scripted", scanner, _targets(ctx))

        mock_suppress.assert_not_called()

    def test_severity_count_model_is_used_directly(self, tmp_path):
        """A ScannerSeverityCount in raw_results is adopted without revalidation."""
        ctx = _make_context(tmp_path)
        counts = ScannerSeverityCount(critical=0, high=1, medium=0, low=2, info=3)
        scanner = _make_scanner(
            ctx, scripted_result={"status": "ok", "severity_counts": counts}
        )
        executor = _make_executor(ctx)

        results = executor._execute_scanner("scripted", scanner, _targets(ctx))

        assert results[0].severity_counts is counts
        assert results[0].finding_count == sum(counts.model_dump().values())

    def test_findings_list_increments_counts_per_severity(self, tmp_path):
        """Each finding's severity is counted; unknown severities fall back to info."""
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(
            ctx,
            scripted_result={
                "status": "ok",
                "findings": [
                    {"severity": "HIGH"},
                    {"severity": "high"},
                    {"severity": "NOT_A_SEVERITY"},
                    {"no_severity_key": True},
                ],
            },
        )
        executor = _make_executor(ctx)

        results = executor._execute_scanner("scripted", scanner, _targets(ctx))

        container = results[0]
        assert container.severity_counts.high == 2
        assert container.severity_counts.info == 1
        assert container.finding_count == 4

    def test_metadata_from_raw_results_is_attached(self, tmp_path):
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(
            ctx,
            scripted_result={
                "status": "ok",
                "metadata": {"tool_version": "1.2.3", "rules_loaded": 42},
            },
        )
        executor = _make_executor(ctx)

        results = executor._execute_scanner("scripted", scanner, _targets(ctx))

        assert results[0].metadata["tool_version"] == "1.2.3"
        assert results[0].metadata["rules_loaded"] == 42

    def test_duration_is_computed_from_scanner_timestamps(self, tmp_path):
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(ctx, scripted_result={"status": "ok"})
        executor = _make_executor(ctx)

        results = executor._execute_scanner("scripted", scanner, _targets(ctx))

        assert results[0].duration == 7.0

    def test_mixed_timezone_timestamps_leave_duration_unset(self, tmp_path):
        """A naive/aware timestamp pair cannot be subtracted; duration stays None."""
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(ctx, scripted_result={"status": "ok"})
        scanner.start_time = datetime(2026, 1, 1, 10, 0, 0)
        scanner.end_time = datetime(2026, 1, 1, 10, 0, 7, tzinfo=timezone.utc)
        executor = _make_executor(ctx)

        results = executor._execute_scanner("scripted", scanner, _targets(ctx))

        assert results[0].duration is None

    def test_scan_exception_produces_error_container(self, tmp_path):
        """A raising scan() is captured as a failed raw_results with a stack trace."""
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(ctx, scripted_result=RuntimeError("tool crashed"))
        executor = _make_executor(ctx)

        results = executor._execute_scanner("scripted", scanner, _targets(ctx))

        container = results[0]
        assert container.status == ScannerStatus.ERROR
        assert container.raw_results["exception"] == "tool crashed"
        assert "RuntimeError" in container.raw_results["stack_trace"]

    def test_scan_exception_survives_broken_events_module(self, tmp_path):
        """The error-notification import failing does not lose the error container."""
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(ctx, scripted_result=RuntimeError("tool crashed"))
        executor = _make_executor(ctx)

        with _broken_events_module():
            results = executor._execute_scanner("scripted", scanner, _targets(ctx))

        assert results[0].status == ScannerStatus.ERROR

    def test_scanner_level_exception_is_reraised(self, tmp_path):
        """A failure outside the per-target try propagates to the caller."""
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(ctx, scripted_result={"status": "ok"})
        executor = _make_executor(ctx)

        with pytest.raises(KeyError):
            executor._execute_scanner(
                "scripted", scanner, [{"path": ctx.source_dir}]  # no "type" key
            )


class TestSafeExecuteScanner:
    """_safe_execute_scanner converts unhandled failures into containers."""

    def test_unhandled_exception_becomes_failure_container(self, tmp_path):
        ctx = _make_context(tmp_path)
        executor = _make_executor(ctx)

        with patch.object(
            executor, "_execute_scanner", side_effect=RuntimeError("deep failure")
        ):
            results, succeeded = executor._safe_execute_scanner("s", MagicMock(), [])

        assert succeeded is False
        assert len(results) == 1
        assert results[0].raw_results["exception"] == "deep failure"
        assert "RuntimeError" in results[0].raw_results["stack_trace"]

    def test_failure_container_survives_broken_events_module(self, tmp_path):
        ctx = _make_context(tmp_path)
        executor = _make_executor(ctx)

        with patch.object(
            executor, "_execute_scanner", side_effect=RuntimeError("deep failure")
        ), _broken_events_module():
            results, succeeded = executor._safe_execute_scanner("s", MagicMock(), [])

        assert succeeded is False
        assert results[0].raw_results["status"] == "failed"


class TestRunSequentialEdgeCases:
    """run_sequential handles None results, notify failures and process failures."""

    def test_none_results_are_recorded_as_a_failure(self, tmp_path):
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(ctx)
        executor = _make_executor(ctx, [("scripted", scanner, _targets(ctx))])

        processed = []

        def _process(container, aggregated):
            processed.append(container)
            return aggregated

        executor._process_fn = _process
        aggregated = AshAggregatedResults()

        with patch.object(
            executor, "_safe_execute_scanner", return_value=(None, False)
        ):
            result = executor.run_sequential(aggregated)

        assert result is aggregated
        assert len(processed) == 1
        assert processed[0].raw_results["exception"] == "Scanner returned None results"
        assert executor.completed_scanners == []

    def test_notification_failures_do_not_stop_the_run(self, tmp_path):
        """Both SCAN_START and SCAN_COMPLETE import failures are tolerated."""
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(ctx, scripted_result={"status": "ok"})
        executor = _make_executor(ctx, [("scripted", scanner, _targets(ctx))])
        aggregated = AshAggregatedResults()

        with _broken_events_module():
            result = executor.run_sequential(aggregated)

        assert result is aggregated
        assert executor.completed_scanners == [scanner]

    def test_process_failure_during_error_handling_is_logged(self, tmp_path):
        """When both the scanner and the result processor fail, the loop continues."""
        ctx = _make_context(tmp_path)
        scanner_a = _make_scanner(ctx)
        scanner_b = _make_scanner(ctx)
        executor = _make_executor(
            ctx,
            [
                ("a", scanner_a, _targets(ctx)),
                ("b", scanner_b, _targets(ctx)),
            ],
        )
        executor._process_fn = MagicMock(side_effect=RuntimeError("processor down"))
        aggregated = AshAggregatedResults()

        seen = []

        def _boom(name, plugin, targets):
            seen.append(name)
            raise RuntimeError(f"{name} exploded")

        with patch.object(
            executor, "_safe_execute_scanner", side_effect=_boom
        ), patch(f"{_EXEC_MODULE}.ASH_LOGGER") as mock_logger:
            result = executor.run_sequential(aggregated)

        assert seen == ["a", "b"], "a failing scanner must not stop the next one"
        assert result is aggregated
        logged = [str(c.args[0]) for c in mock_logger.error.call_args_list]
        assert any("Failed to process error results for a" in m for m in logged)

    def test_error_status_keeps_scanner_out_of_completed_list(self, tmp_path):
        """A container in ERROR state disqualifies the scanner from completion."""
        ctx = _make_context(tmp_path)
        scanner = _make_scanner(ctx, scripted_result=RuntimeError("boom"))
        executor = _make_executor(ctx, [("scripted", scanner, _targets(ctx))])
        aggregated = AshAggregatedResults()

        result = executor.run_sequential(aggregated)

        assert result is aggregated
        assert executor.completed_scanners == []


class TestRunParallelEdgeCases:
    """run_parallel handles None results, notify failures and process failures."""

    def _two_task_executor(self, ctx):
        scanner_a = _make_scanner(ctx, scripted_result={"status": "ok"})
        scanner_b = _make_scanner(ctx, scripted_result={"status": "ok"})
        executor = _make_executor(
            ctx,
            [
                ("par_a", scanner_a, _targets(ctx)),
                ("par_b", scanner_b, _targets(ctx)),
            ],
            max_workers=2,
        )
        return executor, scanner_a, scanner_b

    def test_none_results_are_recorded_as_a_failure(self, tmp_path):
        ctx = _make_context(tmp_path)
        executor, _, _ = self._two_task_executor(ctx)

        processed = []

        def _process(container, aggregated):
            processed.append(container)
            return aggregated

        executor._process_fn = _process
        aggregated = AshAggregatedResults()

        with patch.object(
            executor, "_safe_execute_scanner", return_value=(None, False)
        ):
            result = executor.run_parallel(aggregated)

        assert result is aggregated
        assert len(processed) == 2
        assert all(
            c.raw_results["exception"] == "Scanner returned None results"
            for c in processed
        )
        assert executor.completed_scanners == []

    def test_notification_failure_does_not_stop_the_run(self, tmp_path):
        ctx = _make_context(tmp_path)
        executor, scanner_a, scanner_b = self._two_task_executor(ctx)
        aggregated = AshAggregatedResults()

        with _broken_events_module():
            result = executor.run_parallel(aggregated)

        assert result is aggregated
        # Compared by identity: pydantic models are unhashable, and completion
        # order depends on which thread finishes first.
        completed = executor.completed_scanners
        assert len(completed) == 2
        assert any(s is scanner_a for s in completed)
        assert any(s is scanner_b for s in completed)

    def test_process_failure_during_error_handling_is_logged(self, tmp_path):
        ctx = _make_context(tmp_path)
        executor, _, _ = self._two_task_executor(ctx)
        executor._process_fn = MagicMock(side_effect=RuntimeError("processor down"))
        aggregated = AshAggregatedResults()

        with patch.object(
            executor,
            "_safe_execute_scanner",
            side_effect=RuntimeError("thread exploded"),
        ), patch(f"{_EXEC_MODULE}.ASH_LOGGER") as mock_logger:
            result = executor.run_parallel(aggregated)

        assert result is aggregated
        logged = [str(c.args[0]) for c in mock_logger.error.call_args_list]
        assert sum("Failed to process error results" in m for m in logged) == 2


class TestUpdateProgress:
    """_update_progress is best-effort and never propagates display failures."""

    def test_missing_phase_task_is_a_no_op(self, tmp_path):
        ctx = _make_context(tmp_path)
        display = MagicMock()
        display.phase_task = None
        executor = ScannerExecutor(
            plugin_context=ctx, progress_display=display, scanner_tasks=[]
        )

        executor._update_progress(50, "halfway")

        display.update_task.assert_not_called()

    def test_phase_task_present_forwards_the_update(self, tmp_path):
        ctx = _make_context(tmp_path)
        display = MagicMock()
        display.phase_task = 7
        executor = ScannerExecutor(
            plugin_context=ctx, progress_display=display, scanner_tasks=[]
        )

        executor._update_progress(50, "halfway")

        assert display.update_task.call_args.kwargs["task_id"] == 7
        assert display.update_task.call_args.kwargs["completed"] == 50

    def test_display_exception_is_swallowed(self, tmp_path):
        ctx = _make_context(tmp_path)
        display = MagicMock()
        display.phase_task = 7
        display.update_task.side_effect = RuntimeError("display detached")
        executor = ScannerExecutor(
            plugin_context=ctx, progress_display=display, scanner_tasks=[]
        )

        executor._update_progress(50, "halfway")
