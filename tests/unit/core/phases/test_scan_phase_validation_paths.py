"""Tests for ScanPhase's validation reporting and legacy run-loop stubs.

Covers the three _validate_* reporters' discrepancy, notification-failure and
outer-exception paths, _validate_metrics_consistency across both
scanner_results shapes, the additional_reports state tally in _execute_phase,
and the None-results / notify-failure / process-failure branches of
_execute_scanners_sequential and _execute_scanners_parallel.
"""

import threading
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.cancellation import (
    ScanCancelled,
    cancel_scope,
    raise_if_cancelled,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.core.unified_metrics import ScannerMetrics
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
    ScannerStatusInfo,
)
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
    ScannerValidationState,
    ValidationCheckpoint,
)

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

_PHASE_MODULE = "automated_security_helper.core.phases.scan_phase"
_EXECUTOR_MODULE = "automated_security_helper.core.phases.scanner_executor"


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


def _make_phase(tmp_path, plugins=None, validation_manager=None):
    """Build a ScanPhase with a controllable validation manager.

    The manager double is spec'd on ScannerValidationManager, which is a plain
    class, so every method the phase calls has to exist on the real type. That
    is the check a bare Mock() would not make.
    """
    phase = ScanPhase(
        plugin_context=_make_context(tmp_path),
        plugins=plugins or [],
        progress_display=MagicMock(),
        asharp_model=AshAggregatedResults(),
    )
    phase.validation_manager = (
        validation_manager
        if validation_manager is not None
        else MagicMock(spec=ScannerValidationManager)
    )
    return phase


def _checkpoint(
    name="cp",
    expected=None,
    actual=None,
    discrepancies=None,
    errors=None,
    metadata=None,
):
    return ValidationCheckpoint(
        checkpoint_name=name,
        expected_scanners=list(expected or []),
        actual_scanners=list(actual or []),
        discrepancies=list(discrepancies or []),
        errors=list(errors or []),
        metadata=dict(metadata or {}),
    )


def _raising_notify(message_fragment=None):
    """Return a notify_event replacement that raises, optionally only for one message."""

    def _notify(event_type, **kwargs):
        if message_fragment is None or message_fragment in kwargs.get("message", ""):
            raise RuntimeError("event bus unavailable")

    return _notify


class TestValidateScannerTasks:
    """_validate_scanner_tasks reports missing scanners and survives failures."""

    def test_a_missing_scanner_is_recorded_without_a_retry(self, tmp_path):
        """Against the real manager: no retry is claimed, and the reason is recorded.

        ``retry_scanner_registration`` was a stub that returned [] for every input, so
        the phase logged "attempting retry registration" and then "No scanners were
        successfully retried" for a retry that never happened, and the summary carried
        a ``successfully_retried`` count that could only be 0. Its one side effect,
        a failure reason saying "retry attempted", was the only record of why the
        scanner did not run, because the checkpoint this phase builds has no
        discrepancies and so never opened ``handle_queue_validation_errors``.
        """
        manager = ScannerValidationManager(_make_context(tmp_path))
        for name in ("bandit", "semgrep"):
            manager.update_scanner_state(name, enablement_status="enabled")
        phase = _make_phase(tmp_path, validation_manager=manager)
        phase._scanner_tasks = [("bandit", object())]
        aggregated = AshAggregatedResults()

        with patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger:
            phase._validate_scanner_tasks(aggregated)

        assert not hasattr(ScannerValidationManager, "retry_scanner_registration")
        logged = [str(c.args[0]) for c in mock_logger.method_calls if c.args]
        assert any("semgrep" in line for line in logged), logged
        assert not [line for line in logged if "retr" in line.lower()], logged
        summary = aggregated.metadata.validation_summary["scanner_tasks_validation"]
        assert summary["missing_count"] == 1
        assert "successfully_retried" not in summary, summary
        assert manager.scanner_states["semgrep"].failure_reason == (
            "Scanner was expected to be queued but was not found in task queue"
        )
        assert manager.scanner_states["bandit"].failure_reason is None

    def test_missing_scanners_are_reported_and_handed_to_the_error_handler(
        self, tmp_path
    ):
        """Missing scanners are counted, and the notification failing is tolerated."""
        manager = MagicMock(spec=ScannerValidationManager)
        checkpoint = _checkpoint(
            name="scanner_tasks",
            expected=["bandit", "semgrep"],
            actual=["bandit"],
            discrepancies=["semgrep absent from task queue"],
        )
        manager.validate_task_queue.return_value = checkpoint

        phase = _make_phase(tmp_path, validation_manager=manager)
        phase._scanner_tasks = []
        aggregated = AshAggregatedResults()

        with patch.object(phase, "notify_event", side_effect=_raising_notify()):
            phase._validate_scanner_tasks(aggregated)

        manager.handle_queue_validation_errors.assert_called_once()
        summary = aggregated.metadata.validation_summary["scanner_tasks_validation"]
        assert summary["missing_count"] == 1
        assert "successfully_retried" not in summary
        assert summary["has_issues"] is True
        assert (
            aggregated.validation_checkpoints[-1]["checkpoint_name"] == "scanner_tasks"
        )

    def test_clean_checkpoint_tolerates_notification_failure(self, tmp_path):
        """The success-path notification failing does not fail validation."""
        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_task_queue.return_value = _checkpoint(
            expected=["bandit"], actual=["bandit"]
        )

        phase = _make_phase(tmp_path, validation_manager=manager)
        phase._scanner_tasks = []
        aggregated = AshAggregatedResults()

        with patch.object(phase, "notify_event", side_effect=_raising_notify()):
            phase._validate_scanner_tasks(aggregated)

        summary = aggregated.metadata.validation_summary["scanner_tasks_validation"]
        assert summary["has_issues"] is False
        assert summary["missing_count"] == 0

    def test_validation_failure_is_recorded_and_scan_continues(self, tmp_path):
        """A raising validate_task_queue is captured, not propagated."""
        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_task_queue.side_effect = RuntimeError("queue unreadable")

        phase = _make_phase(tmp_path, validation_manager=manager)
        phase._scanner_tasks = []
        aggregated = AshAggregatedResults()

        with patch.object(phase, "notify_event", side_effect=_raising_notify()):
            phase._validate_scanner_tasks(aggregated)

        manager.add_queue_validation_error.assert_called_once()
        recorded = manager.add_queue_validation_error.call_args.args[0]
        assert "queue unreadable" in recorded
        assert "scanner_tasks_validation" not in aggregated.metadata.validation_summary


class TestValidateExecutionCompletion:
    """_validate_execution_completion derives scanner names and reports gaps."""

    def test_scanner_name_falls_back_to_class_name(self, tmp_path):
        """A completed plugin without config.name is named from its class."""

        class NamelessPlugin:
            """No config attribute, so the class-name fallback applies."""

        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_execution_completion.return_value = _checkpoint(
            expected=["bandit"], actual=["namelessplugin"]
        )
        manager.report_execution_discrepancies.return_value = {"detail": "report"}
        manager.get_scanner_state.return_value = ScannerValidationState(
            name="bandit", failure_reason="never started"
        )

        phase = _make_phase(tmp_path, validation_manager=manager)
        phase._completed_scanners = [NamelessPlugin()]
        aggregated = AshAggregatedResults()

        with patch.object(phase, "notify_event", side_effect=_raising_notify()):
            phase._validate_execution_completion(aggregated)

        manager.validate_execution_completion.assert_called_once_with(
            ["namelessplugin"]
        )
        summary = aggregated.metadata.validation_summary[
            "execution_completion_validation"
        ]
        assert summary["missing_count"] == 1
        assert summary["unexpected_count"] == 1
        assert aggregated.metadata.execution_discrepancy_report == {"detail": "report"}

    def test_configured_name_is_preferred_over_class_name(self, tmp_path):
        """When config.name exists it wins over the class name."""

        class NamedPlugin:
            def __init__(self):
                self.config = MagicMock()
                self.config.name = "bandit"

        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_execution_completion.return_value = _checkpoint(
            expected=["bandit"],
            actual=["bandit"],
            metadata={"completion_rate": 1.0},
        )

        phase = _make_phase(tmp_path, validation_manager=manager)
        phase._completed_scanners = [NamedPlugin(), NamedPlugin()]
        aggregated = AshAggregatedResults()

        phase._validate_execution_completion(aggregated)

        # Duplicates collapse: two instances of one scanner report once.
        manager.validate_execution_completion.assert_called_once_with(["bandit"])
        summary = aggregated.metadata.validation_summary[
            "execution_completion_validation"
        ]
        assert summary["completion_rate"] == 1.0

    def test_clean_checkpoint_tolerates_notification_failure(self, tmp_path):
        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_execution_completion.return_value = _checkpoint(
            expected=["bandit"], actual=["bandit"], metadata={"completion_rate": 1.0}
        )

        phase = _make_phase(tmp_path, validation_manager=manager)
        phase._completed_scanners = []
        aggregated = AshAggregatedResults()

        with patch.object(phase, "notify_event", side_effect=_raising_notify()):
            phase._validate_execution_completion(aggregated)

        summary = aggregated.metadata.validation_summary[
            "execution_completion_validation"
        ]
        assert summary["has_issues"] is False

    def test_issues_are_summarized_when_checkpoint_has_errors(self, tmp_path):
        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_execution_completion.return_value = _checkpoint(
            expected=["bandit"],
            actual=["bandit"],
            errors=["state tracker disagreed"],
            metadata={"completion_rate": 1.0},
        )

        phase = _make_phase(tmp_path, validation_manager=manager)
        phase._completed_scanners = []
        aggregated = AshAggregatedResults()

        with patch.object(phase, "notify_event", side_effect=_raising_notify()):
            phase._validate_execution_completion(aggregated)

        summary = aggregated.metadata.validation_summary[
            "execution_completion_validation"
        ]
        assert summary["has_issues"] is True
        assert summary["missing_count"] == 0

    def test_validation_failure_is_swallowed(self, tmp_path):
        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_execution_completion.side_effect = RuntimeError(
            "tracker unavailable"
        )

        phase = _make_phase(tmp_path, validation_manager=manager)
        phase._completed_scanners = []
        aggregated = AshAggregatedResults()

        with patch.object(phase, "notify_event", side_effect=_raising_notify()):
            phase._validate_execution_completion(aggregated)

        assert (
            "execution_completion_validation"
            not in aggregated.metadata.validation_summary
        )


class TestValidateResultCompleteness:
    """_validate_result_completeness backfills missing scanners into the results."""

    def test_adjustments_are_reported_and_attached(self, tmp_path):
        manager = MagicMock(spec=ScannerValidationManager)
        manager.ensure_complete_results.return_value = _checkpoint(
            expected=["bandit", "semgrep"],
            actual=["bandit", "checkov"],
            discrepancies=["semgrep missing from results"],
            metadata={"completeness_rate": 0.5},
        )
        manager.report_result_completeness.return_value = {"added": ["semgrep"]}
        manager.get_scanner_state.return_value = ScannerValidationState(
            name="semgrep", failure_reason="dependencies missing"
        )

        phase = _make_phase(tmp_path, validation_manager=manager)
        aggregated = AshAggregatedResults()

        with patch.object(phase, "notify_event", side_effect=_raising_notify()):
            phase._validate_result_completeness(aggregated)

        assert aggregated.metadata.result_completeness_report == {"added": ["semgrep"]}
        summary = aggregated.metadata.validation_summary[
            "result_completeness_validation"
        ]
        assert summary["missing_count"] == 1
        assert summary["unexpected_count"] == 1
        assert summary["completeness_rate"] == 0.5
        assert summary["has_issues"] is True

    def test_clean_checkpoint_tolerates_notification_failure(self, tmp_path):
        manager = MagicMock(spec=ScannerValidationManager)
        manager.ensure_complete_results.return_value = _checkpoint(
            expected=["bandit"], actual=["bandit"], metadata={"completeness_rate": 1.0}
        )

        phase = _make_phase(tmp_path, validation_manager=manager)
        aggregated = AshAggregatedResults()

        with patch.object(phase, "notify_event", side_effect=_raising_notify()):
            phase._validate_result_completeness(aggregated)

        summary = aggregated.metadata.validation_summary[
            "result_completeness_validation"
        ]
        assert summary["has_issues"] is False
        manager.report_result_completeness.assert_not_called()

    def test_validation_failure_is_swallowed(self, tmp_path):
        manager = MagicMock(spec=ScannerValidationManager)
        manager.ensure_complete_results.side_effect = RuntimeError("results locked")

        phase = _make_phase(tmp_path, validation_manager=manager)
        aggregated = AshAggregatedResults()

        with (
            patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger,
            patch.object(phase, "notify_event", side_effect=_raising_notify()),
        ):
            phase._validate_result_completeness(aggregated)

        errors = [str(c.args[0]) for c in mock_logger.error.call_args_list]
        assert any("results locked" in e for e in errors)
        assert (
            "result_completeness_validation"
            not in aggregated.metadata.validation_summary
        )


class TestValidateMetricsConsistency:
    """_validate_metrics_consistency tallies both scanner_results shapes."""

    def test_scanner_metrics_shape_is_tallied_and_mismatch_warned(self, tmp_path):
        """A ScannerMetrics entry is summed and compared against summary_stats."""
        phase = _make_phase(tmp_path)
        aggregated = AshAggregatedResults()
        aggregated.scanner_results["bandit"] = ScannerMetrics(
            scanner_name="bandit",
            critical=1,
            high=2,
            medium=3,
            low=4,
            info=5,
            suppressed=6,
        )

        with patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger:
            phase._validate_metrics_consistency(aggregated)

        warnings = [str(c.args[0]) for c in mock_logger.warning.call_args_list]
        # summary_stats is all zeros here, so every non-zero tally must be flagged.
        assert any("failed for critical" in w and "total=1" in w for w in warnings)
        assert any("failed for high" in w and "total=2" in w for w in warnings)
        assert any("failed for suppressed" in w and "total=6" in w for w in warnings)

    def test_matching_totals_produce_no_warning(self, tmp_path):
        """Zero findings on both sides is consistent and warns about nothing."""
        phase = _make_phase(tmp_path)
        aggregated = AshAggregatedResults()
        aggregated.scanner_results["bandit"] = ScannerMetrics(scanner_name="bandit")

        with patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger:
            phase._validate_metrics_consistency(aggregated)

        warnings = [str(c.args[0]) for c in mock_logger.warning.call_args_list]
        assert not any("consistency check failed" in w for w in warnings)

    def test_status_info_shape_is_tallied(self, tmp_path):
        """The older ScannerStatusInfo shape is summed via source/converted."""
        phase = _make_phase(tmp_path)
        aggregated = AshAggregatedResults()
        info = ScannerStatusInfo()
        info.source.severity_counts = ScannerSeverityCount(critical=2, high=1)
        info.source.finding_count = 3
        info.source.actionable_finding_count = 3
        aggregated.scanner_results["bandit"] = info

        with patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger:
            phase._validate_metrics_consistency(aggregated)

        warnings = [str(c.args[0]) for c in mock_logger.warning.call_args_list]
        assert any("failed for critical" in w and "total=2" in w for w in warnings)

    def test_unknown_shape_is_logged_and_skipped(self, tmp_path):
        """An entry matching neither shape is reported without aborting the check."""

        class OpaqueInfo:
            """Neither source/converted nor critical/scanner_name."""

        phase = _make_phase(tmp_path)
        aggregated = AshAggregatedResults()
        aggregated.scanner_results["mystery"] = OpaqueInfo()

        with patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger:
            phase._validate_metrics_consistency(aggregated)

        debugs = [str(c.args[0]) for c in mock_logger.debug.call_args_list]
        assert any("Unknown scanner_info structure for mystery" in d for d in debugs)

    def test_exception_during_tally_is_swallowed(self, tmp_path):
        """A scanner entry that raises on attribute access does not abort the scan."""

        class ExplodingInfo:
            @property
            def source(self):
                raise RuntimeError("corrupt metrics entry")

        phase = _make_phase(tmp_path)
        aggregated = AshAggregatedResults()
        aggregated.scanner_results["broken"] = ExplodingInfo()

        with patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger:
            phase._validate_metrics_consistency(aggregated)

        errors = [str(c.args[0]) for c in mock_logger.error.call_args_list]
        assert any("Error validating metrics consistency" in e for e in errors)
        assert any("corrupt metrics entry" in e for e in errors)


class TestSafeExecuteScannerStub:
    """ScanPhase._safe_execute_scanner wraps failures into one failure container.

    It delegates to ScannerExecutor._safe_execute_scanner, so the failing
    scanner is patched at the executor seam.
    """

    def test_failure_becomes_a_single_container(self, tmp_path):
        phase = _make_phase(tmp_path)

        with patch.object(
            ScannerExecutor,
            "_execute_scanner",
            side_effect=RuntimeError("delegate failed"),
        ):
            results = phase._safe_execute_scanner("bandit", MagicMock(), [])

        assert len(results) == 1
        assert results[0].raw_results["exception"] == "delegate failed"
        assert "RuntimeError" in results[0].raw_results["stack_trace"]

    def test_failure_survives_a_broken_notify(self, tmp_path):
        """A raising notify_event does not lose the failure container."""
        phase = _make_phase(tmp_path)

        with (
            patch.object(
                ScannerExecutor,
                "_execute_scanner",
                side_effect=RuntimeError("delegate failed"),
            ),
            patch.object(phase, "notify_event", side_effect=_raising_notify()),
        ):
            results = phase._safe_execute_scanner("bandit", MagicMock(), [])

        assert len(results) == 1
        assert results[0].raw_results["status"] == "failed"

    def test_a_plugin_whose_values_attribute_raises_keeps_its_failure_container(
        self, tmp_path
    ):
        """A plugin that is not a PluginBase can answer the read of its
        _environment_values attribute with an exception. The handler that
        redacts with the plugin's values still answers the failure container:
        the read costs the plugin's values, never the handler."""
        phase = _make_phase(tmp_path)

        with patch.object(
            ScannerExecutor,
            "_execute_scanner",
            side_effect=RuntimeError("delegate failed"),
        ):
            results = phase._safe_execute_scanner(
                "bandit", _ValuesAttributeRaises(), []
            )

        assert len(results) == 1
        assert results[0].raw_results["exception"] == "delegate failed"


class _ValuesAttributeRaises:
    """A plugin, not a PluginBase, whose _environment_values attribute raises
    when read."""

    @property
    def _environment_values(self):
        raise RuntimeError("the values could not be read")


class _ValuesLookupRaises:
    """The same, through __getattr__ instead of a property."""

    def __getattr__(self, name):
        raise RuntimeError(f"{name} could not be read")


@pytest.mark.parametrize(
    "plugin",
    [
        pytest.param(_ValuesAttributeRaises(), id="property"),
        pytest.param(_ValuesLookupRaises(), id="getattr"),
    ],
)
def test_a_plugin_s_values_that_raise_when_read_leave_the_run_s(plugin):
    """plugin_environment_values answers the run's values for a plugin whose
    _environment_values attribute raises on read, as for one whose getter
    raises when called."""
    from automated_security_helper.utils.error_text import plugin_environment_values

    assert plugin_environment_values(plugin, ["/nonexistent/run-value"]) == (
        "/nonexistent/run-value",
    )


class _NamedPlugin:
    """Minimal stand-in for a scanner plugin in the run-loop stubs.

    The loops only read __class__.__name__ off the plugin, so a plain class is
    a complete double here -- and unlike a Mock it cannot answer for anything
    else the loop might start reading later.
    """


class TestExecuteScannersSequentialStub:
    """_execute_scanners_sequential handles None results and broken collaborators.

    The method delegates to ScannerExecutor.run_sequential, so the scanner
    double is patched on the executor (whose _safe_execute_scanner answers a
    (results, succeeded) pair) and result processing on the phase's
    _result_processor, which the delegation wires through.
    """

    def _prepare(self, tmp_path, names):
        phase = _make_phase(tmp_path)
        phase._scanner_tasks = [
            (
                name,
                _NamedPlugin(),
                [{"path": phase.plugin_context.source_dir, "type": "source"}],
            )
            for name in names
        ]
        phase._max_workers = 2
        phase._completed_scanners = []
        phase._result_processor = MagicMock()
        phase._result_processor.process_container.side_effect = (
            lambda container, aggregated: aggregated
        )
        return phase

    def test_none_results_produce_a_failure_container(self, tmp_path):
        phase = self._prepare(tmp_path, ["bandit"])
        aggregated = AshAggregatedResults()
        processed = []
        phase._result_processor.process_container.side_effect = lambda c, a: (
            processed.append(c) or a
        )

        with patch.object(
            ScannerExecutor, "_safe_execute_scanner", return_value=(None, False)
        ):
            result = phase._execute_scanners_sequential(aggregated)

        assert result is aggregated
        assert len(processed) == 1
        assert processed[0].raw_results["exception"] == "Scanner returned None results"

    def test_notification_failures_do_not_stop_the_loop(self, tmp_path):
        """Both the start and complete notifications may fail without effect."""
        phase = self._prepare(tmp_path, ["bandit"])
        aggregated = AshAggregatedResults()
        container = MagicMock()

        with (
            patch.object(
                ScannerExecutor,
                "_safe_execute_scanner",
                return_value=([container], True),
            ),
            patch.object(phase, "notify_event", side_effect=_raising_notify()),
        ):
            result = phase._execute_scanners_sequential(aggregated)

        assert result is aggregated

    def test_process_failure_during_error_handling_is_logged(self, tmp_path):
        """When the scanner and the processor both fail, later scanners still run."""
        phase = self._prepare(tmp_path, ["bandit", "semgrep"])
        aggregated = AshAggregatedResults()
        seen = []

        def _boom(executor_self, name, plugin, targets):
            seen.append(name)
            raise RuntimeError(f"{name} exploded")

        phase._result_processor.process_container.side_effect = RuntimeError(
            "processor down"
        )

        with (
            patch.object(
                ScannerExecutor,
                "_safe_execute_scanner",
                autospec=True,
                side_effect=_boom,
            ),
            patch(f"{_EXECUTOR_MODULE}.ASH_LOGGER") as mock_logger,
        ):
            result = phase._execute_scanners_sequential(aggregated)

        assert seen == ["bandit", "semgrep"]
        assert result is aggregated
        errors = [str(c.args[0]) for c in mock_logger.error.call_args_list]
        assert any("Failed to process error results for bandit" in e for e in errors)


class TestExecuteScannersParallelStub:
    """_execute_scanners_parallel mirrors the sequential loop across a thread pool.

    Patched at the executor seam like the sequential stubs above.
    """

    def _prepare(self, tmp_path, names):
        phase = _make_phase(tmp_path)
        phase._scanner_tasks = [
            (
                name,
                _NamedPlugin(),
                [{"path": phase.plugin_context.source_dir, "type": "source"}],
            )
            for name in names
        ]
        phase._max_workers = 2
        phase._completed_scanners = []
        phase._result_processor = MagicMock()
        phase._result_processor.process_container.side_effect = (
            lambda container, aggregated: aggregated
        )
        return phase

    def test_single_scanner_delegates_to_sequential(self, tmp_path):
        phase = self._prepare(tmp_path, ["only"])
        aggregated = AshAggregatedResults()

        with patch.object(
            ScannerExecutor, "run_sequential", return_value=aggregated
        ) as mock_seq:
            result = phase._execute_scanners_parallel(aggregated)

        mock_seq.assert_called_once_with(aggregated)
        assert result is aggregated

    def test_none_results_produce_failure_containers(self, tmp_path):
        phase = self._prepare(tmp_path, ["bandit", "semgrep"])
        aggregated = AshAggregatedResults()
        processed = []
        phase._result_processor.process_container.side_effect = lambda c, a: (
            processed.append(c) or a
        )

        with patch.object(
            ScannerExecutor, "_safe_execute_scanner", return_value=(None, False)
        ):
            result = phase._execute_scanners_parallel(aggregated)

        assert result is aggregated
        assert len(processed) == 2
        assert all(
            c.raw_results["exception"] == "Scanner returned None results"
            for c in processed
        )
        assert phase._completed_scanners == []

    def test_completed_scanners_are_collected_despite_broken_notify(self, tmp_path):
        """Successful scanners land in _completed_scanners even if notify fails."""
        phase = self._prepare(tmp_path, ["bandit", "semgrep"])
        aggregated = AshAggregatedResults()

        with (
            patch.object(
                ScannerExecutor,
                "_safe_execute_scanner",
                return_value=([MagicMock()], True),
            ),
            patch.object(phase, "notify_event", side_effect=_raising_notify()),
        ):
            result = phase._execute_scanners_parallel(aggregated)

        assert result is aggregated
        assert len(phase._completed_scanners) == 2
        recorded = {id(p) for p in phase._completed_scanners}
        expected = {id(t[1]) for t in phase._scanner_tasks}
        assert recorded == expected

    def test_process_failure_during_error_handling_is_logged(self, tmp_path):
        phase = self._prepare(tmp_path, ["bandit", "semgrep"])
        aggregated = AshAggregatedResults()
        phase._result_processor.process_container.side_effect = RuntimeError(
            "processor down"
        )

        with (
            patch.object(
                ScannerExecutor,
                "_safe_execute_scanner",
                side_effect=RuntimeError("thread exploded"),
            ),
            patch(f"{_EXECUTOR_MODULE}.ASH_LOGGER") as mock_logger,
        ):
            result = phase._execute_scanners_parallel(aggregated)

        assert result is aggregated
        errors = [str(c.args[0]) for c in mock_logger.error.call_args_list]
        assert sum("Failed to process error results" in e for e in errors) == 2


class _ModelPlugin(BaseModel):
    """A pydantic plugin double: unhashable, like a real scanner plugin."""

    name: str = "bandit"


class TestRunLoopsAreTheExecutors:
    """The phase's run-loop methods carry ScannerExecutor's semantics.

    _execute_phase routes execution through ScannerExecutor.run_sequential/
    run_parallel. The methods here exist for direct callers, so they must
    behave as that path does rather than as a drifted copy of it: the
    executor records a completed scanner only on success with no
    error-status container, and the sequential loop records them at all.
    """

    def _prepare(self, tmp_path, names, plugin_factory=_NamedPlugin):
        phase = _make_phase(tmp_path)
        phase._scanner_tasks = [
            (
                name,
                plugin_factory(),
                [{"path": phase.plugin_context.source_dir, "type": "source"}],
            )
            for name in names
        ]
        phase._max_workers = 2
        phase._completed_scanners = []
        phase._result_processor = MagicMock()
        phase._result_processor.process_container.side_effect = lambda c, a: a
        return phase

    def test_the_sequential_loop_is_the_executors(self, tmp_path):
        phase = self._prepare(tmp_path, ["bandit"])
        aggregated = AshAggregatedResults()

        with patch.object(
            ScannerExecutor, "run_sequential", return_value=aggregated
        ) as run:
            result = phase._execute_scanners_sequential(aggregated)

        run.assert_called_once_with(aggregated)
        assert result is aggregated

    def test_the_parallel_loop_is_the_executors(self, tmp_path):
        phase = self._prepare(tmp_path, ["bandit", "semgrep"])
        aggregated = AshAggregatedResults()

        with patch.object(
            ScannerExecutor, "run_parallel", return_value=aggregated
        ) as run:
            result = phase._execute_scanners_parallel(aggregated)

        run.assert_called_once_with(aggregated)
        assert result is aggregated

    def test_a_sequential_success_lands_in_completed_scanners(self, tmp_path):
        phase = self._prepare(tmp_path, ["bandit"])
        aggregated = AshAggregatedResults()
        container = MagicMock()
        container.status = ScannerStatus.PASSED

        with patch.object(
            ScannerExecutor, "_safe_execute_scanner", return_value=([container], True)
        ):
            phase._execute_scanners_sequential(aggregated)

        assert [id(plugin) for plugin in phase._completed_scanners] == [
            id(phase._scanner_tasks[0][1])
        ]

    def test_an_error_container_is_not_a_completed_scanner(self, tmp_path):
        phase = self._prepare(tmp_path, ["bandit", "semgrep"])
        aggregated = AshAggregatedResults()

        def _run(executor_self, scanner_name, scanner_plugin, scan_targets):
            container = MagicMock()
            container.status = (
                ScannerStatus.ERROR
                if scanner_name == "bandit"
                else ScannerStatus.PASSED
            )
            return [container], True

        with patch.object(
            ScannerExecutor, "_safe_execute_scanner", autospec=True, side_effect=_run
        ):
            phase._execute_scanners_parallel(aggregated)

        assert {id(plugin) for plugin in phase._completed_scanners} == {
            id(phase._scanner_tasks[1][1])
        }

    def test_a_model_plugin_lands_in_completed_scanners(self, tmp_path):
        """Scanner plugins are pydantic models, which are unhashable, so the
        sync-back must not put them in a set."""
        phase = self._prepare(tmp_path, ["bandit"], plugin_factory=_ModelPlugin)
        aggregated = AshAggregatedResults()
        container = MagicMock()
        container.status = ScannerStatus.PASSED

        with patch.object(
            ScannerExecutor, "_safe_execute_scanner", return_value=([container], True)
        ):
            result = phase._execute_scanners_sequential(aggregated)

        assert result is aggregated
        assert [id(plugin) for plugin in phase._completed_scanners] == [
            id(phase._scanner_tasks[0][1])
        ]

    def test_a_model_plugin_lands_in_completed_scanners_in_parallel(self, tmp_path):
        phase = self._prepare(
            tmp_path, ["bandit", "semgrep"], plugin_factory=_ModelPlugin
        )
        aggregated = AshAggregatedResults()
        container = MagicMock()
        container.status = ScannerStatus.PASSED

        with patch.object(
            ScannerExecutor, "_safe_execute_scanner", return_value=([container], True)
        ):
            result = phase._execute_scanners_parallel(aggregated)

        assert result is aggregated
        assert {id(plugin) for plugin in phase._completed_scanners} == {
            id(task[1]) for task in phase._scanner_tasks
        }

    @pytest.mark.parametrize("method", ["_execute_scanner", "_safe_execute_scanner"])
    def test_a_direct_per_scanner_call_takes_no_completion_from_its_executor(
        self, tmp_path, method
    ):
        """The single-scanner delegations record no completion, as the
        executor's own per-scanner methods record none: only its run loops do.
        Even a stand-in that appends to the delegation executor's list leaves
        the phase's completions as they were."""
        phase = self._prepare(tmp_path, ["bandit"], plugin_factory=_ModelPlugin)
        plugin = phase._scanner_tasks[0][1]

        def _run(executor_self, scanner_name, scanner_plugin, scan_targets):
            executor_self.completed_scanners.append(scanner_plugin)
            return []

        with patch.object(
            ScannerExecutor, "_execute_scanner", autospec=True, side_effect=_run
        ):
            result = getattr(phase, method)(
                "bandit", plugin, phase._scanner_tasks[0][2]
            )

        assert result == []
        assert phase._completed_scanners == []

    def test_sequential_completions_keep_run_order(self, tmp_path):
        """Completions already recorded stay first, then the run's, in run
        order, each once."""
        phase = self._prepare(tmp_path, ["s1", "s2"])
        preexisting = _NamedPlugin()
        phase._completed_scanners = [preexisting]
        aggregated = AshAggregatedResults()
        container = MagicMock()
        container.status = ScannerStatus.PASSED

        with patch.object(
            ScannerExecutor, "_safe_execute_scanner", return_value=([container], True)
        ):
            phase._execute_scanners_sequential(aggregated)
            phase._execute_scanners_sequential(aggregated)

        assert [id(plugin) for plugin in phase._completed_scanners] == [
            id(preexisting),
            id(phase._scanner_tasks[0][1]),
            id(phase._scanner_tasks[1][1]),
        ]

    def test_results_are_processed_without_a_prepared_result_processor(self, tmp_path):
        """A direct caller has no _result_processor (only execute() sets one),
        and its results must still be processed, not dropped."""
        phase = _make_phase(tmp_path)
        phase._scanner_tasks = [
            (
                "bandit",
                _NamedPlugin(),
                [{"path": phase.plugin_context.source_dir, "type": "source"}],
            )
        ]
        phase._max_workers = 2
        phase._completed_scanners = []
        aggregated = AshAggregatedResults()
        container = MagicMock()
        container.status = ScannerStatus.PASSED

        with (
            patch.object(
                ScannerExecutor,
                "_safe_execute_scanner",
                return_value=([container], True),
            ),
            patch.object(
                ScanResultProcessor,
                "process_container",
                autospec=True,
                side_effect=lambda processor, c, a: a,
            ) as process,
        ):
            result = phase._execute_scanners_sequential(aggregated)

        assert result is aggregated
        assert process.call_count == 1

    def test_parallel_results_are_processed_without_a_prepared_processor(
        self, tmp_path
    ):
        phase = _make_phase(tmp_path)
        phase._scanner_tasks = [
            (
                name,
                _NamedPlugin(),
                [{"path": phase.plugin_context.source_dir, "type": "source"}],
            )
            for name in ("bandit", "semgrep")
        ]
        phase._max_workers = 2
        phase._completed_scanners = []
        aggregated = AshAggregatedResults()
        container = MagicMock()
        container.status = ScannerStatus.PASSED

        with (
            patch.object(
                ScannerExecutor,
                "_safe_execute_scanner",
                return_value=([container], True),
            ),
            patch.object(
                ScanResultProcessor,
                "process_container",
                autospec=True,
                side_effect=lambda processor, c, a: a,
            ) as process,
        ):
            result = phase._execute_scanners_parallel(aggregated)

        assert result is aggregated
        assert process.call_count == 2

    def test_the_sequential_method_does_not_use_the_pool(self, tmp_path):
        """With more than one scanner the pool would not fall back to the
        sequential loop, so a pool run here could only be a wrong turn."""
        phase = self._prepare(tmp_path, ["bandit", "semgrep"])
        aggregated = AshAggregatedResults()
        order = []

        def _run(executor_self, scanner_name, scanner_plugin, scan_targets):
            order.append(scanner_name)
            container = MagicMock()
            container.status = ScannerStatus.PASSED
            return [container], True

        with (
            patch.object(
                ScannerExecutor,
                "run_parallel",
                side_effect=AssertionError(
                    "the sequential method must not run the pool"
                ),
            ),
            patch.object(
                ScannerExecutor,
                "_safe_execute_scanner",
                autospec=True,
                side_effect=_run,
            ),
        ):
            result = phase._execute_scanners_sequential(aggregated)

        assert result is aggregated
        assert order == ["bandit", "semgrep"]

    def test_one_run_keeps_completion_order(self, tmp_path):
        """A single run over four scanners: completions already recorded stay
        first, then the run's in the order they ran. One run, so a merge that
        reverses its list can't be undone by a second run reversing it back."""
        phase = self._prepare(tmp_path, ["s1", "s2", "s3", "s4"])
        preexisting = _NamedPlugin()
        phase._completed_scanners = [preexisting]
        aggregated = AshAggregatedResults()
        container = MagicMock()
        container.status = ScannerStatus.PASSED

        with patch.object(
            ScannerExecutor, "_safe_execute_scanner", return_value=([container], True)
        ):
            phase._execute_scanners_sequential(aggregated)

        assert [id(plugin) for plugin in phase._completed_scanners] == [
            id(preexisting),
            *(id(task[1]) for task in phase._scanner_tasks),
        ]

    @pytest.mark.parametrize("mode", ["sequential", "parallel"])
    def test_completions_before_a_cancel_are_kept(self, tmp_path, mode):
        """A scanner that completed before the scan was cancelled stays in
        _completed_scanners: the cancel ends the run by raising, and the sync
        back from the executor must not be skipped by it.

        s0 completes; s1 then sees the cancel. In the parallel mode s1 waits
        until s0's results were processed, so s0 is the first future the pool
        hands back and the order is deterministic.
        """
        phase = self._prepare(tmp_path, ["s0", "s1"])
        aggregated = AshAggregatedResults()
        cancel = threading.Event()
        s0_processed = threading.Event()

        def _processed(container, aggregated_results):
            s0_processed.set()
            return aggregated_results

        phase._result_processor.process_container.side_effect = _processed

        def _run(executor_self, scanner_name, scanner_plugin, scan_targets):
            if scanner_name == "s0":
                container = MagicMock()
                container.status = ScannerStatus.PASSED
                if mode == "sequential":
                    # The next scanner's start sees the cancel.
                    cancel.set()
                return [container]
            # Parallel: cancel from inside s1, once s0 has been processed.
            assert s0_processed.wait(10), "s0 was never processed"
            cancel.set()
            raise_if_cancelled()
            return []

        method = (
            phase._execute_scanners_sequential
            if mode == "sequential"
            else phase._execute_scanners_parallel
        )
        with (
            patch.object(
                ScannerExecutor, "_execute_scanner", autospec=True, side_effect=_run
            ),
            cancel_scope(cancel),
        ):
            with pytest.raises(ScanCancelled):
                method(aggregated)

        assert [id(plugin) for plugin in phase._completed_scanners] == [
            id(phase._scanner_tasks[0][1])
        ]


def _fake_scanner(scanner_name, *, deps_satisfied=True):
    """A minimal scanner plugin class with a fixed name and dependency verdict.

    Only the surface `_execute_phase` reaches during filtering: `config.name`
    (which `_scanner_display_name` reads, and which `--exclude-scanners` is
    matched against), `config.enabled`, and `validate_plugin_dependencies`.
    """

    class _Fake:
        def __init__(self, config=None, context=None):
            self.config = MagicMock()
            self.config.name = scanner_name
            self.config.enabled = True

        def validate_plugin_dependencies(self):
            return deps_satisfied

    _Fake.__name__ = f"Fake{scanner_name}"
    return _Fake


class TestExecutePhaseScannerStateTally:
    """_execute_phase tallies scanner states from the collections it wrote."""

    def test_excluded_and_missing_dependency_counts_are_reported(self, tmp_path):
        """Excluded and dependency-short scanners are counted and named.

        These two numbers used to be re-derived by walking `additional_reports`
        for a "source" key, and both were structurally pinned at 0:
        `_process_results` keys that dict by `ScanResultsContainer.target_type`,
        which is None for the excluded and missing-dependency containers built
        during preparation, so the "source" key the walk required was never
        there. The counts now come from `excluded_scanner_names` and
        `dependency_error_scanners` -- the collections the filtering loop
        actually appends to -- so this drives real plugins through that loop
        rather than hand-building `additional_reports`, which no longer feeds it.
        """
        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_task_queue.return_value = _checkpoint()
        manager.validate_execution_completion.return_value = _checkpoint()
        manager.ensure_complete_results.return_value = _checkpoint()

        plugins = [
            _fake_scanner("excluded-one"),
            _fake_scanner("excluded-two"),
            _fake_scanner("missing-deps", deps_satisfied=False),
        ]
        phase = _make_phase(tmp_path, plugins=plugins, validation_manager=manager)
        aggregated = AshAggregatedResults()

        with patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger:
            result = phase._execute_phase(
                aggregated,
                excluded_scanners=["excluded-one", "excluded-two"],
                parallel=False,
            )

        infos = [str(c.args[0]) for c in mock_logger.info.call_args_list]
        assert any("Excluded scanners: 2" in m for m in infos)
        assert any("Missing dependencies: 1" in m for m in infos)
        assert result is aggregated

        # The totals alone do not pin the classification -- 2 and 1 would also be
        # produced by a loop that put the wrong scanner in each bucket. The
        # per-scanner debug lines name who landed where, and the negative
        # assertions below are what would catch a refactor that emptied one
        # bucket into the other while keeping the arithmetic intact.
        debugs = [str(c.args[0]) for c in mock_logger.debug.call_args_list]
        assert any("Scanner excluded-one: EXCLUDED" in d for d in debugs)
        assert any("Scanner excluded-two: EXCLUDED" in d for d in debugs)
        assert any("Scanner missing-deps: MISSING DEPENDENCIES" in d for d in debugs)
        assert not any("Scanner missing-deps: EXCLUDED" in d for d in debugs)
        assert not any(
            "Scanner excluded-one: MISSING DEPENDENCIES" in d for d in debugs
        )
        assert not any(
            "Scanner excluded-two: MISSING DEPENDENCIES" in d for d in debugs
        )

        # No scanner survived filtering, so nothing was queued to run. This is
        # what keeps the assertions above about preparation rather than about
        # whatever the executor would have done with a task.
        assert phase._scanner_tasks == []

    def test_scanner_instance_failure_does_not_abort_the_phase(self, tmp_path):
        """A plugin that raises during filtering is logged and the phase continues."""

        class _Exploder:
            """Raises when its dependencies are validated."""

            def __init__(self, config=None, context=None):
                self.config = MagicMock()
                self.config.name = "exploder"

            def validate_plugin_dependencies(self):
                raise RuntimeError("dependency probe crashed")

        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_task_queue.return_value = _checkpoint()
        manager.validate_execution_completion.return_value = _checkpoint()
        manager.ensure_complete_results.return_value = _checkpoint()

        phase = _make_phase(tmp_path, plugins=[_Exploder], validation_manager=manager)
        aggregated = AshAggregatedResults()

        with patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger:
            result = phase._execute_phase(aggregated, parallel=False)

        errors = [str(c.args[0]) for c in mock_logger.error.call_args_list]
        assert any("dependency probe crashed" in e for e in errors)
        assert result is aggregated
        assert phase._scanner_tasks == []

    def test_phase_failure_is_reraised_and_summarized(self, tmp_path):
        """A failure inside the phase body is re-raised after a Failed summary."""
        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_scanner_enablement.side_effect = RuntimeError(
            "enablement check crashed"
        )

        phase = _make_phase(tmp_path, plugins=[], validation_manager=manager)

        with patch.object(phase, "add_summary") as mock_summary:
            with pytest.raises(RuntimeError, match="enablement check crashed"):
                phase._execute_phase(AshAggregatedResults(), parallel=False)

        assert mock_summary.call_args.args[0] == "Failed"
        assert "enablement check crashed" in mock_summary.call_args.args[1]


def _a_real_npm_audit_scan_phase(tmp_path, phase_class=ScanPhase):
    """A scan phase over one package.json with the real npm-audit scanner class.

    Its dependency check answers True, as the engine would run it with the tool
    installed; the per-scanner work itself is patched by _run_the_real_scan.
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScanner,
    )

    class _WithTool(NpmAuditScanner):
        def validate_plugin_dependencies(self) -> bool:
            return True

    _WithTool.__name__ = NpmAuditScanner.__name__
    _WithTool.__module__ = NpmAuditScanner.__module__

    source = tmp_path / "source"
    source.mkdir()
    (source / "package.json").write_text("{}\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return phase_class(
        plugin_context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=get_default_config(),
        ),
        plugins=[_WithTool],
        progress_display=MagicMock(),
        asharp_model=AshAggregatedResults(),
    )


def _run_the_real_scan(phase, parallel, **own_path):
    """Run phase.execute() with ScannerExecutor._execute_scanner patched.

    *own_path* configures that patch (return_value or side_effect), the
    executor's own per-scanner path; result processing passes the aggregate
    through. Returns the patch's mock.
    """
    with (
        patch.object(
            ScannerExecutor, "_execute_scanner", autospec=True, **own_path
        ) as own,
        patch.object(
            ScanResultProcessor,
            "process_container",
            autospec=True,
            side_effect=lambda processor, container, aggregated: aggregated,
        ),
    ):
        phase.execute(
            aggregated_results=AshAggregatedResults(),
            parallel=parallel,
            max_workers=2,
        )
    return own


class TestThePhasesPerScannerMethodsAreNotHooks:
    """Neither a scan nor a delegator runs a per-scanner method replaced on the phase.

    The scan, ScanPhase.execute, builds a ScannerExecutor and runs its own
    per-scanner path. The run-loop delegators and _safe_execute_scanner build
    the same executor for their direct callers, so they run that path too: a
    double put on the phase's _safe_execute_scanner or _execute_scanner, on
    the instance or by a subclass, is run by neither, and a direct call and
    a scan of one phase run the same code. A test stands in for a scanner's
    run by patching ScannerExecutor._execute_scanner, which both resolve per
    call. Were a replaced _safe_execute_scanner run, its plain list would
    read as a success, so a scanner whose run raised (a FAILED container,
    not ERROR) would be counted as completed.
    """

    def _prepare(self, tmp_path, names):
        phase = _make_phase(tmp_path)
        phase._scanner_tasks = [
            (
                name,
                _NamedPlugin(),
                [{"path": phase.plugin_context.source_dir, "type": "source"}],
            )
            for name in names
        ]
        phase._max_workers = 2
        phase._completed_scanners = []
        phase._result_processor = MagicMock()
        phase._result_processor.process_container.side_effect = lambda c, a: a
        return phase

    @pytest.mark.parametrize("hook_name", ["_safe_execute_scanner", "_execute_scanner"])
    @pytest.mark.parametrize("loop", ["sequential", "parallel"])
    def test_a_replaced_hook_is_not_run_by_the_loops(self, tmp_path, loop, hook_name):
        """The run-loop delegators run the executor's own path, as a scan does.

        Its completions are the executor's own: every scanner whose run
        returned a PASSED container, the replacement's answer unread.
        """
        names = ["s1"] if loop == "sequential" else ["s1", "s2"]
        phase = self._prepare(tmp_path, names)
        container = MagicMock()
        container.status = ScannerStatus.PASSED
        hook = MagicMock(return_value=[])
        setattr(phase, hook_name, hook)

        with patch.object(
            ScannerExecutor, "_execute_scanner", autospec=True, return_value=[container]
        ) as own_path:
            getattr(phase, f"_execute_scanners_{loop}")(AshAggregatedResults())

        hook.assert_not_called()
        assert own_path.call_count == len(names), own_path.mock_calls
        assert {c.args[1] for c in own_path.call_args_list} == set(names)
        assert {id(p) for p in phase._completed_scanners} == {
            id(task[1]) for task in phase._scanner_tasks
        }

    def test_a_replaced_execute_hook_is_not_run_by_safe_execute(self, tmp_path):
        """A direct _safe_execute_scanner runs the executor's own path too."""
        phase = self._prepare(tmp_path, ["s1"])
        plugin = phase._scanner_tasks[0][1]
        container = MagicMock()
        container.status = ScannerStatus.PASSED
        hook = MagicMock(return_value=[])
        phase._execute_scanner = hook

        with patch.object(
            ScannerExecutor, "_execute_scanner", autospec=True, return_value=[container]
        ) as own_path:
            results = phase._safe_execute_scanner("s1", plugin, [])

        assert results == [container]
        hook.assert_not_called()
        own_path.assert_called_once()
        assert own_path.call_args.args[1:] == ("s1", plugin, [])

    @pytest.mark.parametrize("loop", ["sequential", "parallel"])
    def test_with_nothing_replaced_the_executors_own_path_runs(self, tmp_path, loop):
        names = ["s1"] if loop == "sequential" else ["s1", "s2"]
        phase = self._prepare(tmp_path, names)
        container = MagicMock()
        container.status = ScannerStatus.PASSED

        with patch.object(
            ScannerExecutor,
            "_execute_scanner",
            autospec=True,
            return_value=[container],
        ) as own_path:
            getattr(phase, f"_execute_scanners_{loop}")(AshAggregatedResults())

        assert own_path.call_count == len(names)

    @pytest.mark.parametrize("loop", ["sequential", "parallel"])
    def test_with_nothing_replaced_a_raising_scanner_is_not_completed(
        self, tmp_path, loop
    ):
        """The executor's own succeeded flag decides the loops' completions.

        The phase's _safe_execute_scanner answers a plain failure-container
        list, which read as a success would record a scanner whose execution
        raised as completed; the loops read the executor's flag instead.
        """
        names = ["s1"] if loop == "sequential" else ["s1", "s2"]
        phase = self._prepare(tmp_path, names)

        with patch.object(
            ScannerExecutor,
            "_execute_scanner",
            autospec=True,
            side_effect=RuntimeError("scanner down"),
        ) as own_path:
            getattr(phase, f"_execute_scanners_{loop}")(AshAggregatedResults())

        assert own_path.call_count == len(names)
        assert phase._completed_scanners == []

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_a_replaced_hook_is_not_run_by_a_real_scan(self, tmp_path, parallel):
        """ScanPhase.execute runs the executor's own path, not a replaced hook.

        The scan builds its own executor in _execute_phase, so its
        completions come from the executor's own flag. Driven with a real
        scanner class whose dependency check answers True, as the engine
        would run it.
        """
        from automated_security_helper.models.scan_results_container import (
            ScanResultsContainer,
        )

        phase = _a_real_npm_audit_scan_phase(tmp_path)
        hook = MagicMock(
            side_effect=lambda scanner_name, scanner_plugin, scan_targets: [
                ScanResultsContainer(scanner_name=scanner_name)
            ]
        )
        phase._safe_execute_scanner = hook

        own_path = _run_the_real_scan(
            phase, parallel, side_effect=RuntimeError("scanner down")
        )

        hook.assert_not_called()
        assert own_path.call_count == 1
        assert phase._completed_scanners == []

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_with_nothing_replaced_a_real_scan_does_not_complete_a_raising_scanner(
        self, tmp_path, parallel
    ):
        """In a real scan with nothing replaced, the executor's flag decides.

        As in the loops' cell above: the phase's _safe_execute_scanner answers
        a plain failure-container list, which read as a success would record
        a scanner whose run raised as completed.
        """
        phase = _a_real_npm_audit_scan_phase(tmp_path)

        own_path = _run_the_real_scan(
            phase, parallel, side_effect=RuntimeError("scanner down")
        )

        assert own_path.call_count == 1
        assert phase._completed_scanners == []

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_an_execute_scanner_wrap_is_not_run_by_a_real_scan(
        self, tmp_path, parallel
    ):
        """A subclass that wraps _execute_scanner: the real scan runs the
        executor's own path, not the wrap, and a scanner whose run raised
        stays out of completed_scanners."""
        wrapped = []

        class _Wrapping(ScanPhase):
            def _execute_scanner(self, scanner_name, scanner_plugin, scan_targets):
                wrapped.append(scanner_name)
                return super()._execute_scanner(
                    scanner_name, scanner_plugin, scan_targets
                )

        phase = _a_real_npm_audit_scan_phase(tmp_path, phase_class=_Wrapping)

        own_path = _run_the_real_scan(
            phase, parallel, side_effect=RuntimeError("scanner down")
        )

        assert wrapped == [], wrapped
        assert own_path.call_count == 1
        assert phase._completed_scanners == []

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_with_both_hooks_replaced_a_real_scan_runs_neither(
        self, tmp_path, parallel
    ):
        """With both hooks replaced, the real scan runs the executor's own path."""
        from automated_security_helper.models.scan_results_container import (
            ScanResultsContainer,
        )

        phase = _a_real_npm_audit_scan_phase(tmp_path)
        outer = MagicMock(
            side_effect=lambda scanner_name, scanner_plugin, scan_targets: [
                ScanResultsContainer(scanner_name=scanner_name)
            ]
        )
        inner = MagicMock(return_value=[])
        phase._safe_execute_scanner = outer
        phase._execute_scanner = inner

        own_path = _run_the_real_scan(phase, parallel, return_value=[])

        outer.assert_not_called()
        inner.assert_not_called()
        assert own_path.call_count == 1

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_a_safe_execute_override_is_not_run_by_a_real_scan(
        self, tmp_path, parallel
    ):
        """A subclass override of _safe_execute_scanner, which replaces the
        hook on the class rather than the instance, is not run by a real scan
        either: its completions are the executor's own."""
        from automated_security_helper.models.scan_results_container import (
            ScanResultsContainer,
        )

        calls = []

        class _Overriding(ScanPhase):
            def _safe_execute_scanner(self, scanner_name, scanner_plugin, scan_targets):
                calls.append(scanner_name)
                return [ScanResultsContainer(scanner_name=scanner_name)]

        phase = _a_real_npm_audit_scan_phase(tmp_path, phase_class=_Overriding)

        own_path = _run_the_real_scan(
            phase, parallel, side_effect=RuntimeError("scanner down")
        )

        assert calls == [], calls
        assert own_path.call_count == 1
        assert phase._completed_scanners == []


class TestADirectPerScannerCallRecordsNoCompletion:
    """_safe_execute_scanner and _execute_scanner record no completion.

    The executor records a completion only in its run loops, under their
    rule (succeeded, with a result list none of whose containers is ERROR),
    and a direct call to one of the phase's per-scanner delegators runs no
    loop, so it records none, whatever the run answered.
    """

    def test_a_direct_safe_execute_success_records_no_completion(self, tmp_path):
        phase = _make_phase(tmp_path)
        phase._completed_scanners = []
        plugin = _NamedPlugin()
        container = MagicMock()
        container.status = ScannerStatus.PASSED

        with patch.object(
            ScannerExecutor, "_execute_scanner", return_value=[container]
        ):
            results = phase._safe_execute_scanner("direct", plugin, [])

        assert results == [container]
        assert phase._completed_scanners == []

    def test_a_direct_safe_execute_failure_is_not_recorded(self, tmp_path):
        """An unhandled exception answers a failure container, no completion."""
        phase = _make_phase(tmp_path)
        phase._completed_scanners = []

        with patch.object(
            ScannerExecutor,
            "_execute_scanner",
            side_effect=RuntimeError("scanner down"),
        ):
            results = phase._safe_execute_scanner("direct", _NamedPlugin(), [])

        assert [c.status for c in results] == [ScannerStatus.FAILED]
        assert phase._completed_scanners == []

    def test_a_direct_safe_execute_error_result_is_not_recorded(self, tmp_path):
        phase = _make_phase(tmp_path)
        phase._completed_scanners = []
        container = MagicMock()
        container.status = ScannerStatus.ERROR

        with patch.object(
            ScannerExecutor, "_execute_scanner", return_value=[container]
        ):
            phase._safe_execute_scanner("direct", _NamedPlugin(), [])

        assert phase._completed_scanners == []

    def test_a_direct_execute_success_records_no_completion(self, tmp_path):
        phase = _make_phase(tmp_path)
        phase._completed_scanners = []
        plugin = _NamedPlugin()
        container = MagicMock()
        container.status = ScannerStatus.PASSED

        with patch.object(
            ScannerExecutor, "_execute_scanner", return_value=[container]
        ):
            results = phase._execute_scanner("direct", plugin, [])

        assert results == [container]
        assert phase._completed_scanners == []

    def test_a_direct_execute_error_result_is_not_recorded(self, tmp_path):
        phase = _make_phase(tmp_path)
        phase._completed_scanners = []
        container = MagicMock()
        container.status = ScannerStatus.ERROR

        with patch.object(
            ScannerExecutor, "_execute_scanner", return_value=[container]
        ):
            phase._execute_scanner("direct", _NamedPlugin(), [])

        assert phase._completed_scanners == []
