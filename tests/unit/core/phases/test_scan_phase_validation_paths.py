"""Tests for ScanPhase's validation reporting and legacy run-loop stubs.

Covers the three _validate_* reporters' discrepancy, retry, notification-failure
and outer-exception paths, _validate_metrics_consistency across both
scanner_results shapes, the additional_reports state tally in _execute_phase,
and the None-results / notify-failure / process-failure branches of
_execute_scanners_sequential and _execute_scanners_parallel.
"""

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scan_phase import ScanPhase
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

    def test_missing_scanners_with_failed_retry_are_reported(self, tmp_path):
        """Missing scanners trigger a retry; an empty retry result is logged."""
        manager = MagicMock(spec=ScannerValidationManager)
        checkpoint = _checkpoint(
            name="scanner_tasks",
            expected=["bandit", "semgrep"],
            actual=["bandit"],
            discrepancies=["semgrep absent from task queue"],
        )
        manager.validate_task_queue.return_value = checkpoint
        manager.retry_scanner_registration.return_value = []

        phase = _make_phase(tmp_path, validation_manager=manager)
        phase._scanner_tasks = []
        aggregated = AshAggregatedResults()

        with patch.object(phase, "notify_event", side_effect=_raising_notify()):
            phase._validate_scanner_tasks(aggregated)

        manager.retry_scanner_registration.assert_called_once_with(["semgrep"])
        manager.handle_queue_validation_errors.assert_called_once()
        summary = aggregated.metadata.validation_summary["scanner_tasks_validation"]
        assert summary["missing_count"] == 1
        assert summary["successfully_retried"] == 0
        assert summary["has_issues"] is True
        assert (
            aggregated.validation_checkpoints[-1]["checkpoint_name"] == "scanner_tasks"
        )

    def test_successful_retry_is_recorded_in_the_summary(self, tmp_path):
        """A non-empty retry result is counted, with the known re-add limitation logged."""
        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_task_queue.return_value = _checkpoint(
            expected=["bandit", "semgrep"], actual=["bandit"]
        )
        manager.retry_scanner_registration.return_value = ["semgrep"]

        phase = _make_phase(tmp_path, validation_manager=manager)
        phase._scanner_tasks = []
        aggregated = AshAggregatedResults()

        with patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger:
            phase._validate_scanner_tasks(aggregated)

        summary = aggregated.metadata.validation_summary["scanner_tasks_validation"]
        assert summary["successfully_retried"] == 1
        warnings = [str(c.args[0]) for c in mock_logger.warning.call_args_list]
        assert any("not re-added to task list" in w for w in warnings)

    def test_retry_success_notification_failure_is_tolerated(self, tmp_path):
        """The retry-success notification may fail without losing the retry count.

        Only that one notification is made to raise, so a pass here cannot be
        explained by an earlier guard swallowing the failure instead.
        """
        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_task_queue.return_value = _checkpoint(
            expected=["bandit", "semgrep"], actual=["bandit"]
        )
        manager.retry_scanner_registration.return_value = ["semgrep"]

        phase = _make_phase(tmp_path, validation_manager=manager)
        phase._scanner_tasks = []
        aggregated = AshAggregatedResults()

        with patch.object(
            phase,
            "notify_event",
            side_effect=_raising_notify("Successfully retried registration"),
        ):
            phase._validate_scanner_tasks(aggregated)

        summary = aggregated.metadata.validation_summary["scanner_tasks_validation"]
        assert summary["successfully_retried"] == 1
        assert summary["missing_count"] == 1

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
    """ScanPhase._safe_execute_scanner wraps failures into one failure container."""

    def test_failure_becomes_a_single_container(self, tmp_path):
        phase = _make_phase(tmp_path)

        with patch.object(
            phase, "_execute_scanner", side_effect=RuntimeError("delegate failed")
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
                phase, "_execute_scanner", side_effect=RuntimeError("delegate failed")
            ),
            patch.object(phase, "notify_event", side_effect=_raising_notify()),
        ):
            results = phase._safe_execute_scanner("bandit", MagicMock(), [])

        assert len(results) == 1
        assert results[0].raw_results["status"] == "failed"


class _NamedPlugin:
    """Minimal stand-in for a scanner plugin in the run-loop stubs.

    The loops only read __class__.__name__ off the plugin, so a plain class is
    a complete double here -- and unlike a Mock it cannot answer for anything
    else the loop might start reading later.
    """


class TestExecuteScannersSequentialStub:
    """_execute_scanners_sequential handles None results and broken collaborators."""

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
        return phase

    def test_none_results_produce_a_failure_container(self, tmp_path):
        phase = self._prepare(tmp_path, ["bandit"])
        aggregated = AshAggregatedResults()
        processed = []

        with (
            patch.object(phase, "_safe_execute_scanner", return_value=None),
            patch.object(
                phase,
                "_process_results",
                side_effect=lambda c, a: processed.append(c) or a,
            ),
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
            patch.object(phase, "_safe_execute_scanner", return_value=[container]),
            patch.object(phase, "_process_results", return_value=aggregated),
            patch.object(phase, "notify_event", side_effect=_raising_notify()),
        ):
            result = phase._execute_scanners_sequential(aggregated)

        assert result is aggregated

    def test_process_failure_during_error_handling_is_logged(self, tmp_path):
        """When the scanner and the processor both fail, later scanners still run."""
        phase = self._prepare(tmp_path, ["bandit", "semgrep"])
        aggregated = AshAggregatedResults()
        seen = []

        def _boom(name, plugin, targets):
            seen.append(name)
            raise RuntimeError(f"{name} exploded")

        with (
            patch.object(phase, "_safe_execute_scanner", side_effect=_boom),
            patch.object(
                phase, "_process_results", side_effect=RuntimeError("processor down")
            ),
            patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger,
        ):
            result = phase._execute_scanners_sequential(aggregated)

        assert seen == ["bandit", "semgrep"]
        assert result is aggregated
        errors = [str(c.args[0]) for c in mock_logger.error.call_args_list]
        assert any("Failed to process error results for bandit" in e for e in errors)


class TestExecuteScannersParallelStub:
    """_execute_scanners_parallel mirrors the sequential loop across a thread pool."""

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
        return phase

    def test_single_scanner_delegates_to_sequential(self, tmp_path):
        phase = self._prepare(tmp_path, ["only"])
        aggregated = AshAggregatedResults()

        with patch.object(
            phase, "_execute_scanners_sequential", return_value=aggregated
        ) as mock_seq:
            result = phase._execute_scanners_parallel(aggregated)

        mock_seq.assert_called_once_with(aggregated)
        assert result is aggregated

    def test_none_results_produce_failure_containers(self, tmp_path):
        phase = self._prepare(tmp_path, ["bandit", "semgrep"])
        aggregated = AshAggregatedResults()
        processed = []

        with (
            patch.object(phase, "_safe_execute_scanner", return_value=None),
            patch.object(
                phase,
                "_process_results",
                side_effect=lambda c, a: processed.append(c) or a,
            ),
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
            patch.object(phase, "_safe_execute_scanner", return_value=[MagicMock()]),
            patch.object(phase, "_process_results", return_value=aggregated),
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

        with (
            patch.object(
                phase,
                "_safe_execute_scanner",
                side_effect=RuntimeError("thread exploded"),
            ),
            patch.object(
                phase, "_process_results", side_effect=RuntimeError("processor down")
            ),
            patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger,
        ):
            result = phase._execute_scanners_parallel(aggregated)

        assert result is aggregated
        errors = [str(c.args[0]) for c in mock_logger.error.call_args_list]
        assert sum("Failed to process error results" in e for e in errors) == 2


class TestExecutePhaseScannerStateTally:
    """_execute_phase tallies prior scanner states out of additional_reports."""

    def test_excluded_and_missing_dependency_counts_are_reported(self, tmp_path):
        """Existing additional_reports entries are classified into the two buckets."""
        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_task_queue.return_value = _checkpoint()
        manager.validate_execution_completion.return_value = _checkpoint()
        manager.ensure_complete_results.return_value = _checkpoint()

        phase = _make_phase(tmp_path, plugins=[], validation_manager=manager)
        aggregated = AshAggregatedResults()
        aggregated.additional_reports = {
            "excluded_one": {"source": {"excluded": True}},
            "excluded_two": {"source": {"excluded": True}},
            "missing_deps": {"source": {"dependencies_satisfied": False}},
            "healthy": {"source": {"excluded": False, "dependencies_satisfied": True}},
            "not_a_dict": {"source": "a string, not a mapping"},
            "no_source_key": {"converted": {"excluded": True}},
        }

        with patch(f"{_PHASE_MODULE}.ASH_LOGGER") as mock_logger:
            result = phase._execute_phase(aggregated, parallel=False)

        infos = [str(c.args[0]) for c in mock_logger.info.call_args_list]
        assert any("Excluded scanners: 2" in m for m in infos)
        assert any("Missing dependencies: 1" in m for m in infos)
        assert result is aggregated

        # The tallies alone do not pin the classification: swapping the
        # dependencies_satisfied polarity moves "healthy" into the missing bucket
        # and "missing_deps" out of it, leaving both counts unchanged. Assert on
        # the per-scanner debug lines, which name who landed where.
        debugs = [str(c.args[0]) for c in mock_logger.debug.call_args_list]
        assert any("Scanner excluded_one: EXCLUDED" in d for d in debugs)
        assert any("Scanner excluded_two: EXCLUDED" in d for d in debugs)
        assert any("Scanner missing_deps: MISSING DEPENDENCIES" in d for d in debugs)
        assert not any("Scanner healthy" in d for d in debugs)
        assert not any("Scanner not_a_dict" in d for d in debugs)
        assert not any("Scanner no_source_key" in d for d in debugs)

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
