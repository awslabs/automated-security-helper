"""Behavior tests for the uncovered branches of ``models.scanner_validation``.

Real ``ScannerStateTracker`` and ``ValidationCheckpointer`` instances are used
throughout; only two things are ever substituted, and both are noted at the call
site: ``determine_scanner_status_from_execution_data`` (a pure status switch is
easier to drive directly than to reach through eight state fields) and
``_get_executed_scanners_from_validation_state`` (needed to make the two
independently-computed scanner sets disagree, which is the only way to reach the
defensive double-check inside ``ensure_complete_results``).

Where a double is needed for a logger it is built with ``create_autospec``. A
bare ``Mock`` fabricates any attribute it is asked for, so it cannot catch a call
to a method that does not exist -- the defect that shipped in
``ScannerValidationManager`` itself.
"""

from unittest.mock import create_autospec, patch

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import (
    ScannerStateTracker,
    ScannerValidationManager,
    ValidationCheckpoint,
    ValidationCheckpointer,
)
from automated_security_helper.utils.log import ASH_LOGGER


def _status(
    status,
    dependencies_satisfied=True,
    excluded=False,
    execution_completed=False,
    failure_reason="because",
):
    return {
        "status": status,
        "dependencies_satisfied": dependencies_satisfied,
        "excluded": excluded,
        "execution_completed": execution_completed,
        "failure_reason": failure_reason,
    }


@pytest.fixture
def tracker():
    return ScannerStateTracker()


@pytest.fixture
def checkpointer(tracker):
    return ValidationCheckpointer(tracker)


@pytest.fixture
def quiet(checkpointer):
    """Silence the checkpointer's logger and expose it for call assertions."""
    logger = create_autospec(ASH_LOGGER)
    checkpointer.logger = logger
    return logger


# ---------------------------------------------------------------------------
# ScannerStateTracker.get_scanner_state_summary
# ---------------------------------------------------------------------------


def test_the_state_summary_buckets_each_scanner_by_its_status(tracker):
    tracker.update_scanner_state("bandit", enablement_status="excluded")
    tracker.update_scanner_state("semgrep", enablement_status="missing_deps")

    summary = tracker.get_scanner_state_summary()

    assert summary["excluded"] == ["bandit"]
    assert summary["missing_deps"] == ["semgrep"]
    assert summary["completed"] == []


def test_an_unrecognized_status_falls_into_the_missing_bucket(tracker):
    """A status outside the five known buckets must not be dropped silently."""
    tracker.update_scanner_state("oddball", registration_status="registered")

    with patch.object(
        tracker,
        "determine_scanner_status_from_execution_data",
        return_value=_status("some-future-status"),
    ):
        summary = tracker.get_scanner_state_summary()

    assert summary["missing"] == ["oddball"]


def test_the_state_summary_always_reports_the_five_known_buckets(tracker):
    summary = tracker.get_scanner_state_summary()

    assert set(summary) == {
        "completed",
        "excluded",
        "missing_deps",
        "failed",
        "missing",
    }


def test_a_class_name_cannot_be_tracked(tracker):
    with pytest.raises(ValueError, match="looks like a class name"):
        tracker.update_scanner_state("BanditScanner")


def test_an_empty_scanner_name_cannot_be_tracked(tracker):
    with pytest.raises(ValueError, match="non-empty"):
        tracker.update_scanner_state("")


def test_an_unknown_state_field_is_warned_about_rather_than_set(tracker):
    logger = create_autospec(ASH_LOGGER)
    tracker.logger = logger

    state = tracker.update_scanner_state("bandit", no_such_field="x")

    assert not hasattr(state, "no_such_field")
    assert (
        "Unknown scanner state field: no_such_field" in logger.warning.call_args.args[0]
    )


def test_get_scanners_by_status_ignores_an_unknown_status_field(tracker):
    tracker.update_scanner_state("bandit", registration_status="registered")

    assert tracker.get_scanners_by_status("registration_status", "registered") == [
        "bandit"
    ]
    assert tracker.get_scanners_by_status("no_such_field", "registered") == []


# ---------------------------------------------------------------------------
# ValidationCheckpointer.create_checkpoint
# ---------------------------------------------------------------------------


def test_creating_a_clean_checkpoint_records_it(checkpointer, quiet):
    checkpoint = checkpointer.create_checkpoint(
        "clean", expected_scanners=["bandit"], actual_scanners=["bandit"]
    )

    assert checkpointer.checkpoints == [checkpoint]
    assert checkpoint.has_issues() is False


def test_creating_a_checkpoint_with_issues_logs_the_missing_and_unexpected_sets(
    checkpointer, quiet
):
    checkpoint = checkpointer.create_checkpoint(
        "dirty",
        expected_scanners=["bandit", "semgrep"],
        actual_scanners=["semgrep", "grype"],
        errors=["something went wrong"],
    )

    assert checkpoint.has_issues() is True
    assert list(checkpoint.get_missing_scanners()) == ["bandit"]
    assert list(checkpoint.get_unexpected_scanners()) == ["grype"]

    logged = " ".join(str(c.args[0]) for c in quiet.debug.call_args_list)
    assert "Missing scanners: bandit" in logged
    assert "Unexpected scanners: grype" in logged


def test_a_checkpoint_with_only_missing_scanners_logs_no_unexpected_line(
    checkpointer, quiet
):
    checkpointer.create_checkpoint(
        "missing_only",
        expected_scanners=["bandit"],
        actual_scanners=[],
        errors=["e"],
    )

    logged = " ".join(str(c.args[0]) for c in quiet.debug.call_args_list)
    assert "Missing scanners: bandit" in logged
    assert "Unexpected scanners" not in logged


def test_a_checkpoint_with_only_unexpected_scanners_logs_no_missing_line(
    checkpointer, quiet
):
    checkpointer.create_checkpoint(
        "unexpected_only",
        expected_scanners=[],
        actual_scanners=["grype"],
        errors=["e"],
    )

    logged = " ".join(str(c.args[0]) for c in quiet.debug.call_args_list)
    assert "Unexpected scanners: grype" in logged
    assert "Missing scanners" not in logged


# ---------------------------------------------------------------------------
# _create_missing_scanner_result_entry status mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_status,expected",
    [
        ("completed", ScannerStatus.PASSED),
        ("excluded", ScannerStatus.SKIPPED),
        ("missing_deps", ScannerStatus.MISSING),
        ("failed", ScannerStatus.ERROR),
        ("missing", ScannerStatus.MISSING),
        ("some-future-status", ScannerStatus.MISSING),
    ],
)
def test_each_execution_status_maps_to_its_scanner_status(
    checkpointer, tracker, quiet, raw_status, expected
):
    with patch.object(
        tracker,
        "determine_scanner_status_from_execution_data",
        return_value=_status(raw_status),
    ):
        entry = checkpointer._create_missing_scanner_result_entry("bandit", None)

    assert entry.status is expected


def test_the_result_entry_carries_the_dependency_and_exclusion_flags(
    checkpointer, tracker, quiet
):
    with patch.object(
        tracker,
        "determine_scanner_status_from_execution_data",
        return_value=_status(
            "missing_deps", dependencies_satisfied=False, excluded=True
        ),
    ):
        entry = checkpointer._create_missing_scanner_result_entry("bandit", None)

    assert entry.dependencies_satisfied is False
    assert entry.excluded is True


# ---------------------------------------------------------------------------
# _get_executed_scanners_from_validation_state
# ---------------------------------------------------------------------------


def test_executed_scanners_are_read_from_the_results_keys(checkpointer, quiet):
    results = AshAggregatedResults()
    results.scanner_results = {"bandit": None, "semgrep": None}

    assert checkpointer._get_executed_scanners_from_validation_state(results) == [
        "bandit",
        "semgrep",
    ]


def test_class_name_and_empty_keys_are_excluded_from_executed_scanners(
    checkpointer, quiet
):
    """Legacy class-name entries predate name validation and must be ignored."""
    results = AshAggregatedResults()
    results.scanner_results = {"bandit": None, "BanditScanner": None, "": None}

    assert checkpointer._get_executed_scanners_from_validation_state(results) == [
        "bandit"
    ]


def test_a_completed_tracker_state_counts_as_executed(checkpointer, tracker, quiet):
    tracker.update_scanner_state("semgrep", registration_status="registered")
    results = AshAggregatedResults()
    results.scanner_results = {}

    with patch.object(
        tracker,
        "determine_scanner_status_from_execution_data",
        return_value=_status("completed"),
    ):
        executed = checkpointer._get_executed_scanners_from_validation_state(results)

    assert executed == ["semgrep"]


def test_a_non_completed_tracker_state_does_not_count_as_executed(
    checkpointer, tracker, quiet
):
    tracker.update_scanner_state("semgrep", registration_status="registered")
    results = AshAggregatedResults()
    results.scanner_results = {}

    with patch.object(
        tracker,
        "determine_scanner_status_from_execution_data",
        return_value=_status("failed"),
    ):
        executed = checkpointer._get_executed_scanners_from_validation_state(results)

    assert executed == []


def test_a_scanner_in_both_results_and_tracker_state_is_not_double_counted(
    checkpointer, tracker, quiet
):
    """The already-seen guard must be observable, not just deduplicated away.

    The return value alone cannot prove the guard works: the function ends with
    ``sorted(set(executed_scanners))``, so a scanner appended twice still comes
    back once. The guard's real effect is that a scanner already known from the
    results keys is not *also* reported as newly discovered in validation state,
    so the debug line is what distinguishes the two behaviors.
    """
    tracker.update_scanner_state("bandit", registration_status="registered")
    results = AshAggregatedResults()
    results.scanner_results = {"bandit": None}

    with patch.object(
        tracker,
        "determine_scanner_status_from_execution_data",
        return_value=_status("completed"),
    ):
        executed = checkpointer._get_executed_scanners_from_validation_state(results)

    assert executed == ["bandit"]
    debug = " ".join(str(c.args[0]) for c in quiet.debug.call_args_list)
    assert "already in results" in debug
    assert "marked as executed in validation state" not in debug


def test_a_class_named_tracker_state_is_skipped(checkpointer, tracker, quiet):
    """update_scanner_state rejects class names, so this state is injected directly."""
    tracker.update_scanner_state("bandit", registration_status="registered")
    legacy = tracker.scanner_states["bandit"]
    tracker.scanner_states["LegacyScanner"] = legacy
    results = AshAggregatedResults()
    results.scanner_results = {}

    with patch.object(
        tracker,
        "determine_scanner_status_from_execution_data",
        return_value=_status("completed"),
    ):
        executed = checkpointer._get_executed_scanners_from_validation_state(results)

    assert executed == ["bandit"]


# ---------------------------------------------------------------------------
# ensure_complete_results
# ---------------------------------------------------------------------------


def test_a_registered_scanner_absent_from_results_is_added_as_missing(
    checkpointer, tracker, quiet
):
    tracker.update_scanner_state(
        "bandit", registration_status="registered", enablement_status="missing_deps"
    )
    results = AshAggregatedResults()
    results.scanner_results = {}

    checkpoint = checkpointer.ensure_complete_results(results)

    assert results.scanner_results["bandit"].status is ScannerStatus.MISSING
    assert tracker.get_scanner_state("bandit").included_in_results is True
    assert any("was missing from results" in d for d in checkpoint.discrepancies)
    assert quiet.warning.call_count >= 1


def test_a_failed_scanner_is_added_with_an_error_status_and_logged_as_an_error(
    checkpointer, tracker, quiet
):
    tracker.update_scanner_state("bandit", registration_status="registered")
    results = AshAggregatedResults()
    results.scanner_results = {}

    with patch.object(
        tracker,
        "determine_scanner_status_from_execution_data",
        return_value=_status("failed", failure_reason="tool crashed"),
    ):
        checkpointer.ensure_complete_results(results)

    assert results.scanner_results["bandit"].status is ScannerStatus.ERROR
    errors = " ".join(str(c.args[0]) for c in quiet.error.call_args_list)
    assert "EXECUTION FAILED" in errors
    assert "tool crashed" in errors


def test_a_passing_scanner_added_back_is_logged_at_verbose_not_warning(
    checkpointer, tracker, quiet
):
    """PASSED and SKIPPED take the quiet branch; only ERROR/MISSING escalate."""
    tracker.update_scanner_state("bandit", registration_status="registered")
    results = AshAggregatedResults()
    results.scanner_results = {}

    with (
        patch.object(
            checkpointer,
            "_get_executed_scanners_from_validation_state",
            return_value=[],
        ),
        patch.object(
            tracker,
            "determine_scanner_status_from_execution_data",
            return_value=_status("completed"),
        ),
    ):
        checkpointer.ensure_complete_results(results)

    assert results.scanner_results["bandit"].status is ScannerStatus.PASSED
    assert quiet.error.call_count == 0
    verbose = " ".join(str(c.args[0]) for c in quiet.verbose.call_args_list)
    assert "+ Added 'bandit'" in verbose


def test_a_none_results_mapping_is_initialized_before_insertion(
    checkpointer, tracker, quiet
):
    tracker.update_scanner_state(
        "bandit", registration_status="registered", enablement_status="missing_deps"
    )
    results = AshAggregatedResults()
    results.scanner_results = None

    checkpointer.ensure_complete_results(results)

    assert results.scanner_results is not None
    assert "bandit" in results.scanner_results


def test_a_properly_excluded_scanner_is_not_added_back_to_results(
    checkpointer, tracker, quiet
):
    tracker.update_scanner_state(
        "bandit", registration_status="registered", enablement_status="excluded"
    )
    results = AshAggregatedResults()
    results.scanner_results = {}

    checkpointer.ensure_complete_results(results)

    assert "bandit" not in results.scanner_results


def test_a_scanner_already_in_results_is_skipped_by_the_defensive_double_check(
    checkpointer, tracker, quiet
):
    """Reaches the guard that fires when the two scanner sets disagree.

    ``_get_executed_scanners_from_validation_state`` normally derives the actual
    set from the results keys, so a name cannot be both 'missing' and present.
    The helper is stubbed to return nothing so the two computations disagree,
    which is precisely the condition the double-check exists for.
    """
    tracker.update_scanner_state("bandit", registration_status="registered")
    results = AshAggregatedResults()
    results.scanner_results = {"bandit": "pre-existing entry"}

    with patch.object(
        checkpointer, "_get_executed_scanners_from_validation_state", return_value=[]
    ):
        checkpointer.ensure_complete_results(results)

    assert results.scanner_results["bandit"] == "pre-existing entry"
    debug = " ".join(str(c.args[0]) for c in quiet.debug.call_args_list)
    assert "already exists in results, skipping" in debug


def test_an_unregistered_scanner_found_in_results_is_marked_untracked(
    checkpointer, tracker, quiet
):
    results = AshAggregatedResults()
    results.scanner_results = {"mystery": None}

    checkpoint = checkpointer.ensure_complete_results(results)

    state = tracker.get_scanner_state("mystery")
    assert state.registration_status == "untracked"
    assert state.included_in_results is True
    assert any(
        "found in results but not registered" in d for d in checkpoint.discrepancies
    )
    verbose = " ".join(str(c.args[0]) for c in quiet.verbose.call_args_list)
    assert "Unexpected scanners found: mystery" in verbose


def test_a_registered_scanner_present_in_results_is_marked_included(
    checkpointer, tracker, quiet
):
    tracker.update_scanner_state("bandit", registration_status="registered")
    results = AshAggregatedResults()
    results.scanner_results = {"bandit": None}

    checkpoint = checkpointer.ensure_complete_results(results)

    assert tracker.get_scanner_state("bandit").included_in_results is True
    assert checkpoint.discrepancies == []
    verbose = " ".join(str(c.args[0]) for c in quiet.verbose.call_args_list)
    assert "no missing scanners to add" in verbose


def test_ensure_complete_results_on_an_empty_state_passes_without_issues(
    checkpointer, quiet
):
    results = AshAggregatedResults()
    results.scanner_results = {}

    checkpoint = checkpointer.ensure_complete_results(results)

    assert checkpoint.has_issues() is False
    verbose = " ".join(str(c.args[0]) for c in quiet.verbose.call_args_list)
    assert "passed without issues" in verbose


# ---------------------------------------------------------------------------
# add_queue_validation_error
# ---------------------------------------------------------------------------


def test_a_queue_error_attaches_to_the_latest_queue_validation_checkpoint(
    checkpointer, quiet
):
    checkpointer.create_checkpoint("task_queue_validation")
    checkpointer.create_checkpoint("task_queue_validation")
    checkpointer.create_checkpoint("something_else")

    checkpointer.add_queue_validation_error("queue was empty")

    queue_checkpoints = [
        c
        for c in checkpointer.checkpoints
        if c.checkpoint_name == "task_queue_validation"
    ]
    assert queue_checkpoints[-1].errors == ["queue was empty"]
    assert queue_checkpoints[0].errors == []
    assert "Queue validation error: queue was empty" in quiet.error.call_args.args[0]


def test_a_queue_error_with_no_queue_checkpoint_creates_one(checkpointer, quiet):
    """The for/else fires only when no matching checkpoint exists."""
    checkpointer.create_checkpoint("unrelated")

    checkpointer.add_queue_validation_error("nothing was queued")

    created = checkpointer.checkpoints[-1]
    assert created.checkpoint_name == "task_queue_validation_errors"
    assert created.errors == ["nothing was queued"]
    assert "No queue validation checkpoint found" in quiet.warning.call_args.args[0]


def test_a_queue_error_on_an_empty_checkpoint_list_creates_one(checkpointer, quiet):
    checkpointer.add_queue_validation_error("nothing at all")

    assert checkpointer.checkpoints[-1].checkpoint_name == (
        "task_queue_validation_errors"
    )


# ---------------------------------------------------------------------------
# handle_queue_validation_errors
# ---------------------------------------------------------------------------


def test_handling_a_clean_checkpoint_changes_no_state(checkpointer, tracker, quiet):
    checkpoint = ValidationCheckpoint(
        checkpoint_name="task_queue_validation",
        expected_scanners=["bandit"],
        actual_scanners=["bandit"],
    )

    checkpointer.handle_queue_validation_errors(checkpoint)

    assert tracker.scanner_states == {}
    assert quiet.warning.call_count == 0


def test_handling_missing_queue_entries_records_a_failure_reason(
    checkpointer, tracker, quiet
):
    """An error is required to open the gate; see the test below for why."""
    checkpoint = ValidationCheckpoint(
        checkpoint_name="task_queue_validation",
        expected_scanners=["bandit", "semgrep"],
        actual_scanners=["semgrep"],
        errors=["queue mismatch"],
    )

    checkpointer.handle_queue_validation_errors(checkpoint)

    state = tracker.get_scanner_state("bandit")
    assert state is not None
    assert "expected to be queued" in state.failure_reason
    assert "1 scanners missing from queue" in quiet.warning.call_args.args[0]


def test_missing_queue_entries_alone_do_not_open_the_error_handling_gate(
    checkpointer, tracker, quiet
):
    """``has_issues()`` counts discrepancies and errors, not missing scanners.

    A checkpoint whose expected set exceeds its actual set therefore reads as
    clean, and ``handle_queue_validation_errors`` records no failure reason for
    the scanners that never reached the queue. This pins the current behavior so
    a change to either ``has_issues()`` or this gate is visible rather than
    silent -- it is the same shape as a MISSING-scanner run reading as healthy.
    """
    checkpoint = ValidationCheckpoint(
        checkpoint_name="task_queue_validation",
        expected_scanners=["bandit", "semgrep"],
        actual_scanners=["semgrep"],
    )

    assert list(checkpoint.get_missing_scanners()) == ["bandit"]
    assert checkpoint.has_issues() is False

    checkpointer.handle_queue_validation_errors(checkpoint)

    assert tracker.get_scanner_state("bandit") is None


def test_handling_a_checkpoint_with_errors_but_no_missing_scanners_logs_each_error(
    checkpointer, tracker, quiet
):
    checkpoint = ValidationCheckpoint(
        checkpoint_name="task_queue_validation",
        expected_scanners=["bandit"],
        actual_scanners=["bandit"],
        errors=["queue timed out", "worker died"],
    )

    checkpointer.handle_queue_validation_errors(checkpoint)

    logged = " ".join(str(c.args[0]) for c in quiet.error.call_args_list)
    assert "queue timed out" in logged
    assert "worker died" in logged
    assert tracker.scanner_states == {}


def test_handling_errors_accepts_an_optional_scan_results_argument(
    checkpointer, tracker, quiet
):
    checkpoint = ValidationCheckpoint(
        checkpoint_name="task_queue_validation", errors=["boom"]
    )

    assert (
        checkpointer.handle_queue_validation_errors(checkpoint, scan_results=object())
        is None
    )


# ---------------------------------------------------------------------------
# ScannerValidationManager facade
# ---------------------------------------------------------------------------


@pytest.fixture
def manager(tmp_path):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME

    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return ScannerValidationManager(
        plugin_context=PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=work_dir,
            config=AshConfig(project_name="test"),
        )
    )


def test_the_manager_delegates_queue_error_recording_to_the_checkpointer(manager):
    manager.add_queue_validation_error("delegated error", scanner_name="bandit")

    assert manager.checkpoints[-1].errors == ["delegated error"]
    assert manager.checkpoints[-1].checkpoint_name == "task_queue_validation_errors"


def test_the_manager_exposes_the_tracker_state_and_checkpoint_lists(manager):
    manager.update_scanner_state("bandit", registration_status="registered")

    assert "bandit" in manager.scanner_states
    assert manager.get_scanner_state("bandit").registration_status == "registered"
    assert manager.checkpoints == []
