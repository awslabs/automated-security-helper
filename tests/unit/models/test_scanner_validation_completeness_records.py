# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The validation records say what happened, as the low findings read them.

What each test pins, and what it read at the base before the fix:

* a checkpoint's timestamp is an aware UTC datetime (a naive local one was
  serialized without an offset beside every other UTC-aware timestamp);
* the enablement pass keeps the exclusion reason the filtering recorded (it
  rewrote every one to "excluded by configuration");
* the execution completion rate is the share of the expected scanners that
  completed, and nothing expected is 100% (a completed name outside the set
  inflated it past 100%, and nothing expected read 0%);
* the result completeness rate counts registered scanners with a row (an
  unregistered row inflated it), and the log calls the rows present, not
  "executed successfully";
* a completed scanner with no row is backfilled (its state counted as a row,
  so it was never added and no discrepancy was recorded);
* a missing scanner's discrepancy carries the reason its state holds, and a
  deliberately excluded scanner is no discrepancy (the text read "None" and the
  excluded scanner was listed);
* the completeness checkpoint records the final count and the rows added, and
  has_adjustments says whether rows were added (it mirrored has_issues, so an
  unregistered row read as an adjustment);
* a queue error with no queue checkpoint creates one the lookup finds, and
  names the scanner on its state (the fallback's name never matched, so every
  error made another checkpoint, and the scanner name was dropped).
"""

from __future__ import annotations

from datetime import timezone
from unittest.mock import create_autospec

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import (
    ScannerStateTracker,
    ValidationCheckpoint,
    ValidationCheckpointer,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


@pytest.fixture
def tracker():
    return ScannerStateTracker()


@pytest.fixture
def checkpointer(tracker):
    pointer = ValidationCheckpointer(tracker)
    pointer.logger = create_autospec(ASH_LOGGER)
    return pointer


def test_a_checkpoint_timestamp_is_utc_aware():
    """Red before the fix: datetime.now() with no tzinfo."""
    checkpoint = ValidationCheckpoint(checkpoint_name="cp")

    assert checkpoint.timestamp.tzinfo is not None
    assert checkpoint.timestamp.utcoffset() == timezone.utc.utcoffset(None)
    assert checkpoint.timestamp.isoformat().endswith("+00:00")


def test_the_enablement_pass_keeps_the_filterings_exclusion_reason(
    checkpointer, tracker
):
    """Red before the fix: the reason was rewritten to 'excluded by configuration'."""
    tracker.update_scanner_state(
        "bandit",
        registration_status="registered",
        enablement_status="excluded",
        enablement_reason="Scanner excluded during filtering: nothing to scan",
    )
    tracker.update_scanner_state("semgrep", registration_status="registered")

    checkpointer.validate_scanner_enablement(
        enabled_scanners=[], excluded_scanners=["bandit", "semgrep"]
    )

    assert (
        tracker.get_scanner_state("bandit").enablement_reason
        == "Scanner excluded during filtering: nothing to scan"
    )
    # Control: a scanner with no recorded reason gets the generic one.
    assert (
        tracker.get_scanner_state("semgrep").enablement_reason
        == "Scanner is excluded by configuration"
    )


def test_the_completion_rate_counts_only_expected_scanners(checkpointer, tracker):
    """Red before the fix: 2/2 = 100% for one expected scanner missing and one
    completed name outside the expected set."""
    tracker.update_scanner_state(
        "bandit", registration_status="registered", queued_for_execution=True
    )
    tracker.update_scanner_state(
        "semgrep", registration_status="registered", queued_for_execution=True
    )
    tracker.update_scanner_state("grype", registration_status="registered")

    checkpoint = checkpointer.validate_execution_completion(["bandit", "grype"])

    assert checkpoint.metadata["completion_rate"] == 0.5
    assert checkpoint.get_missing_scanners() == ["semgrep"]


def test_nothing_expected_is_a_complete_run(checkpointer):
    """Red before the fix: 0.0, against ensure_complete_results' 1.0 for the
    same empty case."""
    checkpoint = checkpointer.validate_execution_completion([])

    assert checkpoint.metadata["completion_rate"] == 1.0


def test_the_completeness_rate_counts_registered_scanners_with_a_row(
    checkpointer, tracker
):
    """Red before the fix: 2/2 = 100% with one registered scanner missing and a
    load-error module row counted in its place."""
    tracker.update_scanner_state("bandit", registration_status="registered")
    tracker.update_scanner_state(
        "semgrep",
        registration_status="registered",
        enablement_status="missing_deps",
        dependency_errors=["semgrep is not installed"],
    )
    results = AshAggregatedResults()
    results.scanner_results = {"bandit": None, "some.module.that.failed": None}

    checkpoint = checkpointer.ensure_complete_results(results)

    assert checkpoint.metadata["completeness_rate"] == 0.5
    verbose = " ".join(
        str(c.args[0]) for c in checkpointer.logger.verbose.call_args_list
    )
    assert "Scanners present in results" in verbose
    assert "executed successfully" not in verbose


def test_a_missing_scanners_discrepancy_names_the_reason_its_state_holds(
    checkpointer, tracker
):
    """Red before the fix: failure_reason alone was read, so the text said
    'missing from results: None' for a scanner missing its dependencies."""
    tracker.update_scanner_state(
        "semgrep",
        registration_status="registered",
        enablement_status="missing_deps",
        dependency_errors=["semgrep is not installed"],
    )
    results = AshAggregatedResults()
    results.scanner_results = {}

    checkpoint = checkpointer.ensure_complete_results(results)

    expected = (
        "Scanner 'semgrep' was missing from results: Missing dependencies: "
        "semgrep is not installed"
    )
    assert checkpoint.discrepancies == [expected]


def test_an_excluded_scanner_is_no_discrepancy(checkpointer, tracker):
    """Red before the fix: the excluded scanner was skipped from the backfill
    and still recorded as a discrepancy, with the reason None."""
    tracker.update_scanner_state(
        "bandit", registration_status="registered", enablement_status="excluded"
    )
    results = AshAggregatedResults()
    results.scanner_results = {}

    checkpoint = checkpointer.ensure_complete_results(results)

    assert "bandit" not in results.scanner_results
    assert checkpoint.discrepancies == []
    assert (
        checkpointer.report_result_completeness(checkpoint)["has_adjustments"] is False
    )


def test_has_adjustments_says_whether_rows_were_added(checkpointer, tracker):
    """Red before the fix: it mirrored has_issues(), so an unregistered row
    already in the results read as an adjustment although nothing was added."""
    tracker.update_scanner_state("bandit", registration_status="registered")
    results = AshAggregatedResults()
    results.scanner_results = {"bandit": None, "some.module.that.failed": None}

    checkpoint = checkpointer.ensure_complete_results(results)
    report = checkpointer.report_result_completeness(checkpoint)

    assert checkpoint.has_issues() is True
    assert report["has_adjustments"] is False
    assert report["unexpected_scanners"] == ["some.module.that.failed"]


def test_a_checkpoint_without_the_added_record_keeps_the_old_reading(checkpointer):
    """Control: a checkpoint built some other way still reads has_issues()."""
    checkpoint = checkpointer.create_checkpoint(
        "cp", expected_scanners=["bandit"], actual_scanners=[]
    )

    assert (
        checkpointer.report_result_completeness(checkpoint)["has_adjustments"]
        is checkpoint.has_issues()
    )


def test_queue_errors_without_a_checkpoint_land_on_one_checkpoint(
    checkpointer, tracker
):
    """Red before the fix: the fallback was named task_queue_validation_errors,
    which the lookup never found, so the second error made a second checkpoint;
    and scanner_name was never read."""
    tracker.update_scanner_state("bandit", registration_status="registered")

    checkpointer.add_queue_validation_error("first", scanner_name="bandit")
    checkpointer.add_queue_validation_error("second")

    assert len(checkpointer.checkpoints) == 1
    assert checkpointer.checkpoints[0].checkpoint_name == "task_queue_validation"
    assert checkpointer.checkpoints[0].errors == ["first", "second"]
    assert tracker.get_scanner_state("bandit").failure_reason == "first"


def test_a_queue_error_about_an_untracked_scanner_tracks_nothing(checkpointer, tracker):
    """Control: a name the tracker does not know is not created by an error."""
    checkpointer.add_queue_validation_error("stray", scanner_name="unknown")

    assert tracker.get_scanner_state("unknown") is None
