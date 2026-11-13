# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A recorded target failure never reads as a skip or a success.

A scanner can claim zero attempted targets and then record a failure: the
first ``record_target_attempt(0)`` moves ``targets_attempted`` off None, and
``record_target_failure`` raises ``targets_failed`` without touching it. The
status then has a failure count beside an attempt count of zero, which is a
contradiction in the producer's accounting, the same kind as a failure count
beside no attempt count at all. Both grade ERROR, and ``scan_succeeded`` is
False for both, so a report cannot render the run as skipped or successful
while its own counters say a target failed.

The plain tracked-but-zero run (attempted 0, failed 0) keeps its SKIPPED
status and its successful execution, and the partial arm keeps its
gate-first rule.
"""

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)

pytestmark = pytest.mark.unit


def _container(attempted, failed) -> ScanResultsContainer:
    container = ScanResultsContainer(scanner_name="probe")
    container.targets_attempted = attempted
    container.targets_failed = failed
    return container


def test_a_failure_beside_zero_attempts_grades_error():
    container = _container(0, 1)

    assert container.determine_status("MEDIUM") == ScannerStatus.ERROR
    assert container.scan_succeeded is False


def test_the_recorded_path_reaches_the_same_answer():
    container = ScanResultsContainer(scanner_name="probe")
    container.record_target_attempt(0)
    container.record_target_failure("template.yaml", "could not be read")

    assert container.targets_attempted == 0
    assert container.targets_failed == 1
    assert container.determine_status("MEDIUM") == ScannerStatus.ERROR
    assert container.scan_succeeded is False


def test_a_failure_beside_no_attempt_claim_grades_error_without_a_type_error():
    container = _container(None, 1)

    assert container.determine_status("MEDIUM") == ScannerStatus.ERROR
    assert container.scan_succeeded is False


def test_a_negative_failure_count_grades_error():
    container = _container(3, -1)

    assert container.determine_status("MEDIUM") == ScannerStatus.ERROR
    assert container.scan_succeeded is False


@pytest.mark.parametrize("attempted", [0, None])
def test_a_negative_failure_count_beside_no_attempts_is_an_unsuccessful_error(
    attempted,
):
    container = _container(attempted, -1)

    assert container.determine_status("MEDIUM") == ScannerStatus.ERROR
    assert container.scan_succeeded is False


@pytest.mark.parametrize("threshold", ["MEDIUM", None])
def test_a_tracked_run_with_nothing_to_attempt_still_skips(threshold):
    container = _container(0, 0)

    assert container.determine_status(threshold) == ScannerStatus.SKIPPED
    assert container.scan_succeeded is True


def test_a_partial_loss_keeps_the_gate_first_rule():
    failing = _container(10, 4)
    failing.severity_counts.high = 3
    clean = _container(10, 4)

    assert failing.determine_status("MEDIUM") == ScannerStatus.FAILED
    assert clean.determine_status("MEDIUM") == ScannerStatus.ERROR
