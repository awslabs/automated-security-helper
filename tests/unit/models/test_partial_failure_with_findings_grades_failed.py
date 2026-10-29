# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A partial target loss with gate-failing findings grades FAILED, not ERROR.

``determine_status`` graded ERROR whenever any target failed, before the
severity gate ran. For a scanner that evaluated most of its targets and found
real problems on them, that order hid the findings from everything that gates
on FAILED: the executor promotes only PASSED and SKIPPED rows, so a FAILED row
is the one consumers waive or block on, and an ERROR row reads as "nothing to
waive". cdk-nag records every unevaluable template as a failed target, so one
such template relabeled a run full of HIGH findings as ERROR.

The order is now: on a PARTIAL loss (some targets evaluated, some failed) the
severity gate runs first -- FAILED when the surviving findings fail it, ERROR
otherwise. A scanner whose every attempted target failed, or whose counters
are poisoned, still grades ERROR unconditionally: nothing was evaluated, so
there are no findings to outrank the loss.
"""

import pytest

from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)
from automated_security_helper.core.enums import ScannerStatus

pytestmark = pytest.mark.unit


def _partial_container(**counts) -> ScanResultsContainer:
    container = ScanResultsContainer(scanner_name="probe")
    container.targets_attempted = 10
    container.targets_failed = 4
    for name, value in counts.items():
        setattr(container.severity_counts, name, value)
    return container


def test_a_partial_loss_with_gate_failing_findings_grades_failed():
    container = _partial_container(high=3)

    assert container.determine_status("MEDIUM") == ScannerStatus.FAILED


def test_a_partial_loss_with_no_findings_still_grades_error():
    container = _partial_container()

    assert container.determine_status("MEDIUM") == ScannerStatus.ERROR


def test_a_partial_loss_with_only_sub_threshold_findings_grades_error():
    container = _partial_container(low=5)

    assert container.determine_status("MEDIUM") == ScannerStatus.ERROR


def test_an_all_failed_run_grades_error_whatever_it_found():
    container = ScanResultsContainer(scanner_name="probe")
    container.targets_attempted = 4
    container.targets_failed = 4
    container.severity_counts.critical = 2

    assert container.determine_status("MEDIUM") == ScannerStatus.ERROR


def test_a_poisoned_attempted_count_grades_error_whatever_it_found():
    container = ScanResultsContainer(scanner_name="probe")
    container.targets_attempted = -1
    container.targets_failed = 0
    container.severity_counts.critical = 2

    assert container.determine_status("MEDIUM") == ScannerStatus.ERROR
