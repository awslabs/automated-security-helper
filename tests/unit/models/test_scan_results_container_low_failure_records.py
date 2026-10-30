# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a results container records about a failure, and how a zero-attempt one grades.

``set_exception`` recorded the traceback of whatever exception was being handled
where it was called, not of the one it was given. ``for_failure`` listed a failure
twice when it was given both as an error and as an exception, and recorded a run of
0 seconds for a scanner with no timed run. And ``determine_status`` graded a
tracking container that attempted no target SKIPPED even when its findings failed
the gate.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import ScannerSeverityCount
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)

pytestmark = pytest.mark.unit


def _raised(error: BaseException) -> BaseException:
    """``error``, raised and caught here, so it carries a traceback and is not being handled."""
    try:
        raise error
    except type(error) as caught:
        return caught


def test_the_stack_trace_is_the_one_of_the_exception_given_not_the_one_being_handled():
    given = _raised(ValueError("given-one"))
    container = ScanResultsContainer(scanner_name="scripted")

    try:
        raise KeyError("being-handled")
    except KeyError:
        container.set_exception(given)

    assert "given-one" in (container.stack_trace or ""), container.stack_trace
    assert "being-handled" not in (container.stack_trace or ""), container.stack_trace
    assert container.exception == "given-one"
    assert container.status == ScannerStatus.FAILED


def test_the_stack_trace_is_recorded_outside_any_handler():
    container = ScanResultsContainer(scanner_name="scripted")

    container.set_exception(_raised(ValueError("given-one")))

    assert "ValueError" in (container.stack_trace or ""), container.stack_trace
    assert "given-one" in (container.stack_trace or ""), container.stack_trace
    assert container.errors == ["given-one"]


def test_a_failure_has_no_recorded_duration():
    container = ScanResultsContainer.for_failure("scripted", errors=["it broke"])

    assert container.duration is None


def test_a_failure_given_as_an_error_and_as_an_exception_is_listed_once():
    container = ScanResultsContainer.for_failure(
        "scripted",
        errors=["Scanner scripted failed: boom"],
        exception=RuntimeError("boom"),
    )

    assert container.errors == ["Scanner scripted failed: boom"]
    assert container.exception == "boom"
    assert container.status == ScannerStatus.FAILED


def test_an_exception_text_the_errors_do_not_say_is_still_listed():
    container = ScanResultsContainer.for_failure(
        "scripted", errors=["Scanner scripted failed"], exception=RuntimeError("boom")
    )

    assert container.errors == ["Scanner scripted failed", "boom"]


def test_an_exception_alone_is_listed_as_an_error():
    container = ScanResultsContainer.for_failure(
        "scripted", exception=RuntimeError("boom")
    )

    assert container.errors == ["boom"]


def _attempted_nothing(**counts: int) -> ScanResultsContainer:
    container = ScanResultsContainer(
        scanner_name="scripted",
        targets_attempted=0,
        severity_counts=ScannerSeverityCount(**counts),
    )
    return container


def test_findings_that_fail_the_gate_beside_no_attempts_grade_failed():
    container = _attempted_nothing(high=1)

    assert container.determine_status("HIGH") == ScannerStatus.FAILED


def test_findings_below_the_gate_beside_no_attempts_still_grade_skipped():
    container = _attempted_nothing(high=1)

    assert container.determine_status("CRITICAL") == ScannerStatus.SKIPPED


def test_no_findings_and_no_attempts_still_grade_skipped():
    container = _attempted_nothing()

    assert container.determine_status("ALL") == ScannerStatus.SKIPPED
    assert container.determine_status(None) == ScannerStatus.SKIPPED
