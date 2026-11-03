# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The stack trace recorded for an exception that was built but never raised.

``set_exception`` and ``for_failure`` record the trace of the exception they are
given. A caller that wraps what it caught, ``RuntimeError(f"...: {e}")`` inside its
``except``, gives one that was never raised: it has no traceback, so its own trace
is one line and the frames of the failure were lost. The trace of the exception
being handled is the one there is.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)

pytestmark = pytest.mark.unit


def _raised(error: BaseException) -> BaseException:
    """``error``, raised and caught here, so it carries a traceback."""
    try:
        raise error
    except type(error) as caught:
        return caught


def test_an_exception_never_raised_is_traced_by_the_one_being_handled():
    container = ScanResultsContainer(scanner_name="scripted")

    try:
        raise KeyError("being-handled")
    except KeyError as handled:
        container.set_exception(RuntimeError(f"wrapped: {handled}"))

    trace = container.stack_trace or ""
    assert "Traceback (most recent call last)" in trace, trace
    assert "being-handled" in trace, trace
    assert (
        "test_an_exception_never_raised_is_traced_by_the_one_being_handled" in trace
    ), trace
    assert container.exception == "wrapped: 'being-handled'"
    assert container.status == ScannerStatus.FAILED


def test_for_failure_traces_an_exception_never_raised_the_same_way():
    try:
        raise KeyError("being-handled")
    except KeyError as handled:
        container = ScanResultsContainer.for_failure(
            "scripted", exception=RuntimeError(f"wrapped: {handled}")
        )

    trace = container.stack_trace or ""
    assert "Traceback (most recent call last)" in trace, trace
    assert "being-handled" in trace, trace
    assert container.errors == ["wrapped: 'being-handled'"]


def test_an_exception_never_raised_outside_a_handler_keeps_its_one_line_trace():
    container = ScanResultsContainer(scanner_name="scripted")

    container.set_exception(RuntimeError("nothing-was-raised"))

    trace = container.stack_trace or ""
    assert "RuntimeError: nothing-was-raised" in trace, trace
    assert container.exception == "nothing-was-raised"


def test_a_raised_exception_keeps_its_own_trace_inside_another_handler():
    given = _raised(ValueError("given-one"))
    container = ScanResultsContainer(scanner_name="scripted")

    try:
        raise KeyError("being-handled")
    except KeyError:
        container.set_exception(given)

    trace = container.stack_trace or ""
    assert "given-one" in trace, trace
    assert "being-handled" not in trace, trace


def test_the_exception_being_handled_is_not_taken_for_itself():
    container = ScanResultsContainer(scanner_name="scripted")

    try:
        raise KeyError("being-handled")
    except KeyError as handled:
        container.set_exception(handled)

    trace = container.stack_trace or ""
    assert "Traceback (most recent call last)" in trace, trace
    assert "being-handled" in trace, trace
