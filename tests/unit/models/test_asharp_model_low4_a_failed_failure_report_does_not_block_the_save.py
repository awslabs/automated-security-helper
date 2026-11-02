# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failure while reporting a failed final-metrics pass does not block the save.

``save_model`` populates the final metrics first, and the results file it then
writes is what marks the scan complete. The handler of a failed pass formats the
error for the log, and an error raised from that formatting escaped the handler and
`save_model` with it. The handler now falls back to the type of the first error.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

SECRET = "ENVCANARY-low4-values"


@pytest.fixture
def logged():
    lines = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(logging.Formatter("%(message)s").format(record))

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _pass_that_fails(monkeypatch) -> None:
    def refuse(_results):
        raise RuntimeError(f"could not read {SECRET}")

    monkeypatch.setattr(
        "automated_security_helper.core.unified_metrics.get_unified_scanner_metrics",
        refuse,
    )


def test_a_failed_pass_without_a_configuration_is_logged_not_raised(
    monkeypatch, logged
):
    model = AshAggregatedResults()
    assert model.ash_config is None
    _pass_that_fails(monkeypatch)

    model._populate_final_metrics()

    assert any("Error populating final metrics" in line for line in logged), logged
    assert any("Stack trace:" in line for line in logged), logged


def test_a_failure_of_the_error_text_falls_back_to_the_type_alone(monkeypatch, logged):
    model = AshAggregatedResults()
    _pass_that_fails(monkeypatch)

    def broken(_error, _values=()):
        raise ValueError("the text of the error could not be built")

    monkeypatch.setattr("automated_security_helper.utils.error_text.error_text", broken)

    model._populate_final_metrics()

    assert logged[-1] == "Error populating final metrics: RuntimeError", logged
    assert not any("Stack trace:" in line for line in logged), logged
    assert SECRET not in logged[-1]


def test_a_failure_of_the_stack_trace_text_falls_back_to_the_type_alone(
    monkeypatch, logged
):
    model = AshAggregatedResults()
    _pass_that_fails(monkeypatch)

    def broken(_error=None, values=()):
        raise ValueError("the trace could not be built")

    monkeypatch.setattr(
        "automated_security_helper.utils.error_text.traceback_text", broken
    )

    model._populate_final_metrics()

    assert logged[-1] == "Error populating final metrics: RuntimeError", logged
