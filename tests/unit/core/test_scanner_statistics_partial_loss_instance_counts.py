"""A partial-loss report carrying a ScannerSeverityCount instance is graded on it.

``target_report_is_partial_loss`` reads the report's ``severity_counts`` to decide
whether a partial loss is the ERROR a partial loss earns (findings pass the gate) or
the FAILED gate-failing findings earn. It validated a dict and replaced anything else
with empty counts, so a report whose counts were a ``ScannerSeverityCount`` instance
(a live container's own, before any dump) was graded on zeros, and a partial loss
whose findings fail the gate read as a partial-loss ERROR.

An instance is now read through its own dump, which also re-validates it: an
instance mutated after construction into a shape the model refuses is refused, as
an invalid dict is. The controls are the dict shape and the empty instance.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import ScannerSeverityCount

pytestmark = pytest.mark.unit


def _report(counts) -> dict:
    return {
        "scanner_name": "cdk-nag",
        "status": "ERROR",
        "targets_attempted": 3,
        "targets_failed": 1,
        "severity_counts": counts,
    }


def _is_partial_loss(counts) -> bool:
    return ScannerStatisticsCalculator.target_report_is_partial_loss(
        _report(counts), "MEDIUM"
    )


def test_an_instance_with_gate_failing_findings_is_not_a_partial_loss_error():
    assert _is_partial_loss(ScannerSeverityCount(high=1)) is False


def test_an_instance_mutated_into_a_refused_shape_is_refused():
    """Started from counts whose valid grade is a partial loss (no findings at
    all), so a False here can only come from the refusal: started from
    ``high=1``, False was also what the unchanged instance gave, and code that
    skipped the re-validation and read any non-zero ``high`` as a finding would
    have passed too."""
    counts = ScannerSeverityCount()
    assert _is_partial_loss(counts) is True
    counts.low = "many"

    assert _is_partial_loss(counts) is False


def test_a_dict_with_gate_failing_findings_is_graded_as_before():
    """Control."""
    assert _is_partial_loss({"high": 1}) is False


def test_an_empty_instance_is_a_partial_loss_error():
    """Control: nothing fails the gate, so the loss is the loudest fact."""
    assert _is_partial_loss(ScannerSeverityCount()) is True


def test_a_dict_whose_findings_pass_the_gate_is_a_partial_loss_error():
    """Control."""
    assert _is_partial_loss({"low": 2}) is True
