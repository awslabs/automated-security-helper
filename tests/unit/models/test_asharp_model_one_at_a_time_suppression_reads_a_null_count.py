# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Recording one suppressed finding at a time reads a row whose count is null.

``ScannerTargetStatusInfo.suppressed_finding_count`` is declared ``int | None``, so
a results file can carry ``null`` for it. The call that records one finding at a
time (``_apply_suppression_side_effects`` with no count) added one to the field as
it stood and raised ``TypeError`` on ``None``. A null count now reads as zero, so
the row ends at one.

The controls say a count that is set is added to, and that a call with a count
still sets it.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)

pytestmark = pytest.mark.unit


def _model_with(row) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.scanner_results["bandit"] = row
    return model


def test_a_row_loaded_with_a_null_count_ends_at_one():
    row = ScannerTargetStatusInfo.model_validate({"suppressed_finding_count": None})
    assert row.suppressed_finding_count is None, "the row must carry the null"
    model = _model_with(row)

    model._apply_suppression_side_effects("bandit")

    assert model.scanner_results["bandit"].suppressed_finding_count == 1
    assert model.scanner_results["bandit"].severity_counts.suppressed == 1


def test_a_dict_row_with_a_null_count_ends_at_one():
    model = _model_with({"status": "PASSED", "suppressed_finding_count": None})

    model._apply_suppression_side_effects("bandit")

    row = model.scanner_results["bandit"]
    assert isinstance(row, ScannerTargetStatusInfo)
    assert row.suppressed_finding_count == 1
    assert row.severity_counts.suppressed == 1


def test_a_second_call_on_a_null_count_ends_at_two():
    row = ScannerTargetStatusInfo.model_validate({"suppressed_finding_count": None})
    model = _model_with(row)

    model._apply_suppression_side_effects("bandit")
    model._apply_suppression_side_effects("bandit")

    assert model.scanner_results["bandit"].suppressed_finding_count == 2
    assert model.scanner_results["bandit"].severity_counts.suppressed == 2


def test_a_count_that_is_set_is_added_to():
    model = _model_with(ScannerTargetStatusInfo(suppressed_finding_count=4))

    model._apply_suppression_side_effects("bandit")

    assert model.scanner_results["bandit"].suppressed_finding_count == 5


def test_a_call_with_a_count_sets_it_over_a_null():
    row = ScannerTargetStatusInfo.model_validate({"suppressed_finding_count": None})
    model = _model_with(row)

    model._apply_suppression_side_effects("bandit", 3)

    assert model.scanner_results["bandit"].suppressed_finding_count == 3
    assert model.scanner_results["bandit"].severity_counts.suppressed == 3
