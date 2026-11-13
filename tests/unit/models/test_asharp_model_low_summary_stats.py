# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The severity counts and the summary statistics read what they are given.

``ScannerSeverityCount.actionable_count`` takes the configuration's "ALL"
threshold, which counts every severity. ``SummaryStats`` routes the flat severity
keys (``critical=2``) into ``severity_counts`` without changing the dict, the
``severity_counts`` dict or the ``ScannerSeverityCount`` the caller passed in,
refuses a ``severity_counts`` that is neither with a ValidationError, and keeps a
``total`` that was given as 0.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.models.asharp_model import (
    ScannerSeverityCount,
    SummaryStats,
)

pytestmark = pytest.mark.unit


def test_the_all_threshold_counts_every_severity():
    counts = ScannerSeverityCount(
        critical=1, high=2, medium=3, low=4, info=5, suppressed=9
    )

    assert counts.actionable_count("ALL") == 15
    assert counts.actionable_count("all") == counts.actionable_count("info")


def test_an_unknown_threshold_is_still_refused():
    with pytest.raises(ValueError):
        ScannerSeverityCount().actionable_count("everything")


def test_flat_keys_leave_the_callers_dict_as_given():
    given = {"critical": 2, "high": 1}

    stats = SummaryStats.model_validate(given)

    assert given == {"critical": 2, "high": 1}
    assert (stats.critical, stats.high) == (2, 1)


def test_flat_keys_do_not_write_into_the_callers_severity_counts_dict():
    counts = {"low": 1}

    stats = SummaryStats(severity_counts=counts, critical=3)

    assert counts == {"low": 1}
    assert (stats.critical, stats.low) == (3, 1)


def test_flat_keys_do_not_write_into_the_callers_severity_counts_model():
    held = ScannerSeverityCount(low=1)

    stats = SummaryStats(severity_counts=held, critical=3)

    assert held.critical == 0
    assert (stats.critical, stats.low) == (3, 1)


def test_a_severity_counts_given_without_flat_keys_is_the_one_held():
    held = ScannerSeverityCount(low=1)

    stats = SummaryStats(severity_counts=held)

    held.low = 4
    assert stats.low == 4


@pytest.mark.parametrize("malformed", [["critical"], 5, "text"])
def test_a_malformed_severity_counts_beside_a_flat_key_is_a_validation_error(
    malformed,
):
    with pytest.raises(ValidationError):
        SummaryStats.model_validate({"severity_counts": malformed, "critical": 1})


def test_a_total_given_as_zero_is_kept():
    stats = SummaryStats(total=0, critical=2)

    assert stats.total == 0


def test_a_total_not_given_is_the_sum_of_the_severity_counts():
    stats = SummaryStats(critical=2, high=1, suppressed=7)

    assert stats.total == 3
