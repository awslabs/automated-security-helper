# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The count frames: one group-by for the severity counts, one for the actionable ones."""

from __future__ import annotations

import pytest

from automated_security_helper.models.asharp_model import ScannerSeverityCount
from automated_security_helper.utils.count_frame import (
    SUPPRESSED,
    actionable_by_name,
    actionable_frame,
    severity_frame,
    tally_severities,
)

pytestmark = pytest.mark.unit


def test_kinds_are_counted_into_their_fields():
    counts = tally_severities(
        severity_frame(["high", "high", SUPPRESSED, "info", "critical", "high"])
    )
    assert (counts.suppressed, counts.critical, counts.high, counts.info) == (
        1,
        1,
        3,
        1,
    )
    assert counts.medium == counts.low == 0


def test_the_counts_are_added_to_the_ones_given():
    counts = ScannerSeverityCount(high=2)
    assert tally_severities(severity_frame(["high"]), counts) is counts
    assert counts.high == 3


def test_an_empty_frame_adds_nothing():
    assert tally_severities(severity_frame([])).model_dump() == (
        ScannerSeverityCount().model_dump()
    )


def test_an_unknown_kind_is_refused_with_the_counters_message_at_the_first_seen():
    with pytest.raises(ValueError) as caught:
        tally_severities(severity_frame(["high", "weird", "odd"]))
    assert str(caught.value) == "Invalid severity: 'weird'"


def test_a_kind_with_a_lone_surrogate_is_carried_into_the_message():
    with pytest.raises(ValueError) as caught:
        tally_severities(severity_frame(["x\udcff"]))
    assert str(caught.value) == "Invalid severity: 'x\\udcff'"


def test_actionable_counts_keep_first_seen_order_and_every_name():
    frame = actionable_frame(
        [("b", True), ("a", False), ("b", True), ("c", False), ("a", True)]
    )
    counted = actionable_by_name(frame)
    assert counted == {"b": 2, "a": 1, "c": 0}
    assert list(counted) == ["b", "a", "c"]


def test_an_actionable_name_with_a_lone_surrogate_comes_back_as_it_was():
    assert actionable_by_name(actionable_frame([("sc\udcffan", True)])) == {
        "sc\udcffan": 1
    }


def test_no_rows_is_no_names():
    assert actionable_by_name(actionable_frame([])) == {}
