# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The JUnit report's case frame: ``reporters/_junitxml_frame``."""

from __future__ import annotations

import polars as pl
import pytest

from automated_security_helper.plugin_modules.ash_builtin.reporters._junitxml_frame import (
    cases_frame,
    suite_members,
)

pytestmark = pytest.mark.unit


def _frame(rows):
    """rows: (suite, in_effect, n/a, policy, actionable, asserts, fail, reports, type)"""
    cols = list(zip(*rows)) if rows else [[]] * 9
    return cases_frame(*[list(c) for c in cols])


def test_the_outcome_cascade_takes_the_first_flag_that_is_set():
    frame = _frame(
        [
            ("s", True, True, True, True, True, True, True, "error"),
            ("s", False, True, True, True, True, True, True, "error"),
            ("s", False, False, True, True, True, True, True, "error"),
            ("s", False, False, False, False, True, True, True, "error"),
            ("s", False, False, False, True, True, True, True, "warning"),
            ("s", False, False, False, None, True, True, True, "warning"),
        ]
    )
    assert frame["outcome"].to_list() == [
        "suppression",
        "not-evaluated",
        "policy-not-gating",
        "threshold",
        "error",
        "threshold",
    ]


@pytest.mark.parametrize(
    "asserts,fail,reports,level_type,expected_type,outcome",
    [
        (True, True, False, None, "error", "error"),
        (True, False, False, None, "note", "error"),
        (True, True, True, "warning", "warning", "error"),
        (False, False, True, "error", "error", "error"),
        (False, False, False, "note", None, "pass"),
        (False, False, False, None, None, "pass"),
    ],
)
def test_an_actionable_result_is_an_error_of_the_type_its_kind_and_level_give(
    asserts, fail, reports, level_type, expected_type, outcome
):
    frame = _frame(
        [("s", False, False, False, True, asserts, fail, reports, level_type)]
    )
    assert frame["error_type"].to_list() == [expected_type]
    assert frame["outcome"].to_list() == [outcome]


def test_suites_come_in_first_seen_order_with_their_cases_in_order():
    rows = [
        (name, False, False, False, True, True, True, True, "error") for name in "bab"
    ]
    rows.append(("c", False, False, False, True, True, True, True, "error"))
    assert suite_members(_frame(rows)) == [("b", [0, 2]), ("a", [1]), ("c", [3])]


def test_a_suite_name_with_a_lone_surrogate_survives_the_frame():
    names = ["bad\ud800", "bad\ud800", "bad\udfff", "é"]
    rows = [(n, False, False, False, True, True, True, True, "error") for n in names]
    assert suite_members(_frame(rows)) == [
        ("bad\ud800", [0, 1]),
        ("bad\udfff", [2]),
        ("é", [3]),
    ]


def test_no_results_make_no_suites():
    frame = _frame([])
    assert isinstance(frame, pl.DataFrame)
    assert frame.height == 0
    assert suite_members(frame) == []
