# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The JUnit report skips a finding only for a suppression in effect.

A suppression whose ``state`` is ``rejected`` or ``underReview`` has not taken
effect (SARIF 3.35.4). The reporter rendered a Skipped case of type ``suppression``
for any result with a non-empty ``suppressions`` list, so a finding the exit code
counted (and the scan failed on) read as skipped in the report. Such a finding is
now graded by the threshold like any other; only the suppressions in effect are
rendered as the skip.
"""

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Kind1,
    State,
    Suppression,
)

from tests.unit.plugin_modules.ash_builtin.reporters.test_junitxml_reporter import (
    _get_reporter,
    _make_model,
    _make_result,
    _make_run,
    _outcome,
    _parse_xml,
)

pytestmark = pytest.mark.unit


def _suppression(state, justification="awaiting review") -> Suppression:
    return Suppression(kind=Kind1.external, justification=justification, state=state)


def _case(tmp_path, suppressions):
    result = _make_result(
        level="error", scanner_name="bandit", suppressions=suppressions
    )
    output = _get_reporter(tmp_path).report(_make_model(runs=[_make_run([result])]))
    return _parse_xml(output).find(".//testcase")


@pytest.mark.parametrize("state", [State.rejected, State.underReview])
def test_a_suppression_not_in_effect_leaves_the_finding_graded(tmp_path, state):
    case = _case(tmp_path, [_suppression(state)])

    # RED at the base: a Skipped case of type suppression, for a finding the exit
    # code counted and the scan failed on.
    assert _outcome(case) == "actionable"
    assert case.find("skipped") is None


@pytest.mark.parametrize("state", [None, State.accepted])
def test_a_suppression_in_effect_is_still_a_skip(tmp_path, state):
    """Control: an accepted or stateless suppression skips the case, as before."""
    case = _case(tmp_path, [_suppression(state)])

    assert _outcome(case) == "below-threshold"
    assert case.find("skipped").get("type") == "suppression"


def test_only_the_suppressions_in_effect_are_rendered(tmp_path):
    case = _case(
        tmp_path,
        [
            _suppression(State.rejected, "rejected by the reviewer"),
            _suppression(State.accepted, "accepted risk"),
        ],
    )

    skipped = case.findall("skipped")
    assert [element.get("message") for element in skipped] == ["accepted risk"]
