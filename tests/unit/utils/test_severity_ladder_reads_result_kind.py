# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``result_fails_scanner_threshold`` does not grade a result that states no finding.

A SARIF result of kind ``pass``, ``notApplicable`` or ``informational`` says that a
rule passed, did not apply, or reported information only
(``sarif_utils.NON_FINDING_KINDS``), and SARIF asks for level ``none`` beside those
kinds. The ladder reads level ``none`` as INFO and a threshold of ``ALL`` fails INFO,
so graded by its level such a result failed the gate of its scanner. A result states
no finding when its kind is one of those and nothing in it reports a problem: its
level is ``none`` or not stated, and no ``issue_severity`` it declares is above INFO.
It fails no gate, whatever the threshold. A result of such a kind whose level or
``issue_severity`` does report a problem is graded as any other result is.

Every test with a non-finding kind has a control that changes the kind and nothing
else. A failing result (the default kind), and the two kinds that assert a finding a
reader still has to judge, ``open`` and ``review``, keep the grade they had.
"""

from __future__ import annotations

from typing import Any, Callable

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    Message,
    PropertyBag,
    Result,
)
from automated_security_helper.utils.sarif_utils import NON_FINDING_KINDS
from automated_security_helper.utils.severity_ladder import (
    result_fails_scanner_threshold,
)

pytestmark = pytest.mark.unit

# Sorted, so every pytest-xdist worker collects the same ids in the same order.
NON_FINDING = sorted(NON_FINDING_KINDS)
# The kinds that assert a finding. A result that states no kind is a failing one.
FINDING = ["fail", "open", "review"]
ANY_FINDING = [pytest.param(None, id="absent"), *FINDING]


def _json_result(
    kind: str | None, level: str = "none", *, severity: str | None = None
) -> dict[str, Any]:
    """A cdk-nag result as reports/ash.sarif holds it, with *kind*, *level* and, when
    given, a declared ``issue_severity``."""
    result: dict[str, Any] = {
        "ruleId": "AwsSolutions-IAM4",
        "level": level,
        "message": {"text": "the rule was not evaluated"},
        "properties": {"scanner_name": "cdk-nag"},
    }
    if kind is not None:
        result["kind"] = kind
    if severity is not None:
        result["properties"]["issue_severity"] = severity
    return result


def _model_result(kind: str) -> Result:
    """The same result as a model, at level none."""
    return Result(
        ruleId="AwsSolutions-IAM4",
        kind=Kind(kind),
        level=Level.none,
        message=Message(text="the rule was not evaluated"),
        properties=PropertyBag(scanner_name="cdk-nag"),
    )


def _at(threshold: str) -> Callable[[str | None], str]:
    """A resolver that gives every scanner *threshold*."""
    return lambda _scanner: threshold


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_that_states_no_finding_fails_no_all_gate(kind):
    assert result_fails_scanner_threshold(_json_result(kind), _at("ALL")) is False


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_result_that_asserts_a_finding_fails_the_all_gate(kind):
    assert result_fails_scanner_threshold(_json_result(kind), _at("ALL")) is True


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_model_result_that_states_no_finding_fails_no_all_gate(kind):
    assert result_fails_scanner_threshold(_model_result(kind), _at("ALL")) is False


@pytest.mark.parametrize("kind", FINDING)
def test_the_same_model_result_that_asserts_a_finding_fails_the_all_gate(kind):
    assert result_fails_scanner_threshold(_model_result(kind), _at("ALL")) is True


@pytest.mark.parametrize("threshold", ["ALL", "CRITICAL"])
@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_severe_level_makes_a_non_finding_fail_a_gate(kind, threshold):
    """A result whose level reports a problem is a finding, whatever its kind, and is
    graded by its level."""
    result = _json_result(kind, level="error")

    assert result_fails_scanner_threshold(result, _at(threshold)) is True


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_non_finding_kind_at_level_warning_fails_the_medium_gate(kind):
    """A result of such a kind at level warning is graded MEDIUM, which the default
    threshold fails."""
    result = _json_result(kind, level="warning")

    assert result_fails_scanner_threshold(result, _at("MEDIUM")) is True


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_non_finding_kind_with_a_high_issue_severity_fails_the_medium_gate(kind):
    """A result of such a kind at level none that declares a HIGH issue_severity is
    graded HIGH: the declared severity is read before the level."""
    result = _json_result(kind, severity="HIGH")

    assert result_fails_scanner_threshold(result, _at("MEDIUM")) is True


@pytest.mark.parametrize("threshold", ["ALL", "CRITICAL"])
def test_the_same_error_level_result_of_kind_fail_fails_both_gates(threshold):
    result = _json_result("fail", level="error")

    assert result_fails_scanner_threshold(result, _at(threshold)) is True
