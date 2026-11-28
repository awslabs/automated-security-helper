# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A result that states no finding is not one of a project's findings.

A SARIF result of kind ``pass``, ``notApplicable`` or ``informational`` says that a
rule passed, did not apply, or reported information only
(``sarif_utils.NON_FINDING_KINDS``), and SARIF asks for level ``none`` beside those
kinds. ASH grades level ``none`` INFO, and INFO is a finding at the ``ALL`` threshold
and ranks as low for ``--min-severity``. Graded by its level alone, a cdk-nag rule that
was not evaluated made a project's workspace verdict fail, and met ``--min-severity``
with nothing to count. A result states no finding when its kind is one of those and
nothing in it reports a problem: its level is ``none`` or not stated, and no
``issue_severity`` it declares is above INFO. One whose level reports a problem is a
finding, graded as any other result is.

The ``--min-severity`` answer and the actionable count are asked separately, and the
first can be asked with no threshold at all, so each has a test of its own. Every test
with a non-finding kind has a control that changes the kind and nothing else. A
failing result (the default kind), and the two kinds that assert a finding a reader
still has to judge, ``open`` and ``review``, keep the grade they had.
"""

from __future__ import annotations

from typing import Any

import pytest

from automated_security_helper.utils.sarif_utils import NON_FINDING_KINDS
from automated_security_helper.workspace.aggregation import (
    actionable_results_by_scanner,
    count_actionable_results,
    has_finding_at_min_severity,
)

pytestmark = pytest.mark.unit

# Sorted, so every pytest-xdist worker collects the same ids in the same order.
NON_FINDING = sorted(NON_FINDING_KINDS)
# The kinds that assert a finding. A result that states no kind is a failing one.
FINDING = ["fail", "open", "review"]
ANY_FINDING = [pytest.param(None, id="absent"), *FINDING]


def _result(kind: str | None, *, level: str = "none") -> dict[str, Any]:
    """A cdk-nag result as a project's SARIF holds it, with *kind* and *level*."""
    result: dict[str, Any] = {
        "ruleId": "AwsSolutions-IAM4",
        "level": level,
        "message": {"text": "the rule was not evaluated"},
        "properties": {"scanner_name": "cdk-nag"},
    }
    if kind is not None:
        result["kind"] = kind
    return result


# ---------------------------------------------------------------------------
# --min-severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_that_states_no_finding_does_not_meet_the_minimum(kind):
    assert has_finding_at_min_severity([_result(kind)], "low") is False


@pytest.mark.parametrize("kind", NON_FINDING)
def test_nor_does_it_under_a_threshold_of_all(kind):
    assert has_finding_at_min_severity([_result(kind)], "low", "ALL") is False


@pytest.mark.parametrize("threshold", [None, "ALL"])
@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_result_that_asserts_a_finding_meets_the_minimum(kind, threshold):
    assert has_finding_at_min_severity([_result(kind)], "low", threshold) is True


def test_a_finding_beside_a_non_finding_still_meets_the_minimum():
    results = [_result("notApplicable"), _result("fail", level="warning")]

    assert has_finding_at_min_severity(results, "medium", "ALL") is True


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_non_finding_kind_at_level_warning_is_found_at_medium(kind):
    """A result of such a kind whose level reports a problem is a finding, so it meets
    the minimum, with no threshold to turn it away."""
    assert (
        has_finding_at_min_severity([_result(kind, level="warning")], "medium") is True
    )


# ---------------------------------------------------------------------------
# The actionable count
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_that_states_no_finding_is_not_counted_at_all(kind):
    assert count_actionable_results([_result(kind)], "ALL") == 0


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_result_that_asserts_a_finding_is_counted_at_all(kind):
    assert count_actionable_results([_result(kind)], "ALL") == 1


def test_only_the_finding_beside_a_non_finding_is_counted():
    results = [_result("informational"), _result("fail", level="warning")]

    assert count_actionable_results(results, "ALL") == 1


def test_a_scanner_that_reported_only_non_findings_stays_a_key_with_zero():
    """The count names every scanner that produced a result, counted or not, so a
    project that ran cdk-nag and found nothing reads as that, not as no cdk-nag."""
    results = [_result("notApplicable"), _result("pass")]

    assert actionable_results_by_scanner(results, "ALL") == {"cdk-nag": 0}
