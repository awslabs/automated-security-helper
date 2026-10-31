# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every original's own copy is taken before an overlapping one is offered.

Originals were matched one at a time, each taking the first overlapping result
when it had no exact copy. When one finding's copy was dropped by aggregation, it
took its sibling's copy as the nearest overlap; the sibling, processed next, found
its own copy taken and was reported unmatched, and the fields the dropped finding
lacked in the sibling's copy were reported as lost.
"""

import copy

import pytest

from automated_security_helper.utils.meta_analysis.sarif_analysis import (
    find_matching_result,
    validate_sarif_aggregation,
)

pytestmark = pytest.mark.unit


def _located(text, start, end):
    return {
        "ruleId": "B101",
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"startLine": start, "endLine": end},
                }
            }
        ],
    }


def _report(*results):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "t"}}, "results": list(results)}],
    }


# One finding on line 10, another on lines 10-12. Their ranges overlap, so each is
# the other's nearest overlapping result.
SHORT = _located("short", 10, 10)
LONG = _located("long", 10, 12)


@pytest.mark.parametrize("order", ["dropped-first", "kept-first"])
def test_a_dropped_finding_does_not_take_its_siblings_copy(order):
    originals = [SHORT, LONG] if order == "dropped-first" else [LONG, SHORT]
    # Aggregation kept only the copy of LONG.
    aggregated = _report(copy.deepcopy(LONG))

    results = validate_sarif_aggregation({"bandit": _report(*originals)}, aggregated)

    stats = results["match_statistics"]["bandit"]
    assert stats["total_results"] == 2
    assert stats["matched_results"] == 1
    # The one reported lost is the finding whose copy was dropped, whatever the
    # order the scanner wrote them in.
    unmatched = results["unmatched_results"]["bandit"]
    assert [entry["message"] for entry in unmatched] == ["short"]
    # And the finding that was kept lost no field: its copy is its own.
    assert stats["fields_missing"] == 0
    assert results["summary"]["critical_missing_fields"] == 0
    assert results["summary"]["important_missing_fields"] == 0


def test_both_findings_kept_both_match():
    aggregated = _report(copy.deepcopy(SHORT), copy.deepcopy(LONG))

    results = validate_sarif_aggregation({"bandit": _report(SHORT, LONG)}, aggregated)

    assert results["match_statistics"]["bandit"]["matched_results"] == 2
    assert results["unmatched_results"] == {}


def test_an_overlapping_result_is_still_offered_when_nothing_else_wants_it():
    """The control: a finding whose region moved a few lines in aggregation is
    matched to the moved result, as before."""
    moved = _located("short", 10, 12)

    results = validate_sarif_aggregation(
        {"bandit": _report(SHORT)}, _report(copy.deepcopy(moved))
    )

    assert results["match_statistics"]["bandit"]["matched_results"] == 1
    assert results["unmatched_results"] == {}


def test_exact_only_offers_no_overlapping_result():
    aggregated = [copy.deepcopy(LONG)]

    assert find_matching_result(SHORT, aggregated, exact_only=True) is None
    # The default still falls back to the overlapping result.
    assert find_matching_result(SHORT, aggregated) is aggregated[0]
    # An exact copy is found either way.
    assert find_matching_result(LONG, aggregated, exact_only=True) is aggregated[0]
