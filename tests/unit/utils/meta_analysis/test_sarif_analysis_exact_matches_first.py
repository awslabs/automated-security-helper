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


def _located_at_column(text, column):
    result = _located(text, 10, 10)
    result["locations"][0]["physicalLocation"]["region"]["startColumn"] = column
    return result


@pytest.mark.parametrize("order", ["dropped-first", "kept-first"])
def test_two_findings_on_one_line_keep_their_own_copies(order):
    """Two findings of one rule on the same lines have the same exact match. The
    one whose copy was dropped took its sibling's copy when it came first, and
    the sibling, whose copy was gone, was reported lost."""
    dropped = _located("dropped", 10, 10)
    kept = _located("kept", 10, 10)
    originals = [dropped, kept] if order == "dropped-first" else [kept, dropped]

    results = validate_sarif_aggregation(
        {"bandit": _report(*originals)}, _report(copy.deepcopy(kept))
    )

    stats = results["match_statistics"]["bandit"]
    assert stats["matched_results"] == 1
    assert [e["message"] for e in results["unmatched_results"]["bandit"]] == ["dropped"]
    # The finding that was kept lost no field, its message text included.
    assert stats["fields_missing"] == 0
    assert results["summary"]["critical_missing_fields"] == 0


@pytest.mark.parametrize("order", ["dropped-first", "kept-first"])
def test_two_findings_with_one_message_are_told_apart_by_their_column(order):
    dropped = _located_at_column("same text", 1)
    kept = _located_at_column("same text", 20)
    originals = [dropped, kept] if order == "dropped-first" else [kept, dropped]

    results = validate_sarif_aggregation(
        {"bandit": _report(*originals)}, _report(copy.deepcopy(kept))
    )

    stats = results["match_statistics"]["bandit"]
    assert stats["matched_results"] == 1
    assert stats["fields_missing"] == 0


def test_a_copy_whose_message_changed_is_still_matched_at_its_lines():
    """The control: when no result carries the original's message the exact
    location still decides, as before."""
    changed = _located("rewritten", 10, 10)

    results = validate_sarif_aggregation(
        {"bandit": _report(_located("original", 10, 10))},
        _report(copy.deepcopy(changed)),
    )

    assert results["match_statistics"]["bandit"]["matched_results"] == 1
    assert results["unmatched_results"] == {}


def test_same_finding_only_offers_a_result_with_the_same_message():
    other = _located("other", 10, 10)
    same = _located("short", 10, 10)

    assert find_matching_result(SHORT, [other], same_finding_only=True) is None
    # The exact tier alone still offers it.
    assert find_matching_result(SHORT, [other], exact_only=True) is other
    assert find_matching_result(SHORT, [other, same], same_finding_only=True) is same
    # And it offers no overlapping result: it implies the exact tier.
    assert (
        find_matching_result(SHORT, [copy.deepcopy(LONG)], same_finding_only=True)
        is None
    )


def test_exact_only_offers_no_overlapping_result():
    aggregated = [copy.deepcopy(LONG)]

    assert find_matching_result(SHORT, aggregated, exact_only=True) is None
    # The default still falls back to the overlapping result.
    assert find_matching_result(SHORT, aggregated) is aggregated[0]
    # An exact copy is found either way.
    assert find_matching_result(LONG, aggregated, exact_only=True) is aggregated[0]
