# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP views leave out a result whose kind states no finding, as the exit code does.

``_counts_toward_exit_2`` restates ``_compute_exit_code``'s test for one result, and
that test no longer counts a result of kind ``pass``, ``notApplicable`` or
``informational`` (``sarif_utils.NON_FINDING_KINDS``). SARIF asks for level ``none``
beside those kinds, which ASH grades INFO, and a threshold of ``ALL`` fails INFO. The
actionable view still kept such a result, so a client that gated on its findings and
counts failed a scan that exited 0, and the ``severities`` and ``scanners`` recounts
read it as an INFO finding beside per-scanner rows that no longer count it.

Every test with a non-finding kind has a control that changes the kind and nothing
else. A result that carries a suppression in effect stays in the suppressed bucket,
as it does in the per-scanner counts.
"""

from __future__ import annotations

from typing import Any

import pytest

from automated_security_helper.core.resource_management.result_filters import (
    _counts_toward_exit_2,
    apply_content_filters,
    filter_actionable_only,
)
from automated_security_helper.utils.sarif_utils import NON_FINDING_KINDS

pytestmark = pytest.mark.unit

# Sorted, so every pytest-xdist worker collects the same ids in the same order.
NON_FINDING = sorted(NON_FINDING_KINDS)
# The kinds that assert a finding. A result that states no kind is a failing one.
FINDING = ["fail", "open", "review"]
ANY_FINDING = [pytest.param(None, id="absent"), *FINDING]

# Every scanner gates at ALL, which fails the INFO a level of none is graded as.
THRESHOLDS = {"": "ALL", "trivy": "ALL"}


def _high() -> dict[str, Any]:
    """A HIGH finding of the scanner the notes below name."""
    return {
        "ruleId": "F1",
        "level": "error",
        "properties": {"scanner_name": "trivy", "issue_severity": "HIGH"},
    }


def _note(
    kind: str | None, *, level: str = "none", suppressed: bool = False
) -> dict[str, Any]:
    """The note a scanner records for an image it did not scan, with *kind*."""
    result: dict[str, Any] = {
        "ruleId": "N1",
        "level": level,
        "properties": {"scanner_name": "trivy"},
    }
    if kind is not None:
        result["kind"] = kind
    if suppressed:
        result["suppressions"] = [{"kind": "external", "justification": "accepted"}]
    return result


def _document(note: dict[str, Any]) -> dict[str, Any]:
    """A scan's results: the HIGH finding and *note*, counted as the scan counted them."""
    return {
        "summary_stats": {
            "actionable": 2,
            "total": 2,
            "suppressed": 0,
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 1,
                "suppressed": 0,
            },
        },
        "raw_results": {
            "sarif": {"runs": [{"results": [_high(), note]}]},
            "severity_thresholds": THRESHOLDS,
        },
    }


def _sarif_only_document(note: dict[str, Any]) -> dict[str, Any]:
    """The same results with no scanner row, so a scanners filter counts the SARIF."""
    document = _document(note)
    document["raw_results"]["scanner_results"] = {}
    return document


def _rule_ids(filtered: dict[str, Any]) -> list[str]:
    runs = filtered["raw_results"]["sarif"]["runs"]
    return sorted(r["ruleId"] for run in runs for r in run["results"])


# ---------------------------------------------------------------------------
# The one actionability rule of the exit code, restated for the view
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_that_states_no_finding_does_not_count_toward_exit_2(kind):
    assert _counts_toward_exit_2(_note(kind), "ALL") is False


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_level_of_a_result_that_states_no_finding_does_not_make_it_count(kind):
    assert _counts_toward_exit_2(_note(kind, level="error"), "LOW") is False


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_result_that_asserts_a_finding_counts_at_all(kind):
    assert _counts_toward_exit_2(_note(kind), "ALL") is True


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_result_at_level_error_counts_at_low(kind):
    assert _counts_toward_exit_2(_note(kind, level="error"), "LOW") is True


# ---------------------------------------------------------------------------
# The actionable view: the findings it lists and the buckets it recounts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_actionable_view_drops_a_result_that_states_no_finding(kind):
    kept = _rule_ids(filter_actionable_only(_document(_note(kind))))

    assert kept == ["F1"]


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_actionable_view_keeps_the_same_result_when_it_asserts_a_finding(kind):
    kept = _rule_ids(filter_actionable_only(_document(_note(kind))))

    assert kept == ["F1", "N1"]


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_actionable_view_counts_a_result_that_states_no_finding_in_no_bucket(kind):
    counts = filter_actionable_only(_document(_note(kind)))["summary_stats"][
        "severity_counts"
    ]

    assert (counts["high"], counts["info"]) == (1, 0)


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_actionable_view_counts_the_same_result_as_info_when_it_asserts_a_finding(
    kind,
):
    counts = filter_actionable_only(_document(_note(kind)))["summary_stats"][
        "severity_counts"
    ]

    assert (counts["high"], counts["info"]) == (1, 1)


# ---------------------------------------------------------------------------
# The recounts of the content filters
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_severities_filter_recounts_actionable_without_a_non_finding(kind):
    filtered = apply_content_filters(_document(_note(kind)), severities="info,high")

    assert filtered["summary_stats"]["actionable"] == 1


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_a_severities_filter_recounts_the_same_result_when_it_asserts_a_finding(kind):
    filtered = apply_content_filters(_document(_note(kind)), severities="info,high")

    assert filtered["summary_stats"]["actionable"] == 2


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_scanners_filter_counts_a_non_finding_in_no_bucket_and_no_total(kind):
    filtered = apply_content_filters(
        _sarif_only_document(_note(kind)), scanners="trivy"
    )

    stats = filtered["summary_stats"]
    assert (stats["total"], stats["actionable"]) == (1, 1)
    assert (stats["severity_counts"]["high"], stats["severity_counts"]["info"]) == (
        1,
        0,
    )


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_a_scanners_filter_counts_the_same_result_as_info_when_it_asserts_a_finding(
    kind,
):
    filtered = apply_content_filters(
        _sarif_only_document(_note(kind)), scanners="trivy"
    )

    stats = filtered["summary_stats"]
    assert (stats["total"], stats["actionable"]) == (2, 2)
    assert (stats["severity_counts"]["high"], stats["severity_counts"]["info"]) == (
        1,
        1,
    )


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_suppressed_result_that_states_no_finding_is_still_a_suppression(kind):
    """Must-not-regress control: a suppression in effect puts a result under suppressed.

    Green at the base too. The per-scanner counts keep such a result in the
    suppressed bucket, and so does this recount.
    """
    filtered = apply_content_filters(
        _sarif_only_document(_note(kind, suppressed=True)), scanners="trivy"
    )

    stats = filtered["summary_stats"]
    assert stats["total"] == 1
    counts = stats["severity_counts"]
    assert (counts["high"], counts["info"], counts["suppressed"]) == (1, 0, 1)
