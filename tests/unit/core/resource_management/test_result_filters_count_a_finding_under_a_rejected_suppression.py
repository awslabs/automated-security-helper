# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The result filters hide a finding only by a suppression in effect.

``_counts_toward_exit_2`` (the actionable view and its recount) and the severity
filter's ``suppressed`` bucket read any non-empty ``suppressions`` list as
suppressed. A suppression whose ``state`` is ``rejected`` or ``underReview`` has
not taken effect (SARIF 3.35.4), so the MCP actionable view dropped a finding the
exit code, the per-scanner counts and the workspace verdict count, and
``severities="suppressed"`` selected it as though a reviewer had approved hiding it.
Both reads now go through ``sarif_utils.is_result_suppressed``.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.resource_management.result_filters import (
    apply_content_filters,
    filter_actionable_only,
)

pytestmark = pytest.mark.unit


def _document(state: str | None) -> dict:
    """Two HIGH bandit findings; B101 carries one suppression in *state*."""
    suppression = {"kind": "external", "justification": "awaiting review"}
    if state is not None:
        suppression["state"] = state
    return {
        "summary_stats": {"actionable": 1, "total": 2, "suppressed": 1},
        "raw_results": {
            "sarif": {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "B602",
                                "level": "error",
                                "properties": {
                                    "scanner_name": "bandit",
                                    "issue_severity": "HIGH",
                                },
                            },
                            {
                                "ruleId": "B101",
                                "level": "error",
                                "properties": {
                                    "scanner_name": "bandit",
                                    "issue_severity": "HIGH",
                                },
                                "suppressions": [suppression],
                            },
                        ]
                    }
                ]
            },
            "severity_thresholds": {"": "MEDIUM", "bandit": "MEDIUM"},
        },
    }


def _rule_ids(filtered: dict) -> list:
    runs = filtered["raw_results"]["sarif"]["runs"]
    return sorted(r["ruleId"] for run in runs for r in run["results"])


class TestTheActionableViewKeepsAFindingWhoseSuppressionIsNotInEffect:
    @pytest.mark.parametrize("state", ["rejected", "underReview"])
    def test_a_suppression_not_in_effect_leaves_the_finding_actionable(self, state):
        kept = _rule_ids(filter_actionable_only(_document(state)))

        # RED at the base: B101 was dropped on its non-empty suppressions list.
        assert kept == ["B101", "B602"]

    @pytest.mark.parametrize("state", [None, "accepted"])
    def test_a_suppression_in_effect_drops_the_finding(self, state):
        kept = _rule_ids(filter_actionable_only(_document(state)))

        assert kept == ["B602"]


class TestTheSeverityFilterBucketsBySuppressionsInEffect:
    @pytest.mark.parametrize("state", ["rejected", "underReview"])
    def test_a_finding_whose_suppression_is_not_in_effect_is_in_its_severity(
        self, state
    ):
        # RED at the base: B101 sat in the suppressed bucket, so "high" left it
        # out and "suppressed" selected it.
        assert _rule_ids(
            apply_content_filters(_document(state), severities="high")
        ) == [
            "B101",
            "B602",
        ]
        assert (
            _rule_ids(apply_content_filters(_document(state), severities="suppressed"))
            == []
        )

    @pytest.mark.parametrize("state", [None, "accepted"])
    def test_a_finding_whose_suppression_is_in_effect_is_in_the_suppressed_bucket(
        self, state
    ):
        assert _rule_ids(
            apply_content_filters(_document(state), severities="high")
        ) == ["B602"]
        assert _rule_ids(
            apply_content_filters(_document(state), severities="suppressed")
        ) == ["B101"]
