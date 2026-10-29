# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The actionable view of a workspace document judges each finding by its project.

``filter_actionable_only`` keeps the findings exit 2 counts, judged by the
thresholds the scan recorded (``raw_results.severity_thresholds``). For a
workspace's unified results that map is resolved from no config, since the file
carries none, so every project's findings were judged by one threshold while each
project's verdict used its own, and a finding from a scanner only the workspace
policy added was kept though the project's verdict excluded it.

The document's ``workspace.projects`` block records each project's gate
(``severity_threshold``), its scanners' own thresholds (``scanner_thresholds``)
and whether policy findings decided its verdict (``policy_scanners_gate``). The
filter reads them for a finding attributed to a project and falls through to the
scanner-keyed map for every other finding.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.resource_management.result_filters import (
    apply_content_filters,
    filter_actionable_only,
)

pytestmark = pytest.mark.unit


def _result(rule: str, project: str | None, scanner: str, severity: str, **props):
    properties = {"scanner_name": scanner, "issue_severity": severity, **props}
    if project is not None:
        properties["workspace_project"] = project
    return {"ruleId": rule, "level": "note", "properties": properties}


def _project(key: str, threshold: str, **fields) -> dict:
    return {
        "project": key,
        "relative_path": key,
        "display_label": key,
        "status": "completed",
        "severity_threshold": threshold,
        "output_path": f"projects/{key}",
        **fields,
    }


def _workspace_document() -> dict:
    """Three projects with gates no single threshold reproduces.

    ``strict`` gates at HIGH; ``lax`` gates at LOW but recorded bandit's own
    CRITICAL; ``watch`` gates at LOW and does not gate on policy scanners. The
    scanner-keyed map says MEDIUM for everything, as it does for a workspace file
    with no configuration.
    """
    return {
        "summary_stats": {"actionable": 7, "total": 7, "suppressed": 0},
        "raw_results": {
            "sarif": {
                "runs": [
                    {
                        "results": [
                            _result("STRICT-HIGH", "strict", "bandit", "HIGH"),
                            _result("STRICT-MEDIUM", "strict", "bandit", "MEDIUM"),
                            _result("LAX-BANDIT-HIGH", "lax", "bandit", "HIGH"),
                            _result("LAX-SEMGREP-LOW", "lax", "semgrep", "LOW"),
                            _result(
                                "WATCH-POLICY",
                                "watch",
                                "semgrep",
                                "HIGH",
                                origin="workspace-policy",
                            ),
                            _result("WATCH-OWN", "watch", "bandit", "LOW"),
                            _result("UNATTRIBUTED-LOW", None, "bandit", "LOW"),
                        ]
                    }
                ]
            },
            "severity_thresholds": {
                "": "MEDIUM",
                "bandit": "MEDIUM",
                "semgrep": "MEDIUM",
            },
            "workspace": {
                "projects": [
                    _project("strict", "HIGH"),
                    _project("lax", "LOW", scanner_thresholds={"bandit": "CRITICAL"}),
                    _project(
                        "watch",
                        "LOW",
                        policy_scanners_gate=False,
                        policy_origin_finding_count=1,
                    ),
                ]
            },
        },
    }


def _rule_ids(results: dict) -> list:
    return [
        result["ruleId"]
        for run in results["raw_results"]["sarif"]["runs"]
        for result in run["results"]
    ]


class TestEachProjectIsJudgedByItsOwnGates:
    def test_the_project_gate_decides_its_findings(self):
        kept = _rule_ids(filter_actionable_only(_workspace_document()))

        # RED at the base: judged by the map's MEDIUM, STRICT-MEDIUM was kept and
        # LAX-SEMGREP-LOW and WATCH-OWN were dropped.
        assert "STRICT-HIGH" in kept
        assert "STRICT-MEDIUM" not in kept
        assert "LAX-SEMGREP-LOW" in kept
        assert "WATCH-OWN" in kept

    def test_a_scanners_recorded_own_threshold_decides_its_findings(self):
        kept = _rule_ids(filter_actionable_only(_workspace_document()))

        # lax gates at LOW, but recorded bandit's own CRITICAL: its HIGH is out.
        assert "LAX-BANDIT-HIGH" not in kept

    def test_a_non_gating_policy_finding_is_left_out(self):
        kept = _rule_ids(filter_actionable_only(_workspace_document()))

        # RED at the base: HIGH over the map's MEDIUM, so it was kept though the
        # project's verdict excluded it.
        assert "WATCH-POLICY" not in kept

    def test_a_gating_policy_finding_is_kept(self):
        document = _workspace_document()
        document["raw_results"]["workspace"]["projects"][2]["policy_scanners_gate"] = (
            True
        )

        kept = _rule_ids(filter_actionable_only(document))

        assert "WATCH-POLICY" in kept

    def test_a_finding_no_project_claims_is_judged_by_the_map(self):
        """Control: the scanner-keyed map still governs an unattributed finding."""
        kept = _rule_ids(filter_actionable_only(_workspace_document()))

        assert "UNATTRIBUTED-LOW" not in kept

    def test_the_kept_count_is_the_actionable_count(self):
        filtered = filter_actionable_only(_workspace_document())

        assert len(_rule_ids(filtered)) == 4
        assert (
            filtered["summary_stats"]["total"]
            == filtered["summary_stats"]["actionable"]
        )

    def test_a_document_without_a_workspace_block_reads_as_before(self):
        document = _workspace_document()
        del document["raw_results"]["workspace"]

        kept = _rule_ids(filter_actionable_only(document))

        assert kept == [
            "STRICT-HIGH",
            "STRICT-MEDIUM",
            "LAX-BANDIT-HIGH",
            "WATCH-POLICY",
        ]


class TestTheSeverityViewRecountsByProject:
    def test_the_actionable_recount_follows_the_project_gates(self):
        document = _workspace_document()
        document["summary_stats"] = {
            "critical": 0,
            "high": 3,
            "medium": 1,
            "low": 3,
            "info": 0,
            "suppressed": 0,
            "total": 7,
            "actionable": 7,
            "severity_counts": {
                "critical": 0,
                "high": 3,
                "medium": 1,
                "low": 3,
                "info": 0,
                "suppressed": 0,
            },
        }

        filtered = apply_content_filters(document, severities="low")

        # Of the kept LOW findings, the ones each project's gates count:
        # LAX-SEMGREP-LOW and WATCH-OWN (both projects gate at LOW); the
        # unattributed LOW is judged by the map's MEDIUM and does not count. RED at
        # the base: 0, every LOW being under the map's MEDIUM.
        assert filtered["summary_stats"]["actionable"] == 2
