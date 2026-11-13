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
    CRITICAL; ``watch`` gates at LOW and does not gate on policy scanners;
    ``legacy`` gates at LOW and records no policy gate at all, as a file written
    before the field existed does. The scanner-keyed map says MEDIUM for
    everything, as it does for a workspace file with no configuration.
    """
    return {
        "summary_stats": {"actionable": 8, "total": 8, "suppressed": 0},
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
                            _result(
                                "LEGACY-POLICY",
                                "legacy",
                                "semgrep",
                                "HIGH",
                                origin="workspace-policy",
                            ),
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
                    _project("legacy", "LOW", policy_origin_finding_count=1),
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

    def test_a_policy_finding_in_a_record_without_the_field_is_kept(self):
        """A file written before the field existed applied the gate before it wrote."""
        kept = _rule_ids(filter_actionable_only(_workspace_document()))

        # RED at the base: the absent gate read as False and the finding was
        # dropped from the actionable view where the recorded verdict counted it.
        assert "LEGACY-POLICY" in kept

    def test_a_policy_finding_in_an_unlisted_project_is_kept(self):
        """Control, green on both sides: the filters never excluded such a finding.

        Pinned so the two readers (this and the JUnit reporter) agree: only a
        listed project with its gate explicitly off excludes a policy finding;
        an unlisted project leaves it to the threshold.
        """
        document = _workspace_document()
        document["raw_results"]["sarif"]["runs"][0]["results"].append(
            _result(
                "GHOST-POLICY", "ghost", "semgrep", "HIGH", origin="workspace-policy"
            )
        )

        kept = _rule_ids(filter_actionable_only(document))

        assert "GHOST-POLICY" in kept

    def test_a_finding_no_project_claims_is_judged_by_the_map(self):
        """Control: the scanner-keyed map still governs an unattributed finding."""
        kept = _rule_ids(filter_actionable_only(_workspace_document()))

        assert "UNATTRIBUTED-LOW" not in kept

    def test_the_kept_count_is_the_actionable_count(self):
        filtered = filter_actionable_only(_workspace_document())

        # STRICT-HIGH, LAX-SEMGREP-LOW, WATCH-OWN and LEGACY-POLICY: the four the
        # projects' own gates keep (the first venue read of this test found its
        # earlier count, 4 before LEGACY-POLICY existed, one too high).
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
            "LEGACY-POLICY",
        ]


class TestTheSeverityViewRecountsByProject:
    def test_the_actionable_recount_follows_the_project_gates(self):
        document = _workspace_document()
        document["summary_stats"] = {
            "critical": 0,
            "high": 4,
            "medium": 1,
            "low": 3,
            "info": 0,
            "suppressed": 0,
            "total": 8,
            "actionable": 8,
            "severity_counts": {
                "critical": 0,
                "high": 4,
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
