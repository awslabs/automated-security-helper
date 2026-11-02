# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The actionable view does not grade a scanner whose threshold was withheld by the project gate.

A project's own scanner threshold can come from an environment variable. The
unified file then names the scanner in ``withheld_scanner_thresholds`` and does
not carry the value. The filter ignored that field, so it graded the scanner's
findings by the project gate while the project's own actionable count had been
graded by the withheld value: with the withheld value stricter than the project
gate, a finding the count included was left out of the view.

A withheld scanner is now graded by the strictest threshold, so the view lists
every unsuppressed finding of it. That is the side that cannot hide a finding
the project's count included.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.resource_management.result_filters import (
    filter_actionable_only,
)

pytestmark = pytest.mark.unit


def _result(rule: str, project: str, scanner: str, severity: str, **props) -> dict:
    return {
        "ruleId": rule,
        "level": "note",
        "properties": {
            "scanner_name": scanner,
            "issue_severity": severity,
            "workspace_project": project,
            **props,
        },
    }


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


def _document(*projects: dict, results: list) -> dict:
    return {
        "summary_stats": {"actionable": len(results), "total": len(results)},
        "raw_results": {
            "sarif": {"runs": [{"results": results}]},
            "severity_thresholds": {"": "MEDIUM", "bandit": "MEDIUM"},
            "workspace": {"projects": list(projects)},
        },
    }


def _kept(document: dict) -> list:
    filtered = filter_actionable_only(document)
    return [
        result["ruleId"]
        for run in filtered["raw_results"]["sarif"]["runs"]
        for result in run["results"]
    ]


class TestAWithheldScannerIsGradedByTheStrictestGate:
    def test_a_finding_below_the_project_gate_is_listed(self):
        document = _document(
            _project("api", "HIGH", withheld_scanner_thresholds=["bandit"]),
            results=[
                _result("API-BANDIT-LOW", "api", "bandit", "LOW"),
                _result("API-BANDIT-HIGH", "api", "bandit", "HIGH"),
            ],
        )

        kept = _kept(document)

        # RED at the base: the project gate HIGH was read for bandit, so the LOW
        # finding was left out although the withheld value may be as strict as LOW.
        assert "API-BANDIT-LOW" in kept
        assert "API-BANDIT-HIGH" in kept

    def test_a_suppressed_finding_of_the_scanner_is_still_left_out(self):
        suppressed = _result("API-BANDIT-SUPPRESSED", "api", "bandit", "HIGH")
        suppressed["suppressions"] = [{"kind": "inSource", "status": "accepted"}]
        document = _document(
            _project("api", "HIGH", withheld_scanner_thresholds=["bandit"]),
            results=[suppressed],
        )

        assert _kept(document) == []

    def test_a_scanner_the_project_did_not_withhold_keeps_the_project_gate(self):
        """Control, green on both sides: only the named scanner changes."""
        document = _document(
            _project("api", "HIGH", withheld_scanner_thresholds=["bandit"]),
            results=[
                _result("API-SEMGREP-LOW", "api", "semgrep", "LOW"),
                _result("API-SEMGREP-HIGH", "api", "semgrep", "HIGH"),
            ],
        )

        assert _kept(document) == ["API-SEMGREP-HIGH"]

    def test_another_project_keeps_its_own_gate_for_the_same_scanner(self):
        """Control, green on both sides: the name is withheld per project."""
        document = _document(
            _project("api", "HIGH", withheld_scanner_thresholds=["bandit"]),
            _project("web", "HIGH"),
            results=[
                _result("API-BANDIT-LOW", "api", "bandit", "LOW"),
                _result("WEB-BANDIT-LOW", "web", "bandit", "LOW"),
            ],
        )

        assert _kept(document) == ["API-BANDIT-LOW"]

    def test_a_record_written_before_the_field_existed_reads_as_before(self):
        """Control, green on both sides: no field, no change."""
        document = _document(
            _project("api", "HIGH"),
            results=[
                _result("API-BANDIT-LOW", "api", "bandit", "LOW"),
                _result("API-BANDIT-HIGH", "api", "bandit", "HIGH"),
            ],
        )

        assert _kept(document) == ["API-BANDIT-HIGH"]

    def test_a_malformed_field_is_ignored(self):
        """Control, green on both sides: a non-list value names nothing."""
        document = _document(
            _project("api", "HIGH", withheld_scanner_thresholds="bandit"),
            results=[_result("API-BANDIT-LOW", "api", "bandit", "LOW")],
        )

        assert _kept(document) == []
