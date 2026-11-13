# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project's outcome records the gates its verdict used and the inputs it did not convert.

Why this file exists
--------------------
The unified workspace file carries no ``ash_config``: each project ran under its
own configuration and the merged model records only each project's outcome. A
reader that regrades a finding from that file (the merged JUnit report, the MCP
result filters) therefore had three things it could not know:

- the threshold the verdict graded a scanner by when that is the scanner's own
  ``options.severity_threshold`` rather than the project's gate;
- whether a finding from a scanner only the workspace policy added decided the
  verdict (``policy_scanners_gate``), or was reported and excluded;
- which converter input went unconverted, since the unified file's
  ``converter_results`` is empty by design and ``incomplete_converters`` names the
  converter and a summary reason only.

The outcome now carries all three. These tests pin what the executor writes; the
readers are pinned beside the reporters and the result filters.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
    _sarif,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _finding(scanner: str, severity: str = "HIGH", **properties) -> dict:
    return {
        "ruleId": f"{scanner}-rule",
        "level": "error",
        "message": {"text": "fixture"},
        "properties": {
            "scanner_name": scanner,
            "issue_severity": severity,
            **properties,
        },
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}}}
        ],
    }


def _sarif_of(*findings: dict) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ASH"}},
                "results": list(findings),
                "invocations": [],
            }
        ],
    }


OVER_LIMIT_ROW = {
    "converted_paths": [],
    "refused_inputs": [
        {
            "path": "vendor/big.zip",
            "reason": "its members declare more than 1073741824 bytes, the "
            "max_total_bytes extraction limit",
            "limit": "max_total_bytes",
        },
        {"path": "outer.zip", "member": "inner.zip", "reason": "nested archive"},
    ],
}


class TestThePolicyGateIsRecorded:
    def test_a_gating_policy_is_recorded_on_the_outcome(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        plan.projects[0].policy_scanners_gate = True

        entry = _run(tmp_path, plan).payload.projects[0]

        # RED at the base: the outcome declares no such field, so the attribute
        # read raises; a reader could not tell a gating policy from a non-gating one.
        assert entry.policy_scanners_gate is True

    def test_the_default_is_not_gating(self, tmp_path):
        """Control: the plan's default is False, and so is the record's."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))

        entry = _run(tmp_path, plan).payload.projects[0]

        assert entry.policy_scanners_gate is False


class TestEachScannersOwnThresholdIsRecorded:
    @pytest.fixture
    def _bandit_at_critical(self, monkeypatch):
        # (grading value, shown form, source, from env): the resolution the
        # executor reads through get_scanner_threshold_details.
        def threshold_details(_results, scanner_name):
            if scanner_name == "bandit":
                return "CRITICAL", None, "config", False
            return "MEDIUM", None, "global", False

        monkeypatch.setattr(
            ScannerStatisticsCalculator,
            "get_scanner_threshold_details",
            staticmethod(threshold_details),
        )

    def test_a_scanner_with_its_own_threshold_is_in_the_map(
        self, tmp_path, _bandit_at_critical
    ):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif_of(_finding("bandit"), _finding("semgrep")),
        }

        entry = _run(tmp_path, plan).payload.projects[0]

        # RED at the base: no scanner_thresholds field. bandit's own CRITICAL is
        # recorded; semgrep, graded by the project's gate, is not listed.
        assert entry.scanner_thresholds == {"bandit": "CRITICAL"}
        assert entry.severity_threshold == "MEDIUM"
        # The resolution a reader makes from the record, as the verdict made it.
        assert entry.threshold_for_scanner("bandit") == "CRITICAL"
        assert entry.threshold_for_scanner("semgrep") == "MEDIUM"
        assert entry.threshold_for_scanner(None) == "MEDIUM"
        # The verdict itself still grades as before: bandit's HIGH is under its
        # own CRITICAL gate, semgrep's HIGH is over the project's MEDIUM.
        assert entry.actionable_finding_count == 1

    def test_a_scanner_that_ran_and_found_nothing_is_still_recorded(
        self, tmp_path, _bandit_at_critical
    ):
        """A reader grading a later finding of its kind needs the gate too."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "bandit": {
                    "status": "PASSED",
                    "excluded": False,
                    "dependencies_satisfied": True,
                }
            },
        }

        entry = _run(tmp_path, plan).payload.projects[0]

        assert entry.scanner_thresholds == {"bandit": "CRITICAL"}

    def test_the_unified_file_carries_the_recorded_gates(
        self, tmp_path, _bandit_at_critical
    ):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        plan.projects[0].policy_scanners_gate = True
        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif_of(_finding("bandit"))}

        _run(tmp_path, plan)

        unified = json.loads(
            (tmp_path / "out" / "ash_aggregated_results.json").read_text(
                encoding="utf-8"
            )
        )
        (project,) = unified["workspace"]["projects"]
        assert project["scanner_thresholds"] == {"bandit": "CRITICAL"}
        assert project["policy_scanners_gate"] is True


class TestRefusedConverterInputsAreRecorded:
    def test_each_refused_input_is_recorded_at_its_workspace_path(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "converter_results": {"archive": OVER_LIMIT_ROW},
        }

        entry = _run(tmp_path, plan).payload.projects[0]

        # RED at the base: the outcome has no converter_refusals; only the
        # converter-level summary (incomplete_converters) exists there.
        over_limit, nested = entry.converter_refusals
        assert over_limit.converter == "archive"
        assert over_limit.path == "api/vendor/big.zip"
        assert over_limit.limit == "max_total_bytes"
        assert over_limit.scan_incomplete is True
        assert nested.path == "api/outer.zip"
        assert nested.member == "inner.zip"
        assert nested.scan_incomplete is False
        # Control: the converter-level summary is unchanged beside the records.
        assert list(entry.incomplete_converters) == ["archive"]

    def test_the_unified_file_lists_them(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "converter_results": {"archive": OVER_LIMIT_ROW},
        }

        _run(tmp_path, plan)

        unified = json.loads(
            (tmp_path / "out" / "ash_aggregated_results.json").read_text(
                encoding="utf-8"
            )
        )
        (project,) = unified["workspace"]["projects"]
        assert [r["path"] for r in project["converter_refusals"]] == [
            "api/vendor/big.zip",
            "api/outer.zip",
        ]

    def test_a_project_whose_converters_refused_nothing_records_none(self, tmp_path):
        """Control."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))

        entry = _run(tmp_path, plan).payload.projects[0]

        assert entry.converter_refusals == []
