# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace project's verdict grades each finding by its own scanner's threshold.

Why this file exists
--------------------
``_compute_exit_code`` resolves the threshold per result: a scanner with its own
``options.severity_threshold`` is judged by it, every other scanner by the global
one. The workspace verdict judged every finding of a project against the one
project-wide threshold, so a project whose config tightened or relaxed one scanner
got a different answer inside a workspace than ``ash --source-dir P`` gave it.
The per-scanner rollup in the unified file re-derived its counts the same way,
and over every finding of the run, so it also counted policy-origin findings the
project's own verdict excludes and exceeded the per-project totals it sums.

Naming, because the file once called one setting both things: a scanner's own
threshold ABOVE the project's (bandit CRITICAL over project MEDIUM) is LOOSER, it
lets more through; one BELOW (bandit LOW over project HIGH) is STRICTER.

The contract these cases pin:

- the counter grades a finding by the threshold its scanner's name resolves to,
  falling back to the project-wide threshold for a scanner that has none;
- a project whose config gives one scanner a looser threshold is judged by it
  inside a workspace, and so is one whose config gives a scanner a stricter one;
- the unified ``scanner_results`` actionable counts sum what the projects'
  verdicts counted: a non-gating policy scanner's findings count zero there;
- read from a real recorded config (no monkeypatch), a scanner's own looser
  option stands when the workspace declares no ceiling, and is capped by the
  ceiling whenever one exists, whether or not the ceiling moved the project-wide
  threshold: a ceiling MEDIUM over a project declaring MEDIUM tightened nothing
  and still grades a bandit option of CRITICAL at MEDIUM; a scanner's own option
  BELOW the ceiling keeps its own value, the ceiling never loosens;
- a scanner whose own threshold the scan read from an environment variable is
  graded by it and left out of the published ``scanner_thresholds``: the report
  surfaces print the written reference, never the environment's value, and the
  unified results and the MCP payloads must not be the one place that does.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.workspace.aggregation import (
    UNATTRIBUTED_SCANNER,
    actionable_results_by_scanner,
    count_actionable_results,
    has_finding_at_min_severity,
)
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
    _scanner,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _finding(scanner: str, severity: str = "HIGH") -> dict:
    return {
        "ruleId": f"{scanner}-rule",
        "level": "error",
        "message": {"text": "fixture"},
        "properties": {"scanner_name": scanner, "issue_severity": severity},
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


def _threshold_details(own: dict, *, from_env: frozenset = frozenset()):
    """A stand-in for the calculator's resolution: *own* maps scanner to its own
    threshold (source ``config``); every other scanner reads the global MEDIUM."""

    def details(_results, scanner_name):
        if scanner_name in own:
            return own[scanner_name], None, "config", scanner_name in from_env
        return "MEDIUM", None, "global", False

    return staticmethod(details)


def test_the_counter_grades_each_finding_by_its_scanners_threshold():
    findings = [_finding("bandit"), _finding("semgrep"), _finding("semgrep")]

    def threshold_for(scanner):
        return "CRITICAL" if scanner == "bandit" else None

    by_scanner = actionable_results_by_scanner(
        findings, "MEDIUM", threshold_for=threshold_for
    )

    # bandit's HIGH is below its own CRITICAL gate; semgrep has no setting of its
    # own and is judged by the project's MEDIUM. Every scanner is a key.
    assert by_scanner == {"bandit": 0, "semgrep": 2}
    assert (
        count_actionable_results(findings, "MEDIUM", threshold_for=threshold_for) == 2
    )
    # Control: without a resolver, the project-wide threshold judges them all.
    assert count_actionable_results(findings, "MEDIUM") == 3


class TestTheCounterAndTheGateReadOneFinding:
    """The two paths that decide "is this finding actionable" grade alike.

    Red at the base: the counter kept its own reading of a result (the declared
    severity upper-cased but not stripped, a non-string scanner name
    ``str()``-ed, the level graded through its own table) while the
    ``--min-severity`` gate read it through the ladder's one predicate, so a
    finding could qualify for the gate and not be counted, or the reverse.
    """

    def test_a_padded_declared_severity_is_counted_as_the_gate_reads_it(self):
        finding = _finding("bandit")
        finding["properties"]["issue_severity"] = " high "
        finding["level"] = "note"

        # The gate reads HIGH (the ladder strips); the counter read " HIGH " as
        # no declared severity and graded the level, note, as LOW: not counted.
        assert has_finding_at_min_severity([finding], "low", "MEDIUM") is True
        assert actionable_results_by_scanner([finding], "MEDIUM") == {"bandit": 1}

    def test_a_scanner_name_that_is_not_a_string_is_unattributed_on_both_sides(
        self,
    ):
        finding = _finding("bandit")
        finding["properties"]["scanner_name"] = 7

        counts = actionable_results_by_scanner([finding], "MEDIUM")
        # The gate's resolver sees None for a non-string name (the scan-wide
        # threshold); the counter keyed the row "7" and resolved that name.
        assert counts == {UNATTRIBUTED_SCANNER: 1}

    def test_a_finding_the_gate_does_not_qualify_is_not_counted(self):
        """Control: bandit's own CRITICAL makes its HIGH non-actionable on both sides."""
        finding = _finding("bandit")

        def threshold_for(scanner):
            return "CRITICAL" if scanner == "bandit" else None

        assert (
            has_finding_at_min_severity(
                [finding], "low", "MEDIUM", threshold_for=threshold_for
            )
            is False
        )
        assert actionable_results_by_scanner(
            [finding], "MEDIUM", threshold_for=threshold_for
        ) == {"bandit": 0}


def test_a_scanner_with_its_own_looser_threshold_is_judged_by_it(tmp_path, monkeypatch):
    """`ash --source-dir P` with bandit at CRITICAL exits 0 on a HIGH; so must P here."""
    monkeypatch.setattr(
        ScannerStatisticsCalculator,
        "get_scanner_threshold_details",
        _threshold_details({"bandit": "CRITICAL"}),
    )
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif_of(_finding("bandit"), _finding("semgrep")),
        "scanner_results": {
            "bandit": _scanner("PASSED"),
            "semgrep": _scanner("PASSED"),
        },
    }

    outcome = _run(tmp_path, plan)
    entry = outcome.payload.projects[0]

    # Only semgrep's HIGH is actionable under the project's MEDIUM; bandit's HIGH
    # is below the CRITICAL its own options set.
    assert entry.finding_count == 2
    assert entry.actionable_finding_count == 1
    assert entry.scanner_thresholds == {"bandit": "CRITICAL"}
    assert outcome.exit_code == WorkspaceExitCode.ACTIONABLE_FINDINGS

    rollup = json.loads(outcome.results_path.read_text("utf-8"))["scanner_results"]
    assert rollup["bandit"]["actionable_finding_count"] == 0
    assert rollup["semgrep"]["actionable_finding_count"] == 1


def test_a_scanner_with_its_own_stricter_threshold_is_judged_by_it(
    tmp_path, monkeypatch
):
    """The other direction: bandit LOW under project HIGH makes a MEDIUM actionable.

    An implementation that only ever tightened to the project threshold, or
    graded every finding at it, passes the looser case above and fails here.
    """
    monkeypatch.setattr(
        ScannerStatisticsCalculator,
        "get_scanner_threshold_details",
        _threshold_details({"bandit": "LOW"}),
    )
    _, plan = _make_workspace(tmp_path, ("api", "HIGH"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif_of(_finding("bandit", "MEDIUM"), _finding("semgrep", "MEDIUM")),
        "scanner_results": {
            "bandit": _scanner("PASSED"),
            "semgrep": _scanner("PASSED"),
        },
    }

    outcome = _run(tmp_path, plan)
    entry = outcome.payload.projects[0]

    # bandit's MEDIUM is at or above its own LOW; semgrep's MEDIUM is below the
    # project's HIGH.
    assert entry.finding_count == 2
    assert entry.actionable_finding_count == 1
    assert entry.scanner_thresholds == {"bandit": "LOW"}
    assert outcome.exit_code == WorkspaceExitCode.ACTIONABLE_FINDINGS

    rollup = json.loads(outcome.results_path.read_text("utf-8"))["scanner_results"]
    assert rollup["bandit"]["actionable_finding_count"] == 1
    assert rollup["semgrep"]["actionable_finding_count"] == 0


def test_a_threshold_read_from_the_environment_grades_and_is_not_published(
    tmp_path, monkeypatch
):
    """bandit's CRITICAL came from ``${VAR}``: it grades, and the map leaves it out.

    The statistics calculator prints the written reference for such a threshold
    and never the value; the unified results and the MCP payloads carry
    ``scanner_thresholds``, so the value would be published there alone.
    """
    monkeypatch.setattr(
        ScannerStatisticsCalculator,
        "get_scanner_threshold_details",
        _threshold_details({"bandit": "CRITICAL"}, from_env=frozenset({"bandit"})),
    )
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif_of(_finding("bandit"), _finding("semgrep")),
        "scanner_results": {
            "bandit": _scanner("PASSED"),
            "semgrep": _scanner("PASSED"),
        },
    }

    outcome = _run(tmp_path, plan)
    entry = outcome.payload.projects[0]

    # Graded as the scan graded it: bandit's HIGH is below its CRITICAL.
    assert entry.actionable_finding_count == 1
    # Not published: no entry for bandit, so a reader grades it by the project's.
    assert entry.scanner_thresholds == {}
    assert "CRITICAL" not in outcome.results_path.read_text("utf-8")
    # Red at the base: nothing said the fallback was not the verdict's gate, so
    # the merged reporters and the result filters regraded bandit's HIGH at
    # MEDIUM (actionable) while the verdict had not counted it. The name is
    # published, the value still is not.
    assert entry.withheld_scanner_thresholds == ["bandit"]
    assert entry.scanner_threshold_is_withheld("bandit") is True
    assert entry.scanner_threshold_is_withheld("semgrep") is False
    assert entry.threshold_for_scanner("bandit") == entry.severity_threshold


def test_no_withheld_threshold_is_recorded_when_none_came_from_the_environment(
    tmp_path, monkeypatch
):
    """Control: a scanner whose own threshold is in the config is published, not
    withheld, and the withheld list is empty."""
    monkeypatch.setattr(
        ScannerStatisticsCalculator,
        "get_scanner_threshold_details",
        _threshold_details({"bandit": "CRITICAL"}),
    )
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif_of(_finding("bandit"), _finding("semgrep")),
        "scanner_results": {
            "bandit": _scanner("PASSED"),
            "semgrep": _scanner("PASSED"),
        },
    }

    outcome = _run(tmp_path, plan)
    entry = outcome.payload.projects[0]

    assert entry.scanner_thresholds == {"bandit": "CRITICAL"}
    assert entry.withheld_scanner_thresholds == []
    assert entry.scanner_threshold_is_withheld("bandit") is False


def _config_with_bandit_at(threshold: str):
    """A real config: project-wide MEDIUM, bandit's own option at *threshold*."""
    from automated_security_helper.config.ash_config import AshConfig

    config = AshConfig()
    config.global_settings.severity_threshold = "MEDIUM"
    config.scanners.bandit.options.severity_threshold = threshold
    return config


def test_without_a_ceiling_a_scanners_own_looser_option_stands_through_real_config(
    tmp_path,
):
    """The control for the ceiling case: no monkeypatch, the recorded config decides."""
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    assert plan.projects[0].severity_ceiling is None
    FakeOrchestrator.behaviour["api"] = {
        "ash_config": _config_with_bandit_at("CRITICAL"),
        "sarif": _sarif_of(_finding("bandit")),
        "scanner_results": {"bandit": _scanner("PASSED")},
    }

    outcome = _run(tmp_path, plan)
    entry = outcome.payload.projects[0]

    # bandit's HIGH is below the CRITICAL its own option set, as it is in
    # `ash --source-dir P` with the same config.
    assert entry.finding_count == 1
    assert entry.actionable_finding_count == 0
    assert outcome.exit_code == WorkspaceExitCode.SUCCESS


def test_a_ceiling_binds_a_scanners_own_looser_option_even_when_it_moved_nothing(
    tmp_path,
):
    """Ceiling MEDIUM, project MEDIUM, bandit CRITICAL: bandit is graded at MEDIUM.

    The ceiling tightened nothing project-wide (MEDIUM over MEDIUM), so binding
    the scanner's own option only when the project-wide value moved let bandit's
    CRITICAL step under the ceiling and a HIGH pass. Bound whenever a ceiling
    exists, the HIGH is actionable.
    """
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    plan.projects[0] = plan.projects[0].model_copy(
        update={"severity_ceiling": "MEDIUM"}
    )
    assert plan.projects[0].threshold_tightened_by_policy is False
    FakeOrchestrator.behaviour["api"] = {
        "ash_config": _config_with_bandit_at("CRITICAL"),
        "sarif": _sarif_of(_finding("bandit")),
        "scanner_results": {"bandit": _scanner("PASSED")},
    }

    outcome = _run(tmp_path, plan)
    entry = outcome.payload.projects[0]

    assert entry.finding_count == 1
    assert entry.actionable_finding_count == 1
    assert entry.scanner_thresholds == {"bandit": "MEDIUM"}
    assert outcome.exit_code == WorkspaceExitCode.ACTIONABLE_FINDINGS


def test_a_ceiling_does_not_loosen_a_scanners_own_stricter_option(tmp_path):
    """Ceiling MEDIUM, project MEDIUM, bandit LOW: bandit stays at LOW.

    The mirror of ``test_a_ceiling_does_not_loosen_a_stricter_project`` for a
    scanner's own option. An implementation that replaced the option with the
    ceiling whenever one exists passes the case above and grades bandit's LOW
    finding as not actionable here.
    """
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    plan.projects[0] = plan.projects[0].model_copy(
        update={"severity_ceiling": "MEDIUM"}
    )
    FakeOrchestrator.behaviour["api"] = {
        "ash_config": _config_with_bandit_at("LOW"),
        "sarif": _sarif_of(_finding("bandit", "LOW")),
        "scanner_results": {"bandit": _scanner("PASSED")},
    }

    outcome = _run(tmp_path, plan)
    entry = outcome.payload.projects[0]

    assert entry.finding_count == 1
    assert entry.actionable_finding_count == 1
    assert entry.scanner_thresholds == {"bandit": "LOW"}
    assert outcome.exit_code == WorkspaceExitCode.ACTIONABLE_FINDINGS


def test_the_rollup_counts_what_the_verdict_counted_not_policy_origin_findings(
    tmp_path,
):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    # semgrep is a scanner only the workspace policy asked for, and the policy
    # does not gate: its findings are reported and decide nothing.
    plan.projects[0] = plan.projects[0].model_copy(
        update={"policy_scanners": ["semgrep"], "policy_scanners_gate": False}
    )
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif_of(_finding("bandit"), _finding("semgrep")),
        "scanner_results": {
            "bandit": _scanner("PASSED"),
            "semgrep": _scanner("PASSED"),
        },
    }

    outcome = _run(tmp_path, plan)
    entry = outcome.payload.projects[0]

    assert entry.finding_count == 2
    assert entry.policy_origin_finding_count == 1
    assert entry.actionable_finding_count == 1

    rollup = json.loads(outcome.results_path.read_text("utf-8"))["scanner_results"]
    # The per-scanner split sums to the project's own total.
    assert rollup["bandit"]["actionable_finding_count"] == 1
    assert rollup["semgrep"]["actionable_finding_count"] == 0
    assert rollup["semgrep"]["finding_count"] == 1
