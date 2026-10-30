# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Turning a resolved plan into N scoped scans.

The orchestrator is injected rather than mocked in place, so these tests exercise
the executor's own logic -- scoping, concurrency bounds, timeouts, the
changed-files gate, per-project verdicts -- without running any scanner. The
scanner-facing half of the contract (fresh plugin instances, per-project output
paths) is pinned in ``test_project_isolation.py`` against real plugin objects,
because a fake orchestrator could not prove anything about it.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 -- builds throwaway git repositories for the changed-files gate
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceExitCode,
)
from automated_security_helper.workspace.execution import (
    _ABANDONED_STOP_GRACE_SECONDS,
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from tests.utils.git_fixture import run_git


# ---------------------------------------------------------------------------
# Fixtures: a workspace on disk, and a fake orchestrator
# ---------------------------------------------------------------------------


def _sarif(*, level="error", uri="src/app.py", count=1, suppressed=False):
    results = []
    for index in range(count):
        entry = {
            "ruleId": f"R{index}",
            "level": level,
            "message": {"text": "fixture"},
            "properties": {"scanner_name": "bandit"},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": uri}}},
            ],
        }
        if suppressed:
            entry["suppressions"] = [{"kind": "external"}]
        results.append(entry)
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ASH"}},
                "results": results,
                "invocations": [],
            }
        ],
    }


class FakeOrchestrator:
    """Stands in for ASHScanOrchestrator, recording what it was scoped to."""

    #: Every instance built, in construction order. The executor must build one
    #: per project and never reuse one.
    built: List["FakeOrchestrator"] = []
    #: Per-project behaviour, keyed by the project directory name.
    behaviour: Dict[str, Dict[str, Any]] = {}
    lock = threading.Lock()

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.source_dir = Path(kwargs["source_dir"])
        self.output_dir = Path(kwargs["output_dir"])
        self.key = self.source_dir.name
        with FakeOrchestrator.lock:
            FakeOrchestrator.built.append(self)

    @classmethod
    def create(cls, **kwargs: Any) -> "FakeOrchestrator":
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
            ConverterStatusInfo,
            ScannerTargetStatusInfo,
        )
        from automated_security_helper.schemas.sarif_schema_model import SarifReport

        spec = FakeOrchestrator.behaviour.get(self.key, {})
        if "sleep" in spec:
            time.sleep(spec["sleep"])
        if "block" in spec:
            # An event rather than a sleep, so a timeout test can assert the
            # workspace returned while the worker was still running instead of
            # depending on a duration.
            spec["block"].wait(timeout=60)
        if "raise" in spec:
            raise spec["raise"]

        model = AshAggregatedResults()
        # The configuration the scan ran with, as the results record it, for a
        # test of what the recorded config decides (a scanner's own threshold).
        if "ash_config" in spec:
            model.ash_config = spec["ash_config"]
        model.sarif = SarifReport.model_validate(spec.get("sarif") or _sarif(count=0))

        # A real scan writes a scanner_results entry for every scanner it ran --
        # measured at 10 of 10 on a local run, including the ones that were
        # MISSING. This fake used to write none, and that is not a neutral
        # simplification: ScannerStatisticsCalculator gives a scanner it has no
        # record for the status ERROR, because findings attributed to a scanner the
        # report has no evidence ran is exactly what an unrecorded scanner looks
        # like. Fail-closed and right, but it made every fixture here model a state
        # no real scan produces, so the completeness gate fired on all of them.
        #
        # Derived from the SARIF rather than hardcoded to "bandit", so a test that
        # attributes findings to another scanner does not silently get an ERROR.
        for run in model.sarif.runs or []:
            for result in getattr(run, "results", None) or []:
                properties = getattr(result, "properties", None)
                name = getattr(properties, "scanner_name", None)
                if name and str(name) not in model.scanner_results:
                    model.scanner_results[str(name)] = ScannerTargetStatusInfo(
                        status="PASSED",
                        excluded=False,
                        dependencies_satisfied=True,
                    )
        # The explicit spec wins, so a test can say a scanner did not complete.
        for name, info in (spec.get("scanner_results") or {}).items():
            model.scanner_results[name] = ScannerTargetStatusInfo(**info)
        # Converter rows as ConvertPhase records them, for the converter half of
        # the completeness verdict.
        for name, row in (spec.get("converter_results") or {}).items():
            model.converter_results[name] = ConverterStatusInfo.model_validate(row)
        # The per-target reports, as ScanResultProcessor serializes them, for a test
        # that needs what a report recorded beyond the row.
        model.additional_reports.update(spec.get("additional_reports") or {})
        # The scan phase saves the per-project results file itself, before the
        # workspace layer sees the model (ScanPhase, AshAggregatedResults.save_model).
        # Off by default so the fixtures that assert the workspace's own write stay
        # exact; a test about what the scan left behind turns it on.
        if spec.get("save_results"):
            model.save_model(self.output_dir)
            # The report phase writes the project's own reports beside the
            # results, and the tools write their own output under scanners/.
            reports = self.output_dir / "reports"
            reports.mkdir(parents=True, exist_ok=True)
            (reports / "ash.sarif").write_text("{}\n", encoding="utf-8")
            tools = self.output_dir / "scanners" / "bandit"
            tools.mkdir(parents=True, exist_ok=True)
            (tools / "raw.json").write_text("{}\n", encoding="utf-8")
        # The SARIF report the scan's own SARIF reporter wrote, recorded on the
        # model as ReportPhase records it (record_reports_written), for a test of
        # what the verdict counts from. Off by default, so every other fixture's
        # counts keep coming from the model it built.
        if "written_sarif" in spec:
            from automated_security_helper.utils.inner_run_outcome import (
                record_reports_written,
            )

            reports = self.output_dir / "reports"
            reports.mkdir(parents=True, exist_ok=True)
            (reports / "ash.sarif").write_text(
                json.dumps(spec["written_sarif"]), encoding="utf-8"
            )
            record_reports_written(model, [("ash.sarif", "sarif")])
        # The raw values this project's own masking exposed, kept on the model as
        # secret_masking._record keeps them, for a test of the workspace's
        # cross-project masking.
        if "secret_values" in spec:
            model._secret_values = set(spec["secret_values"])
        return model


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _make_workspace(tmp_path, *specs):
    """Build a workspace on disk and a plan describing it.

    ``specs`` are ``(key, threshold)`` pairs. Directories are real because the
    executor resolves paths and creates output subtrees under them.
    """
    root = tmp_path / "workspace"
    root.mkdir(parents=True, exist_ok=True)
    projects = []
    for key, threshold in specs:
        project_dir = root / key
        (project_dir / "src").mkdir(parents=True, exist_ok=True)
        (project_dir / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
        projects.append(
            ProjectPlan(
                key=key,
                relative_path=key,
                path=project_dir.as_posix(),
                label=key,
                display_label=key,
                severity_threshold=threshold,
            )
        )
    workspace_file = root / "fixture.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": key} for key, _ in specs]}), encoding="utf-8"
    )
    plan = WorkspacePlan(
        workspace_file=workspace_file.as_posix(),
        workspace_root=root.as_posix(),
        projects=projects,
    )
    return root, plan


def _settings(tmp_path, **overrides) -> ProjectScanSettings:
    defaults: Dict[str, Any] = {
        "output_dir": tmp_path / "out",
        "phases": ("scan",),
        "max_parallel_projects": 2,
    }
    defaults.update(overrides)
    return ProjectScanSettings(**defaults)


def _run(tmp_path, plan, **overrides):
    return execute_workspace(
        plan,
        _settings(tmp_path, **overrides),
        orchestrator_factory=FakeOrchestrator.create,
    )


# ---------------------------------------------------------------------------
# Scoping
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPerProjectScoping:
    def test_one_orchestrator_per_project(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        _run(tmp_path, plan)
        assert sorted(o.key for o in FakeOrchestrator.built) == ["api", "web"]

    def test_each_source_dir_is_the_project_not_the_workspace_root(self, tmp_path):
        root, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        _run(tmp_path, plan)
        for orchestrator in FakeOrchestrator.built:
            assert orchestrator.source_dir != root
            assert orchestrator.source_dir.parent == root

    def test_each_output_dir_is_the_project_subtree(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        _run(tmp_path, plan)
        built = FakeOrchestrator.built[0]
        assert built.output_dir == tmp_path / "out" / "projects" / "api"

    def test_each_project_gets_a_config_resolved_from_its_own_file(self, tmp_path):
        """Was asserted via config_path, which the executor no longer passes.

        The executor now resolves each project's config itself and hands over a
        resolved_config, because the orchestrator refuses config_path alongside
        one. The property under test is unchanged -- each project's config comes
        from its own directory -- so the assertion moves to the resolved object,
        where it is stronger: it checks the file's CONTENT arrived, not just that
        a path was forwarded.
        """
        root, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        for project, threshold in (
            (plan.projects[0], "LOW"),
            (plan.projects[1], "HIGH"),
        ):
            ash_dir = Path(project.path) / ".ash"
            ash_dir.mkdir(parents=True, exist_ok=True)
            (ash_dir / "ash.yaml").write_text(
                f"global_settings:\n  severity_threshold: {threshold}\n",
                encoding="utf-8",
            )
            project.config_source = (ash_dir / "ash.yaml").as_posix()

        _run(tmp_path, plan)

        by_key = {o.key: o.kwargs["resolved_config"] for o in FakeOrchestrator.built}
        assert by_key["api"].global_settings.severity_threshold == "LOW"
        assert by_key["web"].global_settings.severity_threshold == "HIGH"
        assert by_key["api"] is not by_key["web"]

    def test_a_project_with_no_config_takes_the_default(self, tmp_path):
        """Same substitution: config_path=None became "resolution found no file".

        The observable consequence is what this asserts -- the project gets a
        usable default config rather than nothing -- which is what the old
        config_path assertion stood in for.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        assert plan.projects[0].config_source is None

        _run(tmp_path, plan)

        resolved = FakeOrchestrator.built[0].kwargs["resolved_config"]
        assert resolved is not None
        assert resolved.global_settings is not None

    def test_the_per_project_orchestrator_never_shows_progress(self, tmp_path):
        """N concurrent Rich Live displays would corrupt the terminal."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        _run(tmp_path, plan)
        assert all(o.kwargs["show_progress"] is False for o in FakeOrchestrator.built)

    def test_each_project_writes_its_own_results_file(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        _run(tmp_path, plan)
        for key in ("api", "web"):
            path = tmp_path / "out" / "projects" / key / "ash_aggregated_results.json"
            assert path.exists()

    def test_a_skipped_project_gets_no_orchestrator(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        plan.projects[1].skipped = True
        plan.projects[1].skip_reason = SkippedProjectReason.ERROR
        plan.projects[1].skip_detail = "does not exist"
        _run(tmp_path, plan)
        assert [o.key for o in FakeOrchestrator.built] == ["api"]

    def test_a_resolution_skip_is_carried_into_the_payload(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        plan.projects[1].skipped = True
        plan.projects[1].skip_reason = SkippedProjectReason.ERROR
        plan.projects[1].skip_detail = "does not exist"
        outcome = _run(tmp_path, plan)
        entry = next(p for p in outcome.payload.projects if p.project == "web")
        assert entry.status is ProjectRunStatus.SKIPPED
        assert entry.skip_reason is SkippedProjectReason.ERROR
        assert [e.project for e in outcome.payload.skipped_projects] == ["web"]


# ---------------------------------------------------------------------------
# Per-project verdicts
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPerProjectThresholds:
    def test_a_project_below_its_own_threshold_passes(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "CRITICAL"))
        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="warning")}
        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]
        assert entry.actionable_finding_count == 0
        assert entry.exceeds_threshold is False
        assert outcome.exit_code == WorkspaceExitCode.SUCCESS

    def test_a_project_above_its_own_threshold_fails(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "LOW"))
        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="warning")}
        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]
        assert entry.actionable_finding_count == 1
        assert entry.exceeds_threshold is True
        assert outcome.exit_code == WorkspaceExitCode.ACTIONABLE_FINDINGS

    def test_two_projects_are_judged_against_their_own_thresholds(self, tmp_path):
        """The whole point of per-project scoping, on one identical finding."""
        _, plan = _make_workspace(tmp_path, ("strict", "LOW"), ("lax", "CRITICAL"))
        for key in ("strict", "lax"):
            FakeOrchestrator.behaviour[key] = {"sarif": _sarif(level="warning")}
        outcome = _run(tmp_path, plan)
        verdicts = {p.project: p.exceeds_threshold for p in outcome.payload.projects}
        assert verdicts == {"strict": True, "lax": False}

    def test_a_workspace_ceiling_makes_a_lax_project_fail(self, tmp_path):
        """The ceiling has to change the VERDICT, not just the plan.

        api declares CRITICAL, so on its own a warning-level finding is not
        actionable -- test_a_project_below_its_own_threshold_passes above is that
        exact case. Under a MEDIUM ceiling the same finding must fail. If
        execution read severity_threshold instead of the effective value, this
        test would see exit 0 and the ceiling would be decorative.
        """
        _, plan = _make_workspace(tmp_path, ("api", "CRITICAL"))
        project = plan.projects[0]
        project.effective_severity_threshold = "MEDIUM"
        project.threshold_tightened_by_policy = True
        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="warning")}

        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]

        assert entry.actionable_finding_count == 1
        assert entry.exceeds_threshold is True
        assert outcome.exit_code == WorkspaceExitCode.ACTIONABLE_FINDINGS
        # The reported threshold is the one actually enforced, or a reader
        # comparing the finding against it would conclude ASH had miscounted.
        assert entry.severity_threshold == "MEDIUM"

    def test_a_ceiling_does_not_loosen_a_stricter_project(self, tmp_path):
        """The other direction, since a ceiling that replaced would pass here.

        strict declares LOW and the ceiling is CRITICAL. stricter_of keeps LOW,
        so the warning stays actionable. An implementation that let the ceiling
        win would report exit 0 for a project the operator set to LOW.
        """
        _, plan = _make_workspace(tmp_path, ("strict", "LOW"))
        project = plan.projects[0]
        # What resolution produces for a project already stricter than the
        # ceiling: unchanged, and not flagged as tightened.
        project.effective_severity_threshold = "LOW"
        project.threshold_tightened_by_policy = False
        FakeOrchestrator.behaviour["strict"] = {"sarif": _sarif(level="warning")}

        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]

        assert entry.actionable_finding_count == 1
        assert entry.exceeds_threshold is True
        assert entry.severity_threshold == "LOW"

    def test_a_plan_with_no_effective_threshold_falls_back_to_the_projects_own(
        self, tmp_path
    ):
        """Plans built outside resolve_workspace never set the effective value.

        plan.py's docstring says a hand-built plan can hold states resolution
        would not produce, and the executor is given plans by tests and by
        callers that predate this field. Falling back keeps those judged by their
        own threshold rather than by None, which would turn the gate off.
        """
        _, plan = _make_workspace(tmp_path, ("api", "LOW"))
        assert plan.projects[0].effective_severity_threshold is None

        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="warning")}
        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]

        assert entry.actionable_finding_count == 1
        assert entry.severity_threshold == "LOW"

    def test_the_per_scanner_rollup_agrees_with_the_project_total_under_a_ceiling(
        self, tmp_path
    ):
        """Two derivations of one number must not disagree once policy applies.

        The project's actionable count is computed from the effective threshold,
        while the workspace rollup splits it per scanner. If the split is derived
        from the DECLARED threshold instead, the two disagree the moment a ceiling
        tightens anything -- the per-scanner numbers sum to 0 while the project
        says 1, and a reader has no rule for which to trust.

        This is the failure the ceiling wiring introduces if the split is missed,
        so it is asserted as an equality between the two payloads rather than
        against a literal.
        """
        _, plan = _make_workspace(tmp_path, ("api", "CRITICAL"))
        project = plan.projects[0]
        project.effective_severity_threshold = "MEDIUM"
        project.threshold_tightened_by_policy = True
        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="warning")}

        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]

        # Control: the ceiling really did make this actionable, or the equality
        # below would hold trivially at 0 == 0 and prove nothing.
        assert entry.actionable_finding_count == 1

        # Read the written file: scanner_results is a top-level key of the
        # aggregated report, not a field of WorkspaceResults, and the file is what
        # a consumer actually reads.
        written = json.loads(
            (tmp_path / "out" / "ash_aggregated_results.json").read_text(
                encoding="utf-8"
            )
        )
        rollup = {
            name: (value or {}).get("actionable_finding_count", 0)
            for name, value in (written.get("scanner_results") or {}).items()
        }
        assert sum(rollup.values()) == entry.actionable_finding_count, rollup

    def test_a_tightened_project_discloses_findings_the_ceiling_could_not_reach(
        self, tmp_path
    ):
        """The mechanised form of the documented limitation, on the outcome.

        A level-only `error` is read as critical by both threshold gates, so
        tightening CRITICAL to MEDIUM changes nothing for it. The project still
        fails -- correctly -- but the operator needs to know the ceiling is not
        what made it fail, or they will conclude the ceiling works on findings it
        never touched.
        """
        _, plan = _make_workspace(tmp_path, ("api", "CRITICAL"))
        project = plan.projects[0]
        project.effective_severity_threshold = "MEDIUM"
        project.threshold_tightened_by_policy = True
        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="error")}

        entry = _run(tmp_path, plan).payload.projects[0]
        assert entry.ceiling_unreachable_findings == {"bandit": 1}

    def test_an_untightened_project_discloses_nothing(self, tmp_path):
        """Load-bearing only. The same finding, no ceiling, no disclosure.

        Without this the disclosure would appear on every scan carrying a
        level-only finding, and a message that always appears is one nobody
        reads.
        """
        _, plan = _make_workspace(tmp_path, ("api", "CRITICAL"))
        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="error")}

        entry = _run(tmp_path, plan).payload.projects[0]
        # Control: the finding IS present and actionable, so the empty disclosure
        # is a decision rather than an absence of input.
        assert entry.actionable_finding_count == 1
        assert entry.ceiling_unreachable_findings == {}

    def test_the_disclosure_follows_the_tightened_flag_not_just_the_thresholds(
        self, tmp_path
    ):
        """Pins the execution-level guard, which is otherwise indistinguishable.

        ceiling_unreachable_counts short-circuits on equal thresholds, so for any
        plan resolve_workspace builds -- where the flag and the two thresholds are
        set together and cannot disagree -- either guard alone suffices, and
        removing the one in execution.py leaves every other test green. That was
        measured, not assumed.

        This constructs the one state where they disagree: differing thresholds
        with the flag false, which plan.py's docstring says a hand-built plan may
        hold. The flag is the record of whether policy moved this project, so it
        is what the disclosure follows.
        """
        _, plan = _make_workspace(tmp_path, ("api", "CRITICAL"))
        project = plan.projects[0]
        project.effective_severity_threshold = "MEDIUM"
        project.threshold_tightened_by_policy = False
        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="error")}

        entry = _run(tmp_path, plan).payload.projects[0]

        # Control: the finding is present and the thresholds DO differ, so the
        # empty disclosure is the flag's doing and not a missing input.
        assert entry.actionable_finding_count == 1
        assert project.severity_threshold != project.effective_severity_threshold
        assert entry.ceiling_unreachable_findings == {}

    def test_a_tightened_project_whose_findings_the_ceiling_reached_discloses_nothing(
        self, tmp_path
    ):
        """The other load-bearing arm: tightening happened AND it worked.

        A severity-carrying MEDIUM finding is exactly what the ceiling is for, so
        there is nothing to qualify. Distinguishes "we disclose whenever tightened"
        from "we disclose when tightening fell short".
        """
        _, plan = _make_workspace(tmp_path, ("api", "CRITICAL"))
        project = plan.projects[0]
        project.effective_severity_threshold = "MEDIUM"
        project.threshold_tightened_by_policy = True
        sarif = _sarif(level="warning")
        sarif["runs"][0]["results"][0]["properties"]["issue_severity"] = "MEDIUM"
        FakeOrchestrator.behaviour["api"] = {"sarif": sarif}

        entry = _run(tmp_path, plan).payload.projects[0]
        assert entry.actionable_finding_count == 1
        assert entry.ceiling_unreachable_findings == {}

    def test_a_non_gating_policy_scanners_level_only_finding_is_not_disclosed(
        self, tmp_path
    ):
        """The verdict's policy_scanners_gate exclusion, applied to the disclosure.

        semgrep is a scanner only the workspace policy asked for, with the gate
        off: its findings are judged at no threshold, so the ceiling never
        claimed them. Red at the base: the executor called the counter without
        the project's non-gating scanners, so the helper's own exclusion never
        ran in production and semgrep's level-only finding was disclosed as one
        the ceiling could not reach. bandit's is the control: the project's own
        scanner, still disclosed.
        """
        _, plan = _make_workspace(tmp_path, ("api", "CRITICAL"))
        project = plan.projects[0].model_copy(
            update={"policy_scanners": ["semgrep"], "policy_scanners_gate": False}
        )
        project.effective_severity_threshold = "MEDIUM"
        project.threshold_tightened_by_policy = True
        plan.projects[0] = project
        sarif = _sarif(level="error", count=2)
        sarif["runs"][0]["results"][1]["properties"]["scanner_name"] = "semgrep"
        FakeOrchestrator.behaviour["api"] = {"sarif": sarif}

        entry = _run(tmp_path, plan).payload.projects[0]

        # Controls: semgrep's finding is present and policy-origin, and bandit's
        # is actionable, so the missing semgrep key is the exclusion's doing.
        assert entry.finding_count == 2
        assert entry.policy_origin_finding_count == 1
        assert entry.actionable_finding_count == 1
        assert entry.ceiling_unreachable_findings == {"bandit": 1}

    def test_a_gating_policy_scanners_level_only_finding_is_disclosed(self, tmp_path):
        """The other arm: with the gate on, semgrep's finding decides the verdict,
        so the ceiling's claim covers it and the disclosure names both scanners."""
        _, plan = _make_workspace(tmp_path, ("api", "CRITICAL"))
        project = plan.projects[0].model_copy(
            update={"policy_scanners": ["semgrep"], "policy_scanners_gate": True}
        )
        project.effective_severity_threshold = "MEDIUM"
        project.threshold_tightened_by_policy = True
        plan.projects[0] = project
        sarif = _sarif(level="error", count=2)
        sarif["runs"][0]["results"][1]["properties"]["scanner_name"] = "semgrep"
        FakeOrchestrator.behaviour["api"] = {"sarif": sarif}

        entry = _run(tmp_path, plan).payload.projects[0]

        assert entry.actionable_finding_count == 2
        assert entry.ceiling_unreachable_findings == {"bandit": 1, "semgrep": 1}

    def test_the_aggregate_exit_code_reflects_the_strictest_failing_project(
        self, tmp_path
    ):
        _, plan = _make_workspace(tmp_path, ("strict", "LOW"), ("lax", "CRITICAL"))
        FakeOrchestrator.behaviour["strict"] = {"sarif": _sarif(level="warning")}
        FakeOrchestrator.behaviour["lax"] = {"sarif": _sarif(level="warning")}
        outcome = _run(tmp_path, plan)
        assert outcome.exit_code == WorkspaceExitCode.ACTIONABLE_FINDINGS
        # Asserted against the member, not the integer: a findings verdict and a
        # workspace definition error are different codes and must stay different.
        assert outcome.exit_code != WorkspaceExitCode.WORKSPACE_ERROR

    def test_fail_on_findings_off_records_findings_without_failing(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "LOW"))
        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="error")}
        outcome = _run(tmp_path, plan, fail_on_findings=False)
        entry = outcome.payload.projects[0]
        assert entry.actionable_finding_count == 1
        assert entry.exceeds_threshold is False
        assert outcome.exit_code == WorkspaceExitCode.SUCCESS

    def test_suppressed_findings_do_not_count(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "ALL"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(level="error", suppressed=True)
        }
        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]
        assert entry.finding_count == 0
        assert entry.actionable_finding_count == 0

    def test_min_severity_can_zero_an_otherwise_failing_project(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "ALL"))
        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="note")}
        outcome = _run(tmp_path, plan, min_severity="high")
        assert outcome.payload.projects[0].exceeds_threshold is False


# ---------------------------------------------------------------------------
# Scanner completeness
# ---------------------------------------------------------------------------


def _scanner(status, *, excluded=False, satisfied=True):
    """One ``scanner_results`` entry, as the fake orchestrator takes them."""
    return {
        "status": status,
        "excluded": excluded,
        "dependencies_satisfied": satisfied,
    }


@pytest.mark.unit
class TestScannerCompleteness:
    """A project whose scanners did not all run must not report clean.

    The gap this closes. ``_compute_exit_code`` asks two questions in order --
    did the selected scanners run, and did they find anything -- and workspace
    mode only ever asked the second. So ``ash --source-dir P`` exited 1 on a host
    missing P's scanners while the same P inside a workspace reported SUCCESS,
    for the same reason a finding-count verdict cannot tell "nothing was wrong"
    from "nothing was checked".

    An incomplete project is an unknown, so it lands on ``INTERNAL_ERROR`` (1),
    which ranks ABOVE ``ACTIONABLE_FINDINGS`` (2), as in single-project mode.
    ``WORKSPACE_ERROR`` (4) is untouched: it means nothing was attempted, and these
    projects were.
    """

    def test_a_missing_scanner_stops_a_clean_project_reporting_success(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "bandit": _scanner("PASSED"),
                "cfn-nag": _scanner("MISSING", satisfied=False),
            },
        }
        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]

        # Control: no findings at all, so a threshold-only verdict says SUCCESS
        # and only the completeness pass can move this.
        assert entry.actionable_finding_count == 0
        assert entry.exceeds_threshold is False

        assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR
        assert entry.incomplete_scanners == ["cfn-nag"]
        assert entry.scan_incomplete is True

    @pytest.mark.parametrize(
        "policy,incomplete,code",
        [
            ("fail", True, WorkspaceExitCode.INTERNAL_ERROR),
            ("warn", False, WorkspaceExitCode.SUCCESS),
        ],
    )
    def test_a_stale_content_database_follows_its_policy_not_the_flag(
        self, tmp_path, policy, incomplete, code
    ):
        """`ash --source-dir P` exits 1 on a stale database; P inside a workspace must too.

        With the completeness gate explicitly off, so only the staleness arm can move it.
        """
        from datetime import datetime, timedelta, timezone

        from automated_security_helper.schemas.sarif_schema_model import SarifReport
        from automated_security_helper.utils import content_db_staleness as staleness
        from automated_security_helper.utils.content_databases import get

        entry = get("grype-db")
        now = datetime.now(timezone.utc)
        record = staleness.ContentDbAgeRecord(
            name=entry.name,
            scanner=entry.scanner,
            built=now - timedelta(days=10),
            measured_by=entry.age_source,
            max_age=entry.max_age,
            measured_at=now,
            policy=policy,
            bound_source=entry.bound_source,
            bound_is_tool_default=entry.bound_is_tool_default,
            refresh=entry.refresh,
        )
        report = SarifReport.model_validate(_sarif(count=0))
        staleness.attach_records(report, [record])

        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": json.loads(
                report.model_dump_json(by_alias=True, exclude_none=True)
            ),
            "scanner_results": {"grype": _scanner("PASSED")},
        }
        outcome = _run(tmp_path, plan, fail_on_incomplete_scanners=False)
        assert outcome.payload.projects[0].scan_incomplete is incomplete
        assert outcome.exit_code == code
        # Named once, in its own field, as a single scan's payload names it; grype
        # ran, so it is not among the scanners that did not complete.
        project = outcome.payload.projects[0]
        assert [r["name"] for r in project.stale_content_databases] == (
            ["grype-db"] if policy == "fail" else []
        )
        assert project.incomplete_scanners == []

    def test_an_error_scanner_stops_a_clean_project_reporting_success(self, tmp_path):
        """ERROR and MISSING are the same news: the scanner did not complete."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"bandit": _scanner("ERROR")},
        }
        outcome = _run(tmp_path, plan)

        assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR
        assert outcome.payload.projects[0].incomplete_scanners == ["bandit"]

    def test_a_scanner_the_operator_excluded_is_not_incomplete(self, tmp_path):
        """The control that separates a correct gate from a plausible one.

        This entry is excluded AND its tool is absent, which is what
        ``--exclude-scanners cfn-nag`` looks like on a host without cfn-nag. Read
        through ``get_unified_scanner_metrics`` the exclusion wins and the status
        is SKIPPED; read straight off ``scanner_results`` it is MISSING. A gate
        built on the raw statuses passes every other test in this class and fails
        a workspace for a scanner the operator told it not to run -- which is also
        how sharding divides work, so it would fail every shard of a healthy
        sharded scan.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "bandit": _scanner("PASSED"),
                "cfn-nag": _scanner("MISSING", excluded=True, satisfied=False),
            },
        }
        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]

        assert entry.incomplete_scanners == []
        assert entry.scan_incomplete is False
        assert outcome.exit_code == WorkspaceExitCode.SUCCESS

    def test_the_gate_can_be_turned_off_without_hiding_which_scanners_missed(
        self, tmp_path
    ):
        """Same shape as fail_on_findings: the count stays honest, the verdict moves.

        An operator who turns the gate off has accepted the risk; they have not
        asked to be told the scan was complete. So the disclosure survives and
        only ``scan_incomplete`` follows the flag.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"cfn-nag": _scanner("MISSING", satisfied=False)},
        }
        outcome = _run(tmp_path, plan, fail_on_incomplete_scanners=False)
        entry = outcome.payload.projects[0]

        assert entry.incomplete_scanners == ["cfn-nag"]
        assert entry.scan_incomplete is False
        assert outcome.exit_code == WorkspaceExitCode.SUCCESS

    def test_an_incomplete_project_outranks_another_project_s_findings(self, tmp_path):
        """Workspace precedence is single-project's: 1 ahead of 2.

        Reverses this test's earlier expectation (ACTIONABLE_FINDINGS), by design:
        `ash --source-dir P` answers 1 when a scanner did not complete, so P inside
        a workspace must too, whatever another project found. The findings stay in
        the payload; see the ordering rationale in models/workspace.py.
        """
        _, plan = _make_workspace(tmp_path, ("api", "LOW"), ("web", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(level="error"),
            "scanner_results": {"bandit": _scanner("PASSED")},
        }
        FakeOrchestrator.behaviour["web"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"cfn-nag": _scanner("MISSING", satisfied=False)},
        }
        outcome = _run(tmp_path, plan)
        verdicts = {p.project: p.scan_incomplete for p in outcome.payload.projects}

        # Control: both facts really are present, so 1 is precedence and not the
        # findings having gone missing.
        assert verdicts == {"api": False, "web": True}
        thresholds = {p.project: p.exceeds_threshold for p in outcome.payload.projects}
        assert thresholds == {"api": True, "web": False}
        assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR

    def test_a_complete_clean_project_still_reports_success(self, tmp_path):
        """Load-bearing: the gate must not fail every workspace it looks at."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "bandit": _scanner("PASSED"),
                "cfn-nag": _scanner("SKIPPED", excluded=True),
            },
        }
        outcome = _run(tmp_path, plan)

        assert outcome.payload.projects[0].incomplete_scanners == []
        assert outcome.exit_code == WorkspaceExitCode.SUCCESS

    def test_a_project_whose_every_scanner_was_skipped_does_not_report_success(
        self, tmp_path
    ):
        """The set-level half of the same gate, which the per-entry pass cannot see.

        SKIPPED has to be tolerated one entry at a time, because that is how an
        exclusion and another shard's ownership are recorded. So a project whose
        *every* entry is SKIPPED cleared the per-entry pass having measured nothing:
        ``incomplete_scanners == []``, ``scan_incomplete == False``, COMPLETED, zero
        actionable findings, workspace exit 0. ``ash --source-dir P`` on the same
        project exits 1 through ``_compute_exit_code``'s own set-level check.

        Reachable without sharding and without operator error beyond one misspelled
        word: an allowlist that resolves to a scanner this platform declines leaves
        every entry SKIPPED.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "bandit": _scanner("SKIPPED", excluded=True),
                "cfn-nag": _scanner("SKIPPED", excluded=True),
            },
        }
        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]

        # Control: nothing was found and no single entry is incomplete, so only the
        # set-level question can move this verdict.
        assert entry.actionable_finding_count == 0
        assert entry.exceeds_threshold is False
        assert entry.incomplete_scanners == []

        assert entry.no_scanner_ran is True
        assert entry.scan_incomplete is True
        assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR

    def test_one_scanner_that_ran_is_enough_to_keep_a_narrowed_project_passing(
        self, tmp_path
    ):
        """The control for the case above, at the boundary that decides it.

        ``ash scan --scanners bandit`` inside a workspace leaves every other entry
        SKIPPED, and that is a scan which did what it was asked. Without this the
        set-level gate could be stuck at always-fail -- which would fail every
        narrowed workspace run -- and the test above would still pass.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "bandit": _scanner("PASSED"),
                "cfn-nag": _scanner("SKIPPED", excluded=True),
            },
        }
        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]

        assert entry.no_scanner_ran is False
        assert entry.scan_incomplete is False
        assert outcome.exit_code == WorkspaceExitCode.SUCCESS

    def test_turning_the_gate_off_keeps_the_all_skipped_disclosure(self, tmp_path):
        """Same shape as ``incomplete_scanners``: the fact stays, the verdict moves.

        ``no_scanner_ran`` is recorded unconditionally so an operator who turned the
        gate off can still see that the project measured nothing; only
        ``scan_incomplete`` follows the flag.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"bandit": _scanner("SKIPPED", excluded=True)},
        }
        outcome = _run(tmp_path, plan, fail_on_incomplete_scanners=False)
        entry = outcome.payload.projects[0]

        assert entry.no_scanner_ran is True
        assert entry.scan_incomplete is False
        assert outcome.exit_code == WorkspaceExitCode.SUCCESS

    def test_a_project_that_recorded_no_scanners_at_all_is_not_flagged(self, tmp_path):
        """An empty scanner set is a different claim, and ``--phases convert`` makes one.

        ``no_scanner_ran`` answers False for an empty set deliberately, so that a
        phase-limited run does not become an error. Pinned here because a mirrored
        implementation that tested emptiness would fail every convert-only project.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {},
        }
        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]

        assert entry.no_scanner_ran is False
        assert entry.scan_incomplete is False
        assert outcome.exit_code == WorkspaceExitCode.SUCCESS

    def test_the_incomplete_project_is_named_in_the_written_file(self, tmp_path):
        """A consumer reads the file, not the return value."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"cfn-nag": _scanner("MISSING", satisfied=False)},
        }
        _run(tmp_path, plan)

        written = json.loads(
            (tmp_path / "out" / "ash_aggregated_results.json").read_text(
                encoding="utf-8"
            )
        )
        project = written["workspace"]["projects"][0]
        assert project["incomplete_scanners"] == ["cfn-nag"]
        assert project["scan_incomplete"] is True

    def test_the_rollup_does_not_claim_a_missing_scanner_had_its_dependencies(
        self, tmp_path
    ):
        """The workspace file must not contradict itself about one scanner.

        ``scanner_results`` in the written file is the shape every reader already
        knows, and ``ScannerStatisticsCalculator`` derives "missing" from
        ``dependencies_satisfied`` rather than from ``status``. Asserting True
        there while status says MISSING makes any tool that re-derives a verdict
        from the workspace file -- ``ash report`` on a workspace output, or the
        completeness gate itself -- read the scanner as present.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "bandit": _scanner("PASSED"),
                "cfn-nag": _scanner("MISSING", satisfied=False),
            },
        }
        _run(tmp_path, plan)

        written = json.loads(
            (tmp_path / "out" / "ash_aggregated_results.json").read_text(
                encoding="utf-8"
            )
        )
        rollup = written["scanner_results"]
        assert rollup["cfn-nag"]["status"] == "MISSING"
        assert rollup["cfn-nag"]["dependencies_satisfied"] is False
        # Control: the honest entry is unchanged, so this is not a blanket flip.
        assert rollup["bandit"]["dependencies_satisfied"] is True


def _missing(reason):
    return {
        **_scanner("MISSING", satisfied=False),
        "missing_reason": reason,
    }


def _skipped(reason):
    return {**_scanner("SKIPPED", excluded=True), "skipped_reason": reason}


def _written(tmp_path) -> Dict[str, Any]:
    return json.loads(
        (tmp_path / "out" / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )


@pytest.mark.unit
class TestScannerReasonsInTheWorkspace:
    """The workspace says why a scanner did not run, as a single scan does.

    Each project's own ``projects/<key>/ash_aggregated_results.json`` has the
    rows' missing_reason and skipped_reason. The workspace's own file rolls the
    scanner rows up to the worst status across projects, and docs/content/docs/
    output-formats.md says its ``scanner_results`` carry the same two fields. So a
    rolled-up SKIPPED or MISSING row names, for each project at that status, the
    project and its reason: ``<project>: <reason>``, joined with ``; `` in
    workspace-file order. Each project's entry in the ``workspace`` block keeps its
    own reasons in ``scanner_reasons``.
    """

    def test_each_project_entry_keeps_its_scanners_reasons(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "bandit": _scanner("PASSED"),
                "cfn-nag": _missing("its tool cfn_nag_scan was not found on PATH"),
                "grype": _skipped("excluded from this run (--exclude-scanners)"),
            },
        }
        _run(tmp_path, plan)

        project = _written(tmp_path)["workspace"]["projects"][0]
        assert project.get("scanner_reasons") == {
            "cfn-nag": "its tool cfn_nag_scan was not found on PATH",
            "grype": "excluded from this run (--exclude-scanners)",
        }, project

    def test_an_error_row_lists_the_error_its_report_recorded(self, tmp_path):
        """An ERROR scanner says why, from the first error its reports recorded.

        A scanner whose constructor raised is ERROR with no reason field on its
        row; the scan phase records the constructor's error on its report. An MCP
        client reads the project's entry, not ash.log, so without this it learns
        only that the scanner failed.
        """
        constructor_error = (
            "Scanner bandit could not be constructed, so it did not run: "
            "RuntimeError: boom"
        )
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "bandit": _scanner("ERROR"),
                "grype": _scanner("ERROR"),
                "semgrep": _scanner("PASSED"),
            },
            "additional_reports": {
                "bandit": {
                    "None": {
                        "scanner_name": "bandit",
                        "status": "ERROR",
                        "errors": [constructor_error],
                    }
                },
                # Control: an ERROR whose report recorded no error is not listed.
                "grype": {"source": {"scanner_name": "grype", "status": "ERROR"}},
            },
        }
        _run(tmp_path, plan)

        written = _written(tmp_path)
        project = written["workspace"]["projects"][0]
        assert project.get("scanner_reasons") == {"bandit": constructor_error}, project
        # The rollup keeps its reason fields for SKIPPED and MISSING rows.
        row = written["scanner_results"]["bandit"]
        assert row["status"] == "ERROR", row
        assert row.get("missing_reason") is None, row
        assert row.get("skipped_reason") is None, row

    def test_an_error_from_a_scan_that_raised_lists_its_message(self, tmp_path):
        """The executor records a raised scan()'s error in the report's raw_results.

        That ERROR's report has no ``errors`` of its own: the message is
        ``raw_results.errors[0]``, beside the exception and its stack trace. The
        message is listed; the stack trace, which a report keeps for a reader of
        the results file, is not.
        """
        message = "Failed to execute bandit scanner on source: bandit crashed"
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"bandit": _scanner("ERROR")},
            "additional_reports": {
                "bandit": {
                    "source": {
                        "scanner_name": "bandit",
                        "status": "ERROR",
                        "raw_results": {
                            "errors": [message, "a second error"],
                            "status": "failed",
                            "exception": "bandit crashed",
                            "stack_trace": "Traceback (most recent call last):\n...",
                        },
                    }
                }
            },
        }
        _run(tmp_path, plan)

        project = _written(tmp_path)["workspace"]["projects"][0]
        assert project.get("scanner_reasons") == {"bandit": message}, project

    def test_a_listed_error_carries_no_environment_value(self, tmp_path, monkeypatch):
        """Listed redacted with the project config's environment values.

        The listed message goes to the workspace results and the MCP response,
        where env values are never written, and a report's error can name an
        option the project's config read from the environment: a tool's stderr
        line about a file it could not load, say.
        """
        value = "/nonexistent/ENVCANARY-listed-error/bandit.toml"
        monkeypatch.setenv("ASH_CONFIG_FILE_FROM_ENV", value)
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        ash_dir = Path(plan.projects[0].path) / ".ash"
        ash_dir.mkdir(parents=True, exist_ok=True)
        (ash_dir / "ash.yaml").write_text(
            "project_name: api\n"
            "scanners:\n"
            "  bandit:\n"
            "    options:\n"
            "      config_file: ${ASH_CONFIG_FILE_FROM_ENV}\n",
            encoding="utf-8",
        )
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"bandit": _scanner("ERROR")},
            "additional_reports": {
                "bandit": {
                    "source": {
                        "scanner_name": "bandit",
                        "status": "ERROR",
                        "raw_results": {
                            "errors": [f"[main] WARNING could not load {value}"],
                            "status": "failed",
                        },
                    }
                }
            },
        }
        _run(tmp_path, plan)

        project = _written(tmp_path)["workspace"]["projects"][0]
        reason = (project.get("scanner_reasons") or {}).get("bandit", "")
        assert "could not load" in reason, project
        assert "ENVCANARY-listed-error" not in reason, reason

    def test_a_rolled_up_missing_row_names_each_project_and_its_reason(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"cfn-nag": _missing("no cfn_nag_scan on PATH")},
        }
        FakeOrchestrator.behaviour["web"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"cfn-nag": _missing("no ruby on PATH")},
        }
        _run(tmp_path, plan)

        row = _written(tmp_path)["scanner_results"]["cfn-nag"]
        assert row["status"] == "MISSING", row
        assert row.get("missing_reason") == (
            "api: no cfn_nag_scan on PATH; web: no ruby on PATH"
        ), row
        assert row.get("skipped_reason") is None, row

    def test_only_the_projects_at_the_rolled_up_status_are_named(self, tmp_path):
        """MISSING in one project and SKIPPED in another rolls up MISSING.

        The SKIPPED project's reason is not a reason the scanner is MISSING, so
        it is not on the row; it stays on that project's own entry.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "grype": _skipped("excluded from this run (--exclude-scanners)")
            },
        }
        FakeOrchestrator.behaviour["web"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"grype": _missing("no grype on PATH")},
        }
        _run(tmp_path, plan)

        written = _written(tmp_path)
        row = written["scanner_results"]["grype"]
        assert row["status"] == "MISSING", row
        assert row.get("missing_reason") == "web: no grype on PATH", row
        assert row.get("skipped_reason") is None, row
        api = written["workspace"]["projects"][0]
        assert api.get("scanner_reasons") == {
            "grype": "excluded from this run (--exclude-scanners)"
        }, api

    def test_a_rolled_up_skipped_row_names_each_project_and_its_reason(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"bandit": _skipped("not named by --scanners")},
        }
        FakeOrchestrator.behaviour["web"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "bandit": _skipped("disabled in the configuration (enabled: false)")
            },
        }
        _run(tmp_path, plan)

        row = _written(tmp_path)["scanner_results"]["bandit"]
        assert row["status"] == "SKIPPED", row
        assert row.get("skipped_reason") == (
            "api: not named by --scanners; "
            "web: disabled in the configuration (enabled: false)"
        ), row
        assert row.get("missing_reason") is None, row

    def test_the_rolled_up_reason_reads_back_through_the_results_model(self, tmp_path):
        """What ``ash report`` over the workspace output reads."""
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
        )

        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"cfn-nag": _missing("no cfn_nag_scan on PATH")},
        }
        _run(tmp_path, plan)

        model = AshAggregatedResults.model_validate_json(
            (tmp_path / "out" / "ash_aggregated_results.json").read_text(
                encoding="utf-8"
            )
        )
        row = model.scanner_results["cfn-nag"]
        assert row.missing_reason == "api: no cfn_nag_scan on PATH", row

    def test_a_scanner_that_ran_has_no_reason_on_the_rollup(self, tmp_path):
        """Control: only SKIPPED and MISSING rows carry a reason."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"bandit": _scanner("PASSED")},
        }
        _run(tmp_path, plan)

        written = _written(tmp_path)
        row = written["scanner_results"]["bandit"]
        assert row.get("missing_reason") is None, row
        assert row.get("skipped_reason") is None, row
        assert written["workspace"]["projects"][0].get("scanner_reasons", {}) == {}

    def test_a_workspace_block_without_reasons_still_loads(self, tmp_path):
        """Control: a workspace file written before the field reads with none."""
        from automated_security_helper.models.workspace import WorkspaceResults

        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"cfn-nag": _missing("no cfn_nag_scan on PATH")},
        }
        _run(tmp_path, plan)
        block = _written(tmp_path)["workspace"]
        for project in block["projects"]:
            project.pop("scanner_reasons", None)

        loaded = WorkspaceResults.model_validate(block)

        (project,) = loaded.projects
        assert getattr(project, "scanner_reasons", {}) == {}
        assert project.scanners == {"cfn-nag": "MISSING"}


# ---------------------------------------------------------------------------
# Failures and timeouts
# ---------------------------------------------------------------------------

#: Budget for the tests that need a project to exceed its deadline.
#
# It was 0.2s, and that produced an intermittent CI failure in
# test_a_project_timeout_fails_that_project_only: the assertion is that a timeout fails only the
# offending project, and on one run BOTH the slow project AND the one configured to sleep not at
# all exceeded the budget. A project with no work to do cannot overrun a deadline that covers the
# cost of starting it, so 0.2s did not cover that cost on a loaded runner.
#
# The leading explanation is cold Pydantic validation under CPU contention -- FakeOrchestrator
# validates a SarifReport, and first-use model validation is easily over 200ms on a contended
# runner with several xdist workers competing. That would also explain why the sibling tests
# below survived the same run: by the time they execute, the models are warm in that worker.
# Stated as the best available reading rather than a measurement, because reproducing a hosted
# runner's load was not attempted.
#
# The value does not depend on which explanation is right, which is the point. What was wrong was
# a budget of the same order as the fixed overhead of running a project at all, so the fix is
# headroom -- 15x the old value -- rather than a smaller number or a retry. The cost is that each
# test here waits for this to elapse before the workspace gives up; under xdist that is
# concurrent, and a deterministic three seconds beats an 0.2s race that lands on unrelated PRs.
PROJECT_TIMEOUT = 3.0


@pytest.mark.unit
class TestConverterCompleteness:
    """A project whose converter lost coverage is incomplete, as ``ash --source-dir P`` is.

    ``_compute_exit_code`` asks ``incomplete_converters`` alongside the scanner
    questions: a notebook that could not be converted, a converter that crashed, or
    one whose tool was absent with inputs to convert. The workspace verdict asked
    only the scanner questions, so the same project passed inside a workspace.
    """

    @staticmethod
    def _project(tmp_path, converter_row):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"bandit": _scanner("PASSED")},
            "converter_results": {"jupyter": converter_row},
        }
        return plan

    def test_a_failed_conversion_makes_the_project_incomplete(self, tmp_path):
        plan = self._project(
            tmp_path,
            {"failed_inputs": [{"path": "nb.ipynb", "reason": "nbconvert timed out"}]},
        )

        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]

        # Control: every scanner completed and nothing was found.
        assert entry.incomplete_scanners == []
        assert entry.exceeds_threshold is False

        assert entry.scan_incomplete is True
        assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR
        assert entry.incomplete_converters == {
            "jupyter": "could not convert 1 input: nb.ipynb"
        }

    def test_a_crashed_converter_makes_the_project_incomplete(self, tmp_path):
        plan = self._project(tmp_path, {"failure": "RuntimeError: boom"})

        entry = _run(tmp_path, plan).payload.projects[0]

        assert entry.scan_incomplete is True
        assert entry.incomplete_converters == {"jupyter": "RuntimeError: boom"}

    def test_the_gate_off_still_reports_the_converter(self, tmp_path):
        plan = self._project(
            tmp_path,
            {"failed_inputs": [{"path": "nb.ipynb", "reason": "timed out"}]},
        )

        outcome = _run(tmp_path, plan, fail_on_incomplete_scanners=False)
        entry = outcome.payload.projects[0]

        assert entry.scan_incomplete is False
        assert outcome.exit_code == WorkspaceExitCode.SUCCESS
        assert list(entry.incomplete_converters) == ["jupyter"]

    def test_an_absent_tool_with_nothing_to_convert_is_complete(self, tmp_path):
        plan = self._project(
            tmp_path, {"dependencies_satisfied": False, "candidate_inputs": 0}
        )

        outcome = _run(tmp_path, plan)
        entry = outcome.payload.projects[0]

        assert entry.incomplete_converters == {}
        assert entry.scan_incomplete is False
        assert outcome.exit_code == WorkspaceExitCode.SUCCESS

    def test_the_mcp_coverage_for_the_project_names_the_converter(self, tmp_path):
        """An MCP client polling the project is told why it is incomplete."""
        from automated_security_helper.cli.mcp.workspace import _project_coverage
        from automated_security_helper.core.resource_management.scan_tracking import (
            coverage_has_gap,
        )

        plan = self._project(
            tmp_path,
            {"failed_inputs": [{"path": "nb.ipynb", "reason": "timed out"}]},
        )
        entry = _run(tmp_path, plan).payload.projects[0]

        coverage = _project_coverage(entry)

        assert coverage["incomplete_converters"] == [
            {"converter": "jupyter", "reason": "could not convert 1 input: nb.ipynb"}
        ]
        assert coverage_has_gap(coverage)


@pytest.mark.unit
class TestFailureHandling:
    def test_a_failing_project_does_not_stop_the_others(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("broken", "MEDIUM"), ("fine", "MEDIUM"))
        FakeOrchestrator.behaviour["broken"] = {
            "raise": RuntimeError("scanner blew up")
        }
        outcome = _run(tmp_path, plan)
        statuses = {p.project: p.status for p in outcome.payload.projects}
        assert statuses["broken"] is ProjectRunStatus.FAILED
        assert statuses["fine"] is ProjectRunStatus.COMPLETED

    def test_a_failing_project_makes_the_workspace_exit_non_zero(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("broken", "MEDIUM"), ("fine", "MEDIUM"))
        FakeOrchestrator.behaviour["broken"] = {"raise": RuntimeError("boom")}
        assert _run(tmp_path, plan).exit_code == WorkspaceExitCode.INTERNAL_ERROR

    def test_a_failing_project_outranks_another_project_s_findings(self, tmp_path):
        """1 ahead of 2, as in a single-directory scan, and the findings still shown.

        Reverses this test's earlier expectation (ACTIONABLE_FINDINGS), by design.
        The other project's findings do not decide the exit code any more, so the
        payload is where they must stay visible.
        """
        _, plan = _make_workspace(tmp_path, ("broken", "MEDIUM"), ("dirty", "LOW"))
        FakeOrchestrator.behaviour["broken"] = {"raise": RuntimeError("boom")}
        FakeOrchestrator.behaviour["dirty"] = {"sarif": _sarif(level="error", count=7)}

        outcome = _run(tmp_path, plan)

        assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR
        statuses = {p.project: p.status for p in outcome.payload.projects}
        assert statuses["broken"] is ProjectRunStatus.FAILED
        errors = {p.project: p.error for p in outcome.payload.projects}
        assert "boom" in (errors["broken"] or "")
        dirty = next(p for p in outcome.payload.projects if p.project == "dirty")
        assert dirty.exceeds_threshold is True
        assert dirty.finding_count == 7

    def test_the_failure_message_names_the_project(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("broken", "MEDIUM"))
        FakeOrchestrator.behaviour["broken"] = {
            "raise": RuntimeError("scanner blew up")
        }
        outcome = _run(tmp_path, plan)
        assert "scanner blew up" in (outcome.payload.projects[0].error or "")

    def test_an_invalid_project_config_selects_exit_three(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "raise": ASHConfigValidationError("threshold: not-a-threshold")
        }
        outcome = _run(tmp_path, plan)
        assert outcome.payload.projects[0].invalid_config is True
        assert outcome.exit_code == WorkspaceExitCode.INVALID_PROJECT_CONFIG

    def test_a_project_timeout_fails_that_project_only(self, tmp_path):
        """The other projects still complete, and the workspace still reports.

        The stalled project blocks on an event rather than sleeping past its budget, matching
        the tests further down this class. A sleep makes the overrun depend on two durations
        being ordered correctly -- sleep longer than budget, budget longer than startup -- and
        the second of those is not under the test's control. Blocking removes one side of it:
        a project waiting on an event that is never set overruns any budget, so only the
        sibling's completion depends on timing, and PROJECT_TIMEOUT gives that room.

        The event is released in a finally so the abandoned worker exits with the test rather
        than outliving it. It cannot be interrupted -- see the module docstring in
        workspace/execution.py for why a thread cannot be preempted -- so releasing it is the
        only way to reclaim it.
        """
        _, plan = _make_workspace(tmp_path, ("stalled", "MEDIUM"), ("quick", "MEDIUM"))
        release = threading.Event()
        FakeOrchestrator.behaviour["stalled"] = {"block": release}
        try:
            outcome = _run(
                tmp_path,
                plan,
                project_timeout=PROJECT_TIMEOUT,
                max_parallel_projects=2,
            )
        finally:
            release.set()

        statuses = {p.project: p.status for p in outcome.payload.projects}
        assert statuses["stalled"] is ProjectRunStatus.FAILED
        assert statuses["quick"] is ProjectRunStatus.COMPLETED, (
            "a project configured to do nothing must finish inside the budget; if it did not, "
            "the budget is smaller than the fixed cost of starting a project"
        )
        assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR

    def test_a_timeout_says_so_in_the_error(self, tmp_path):
        """The error names the budget, so the number is read from the constant.

        Asserting a hardcoded "0.2" here was what tied this test to the old value: changing the
        budget anywhere else would have failed this assertion for a reason unrelated to what it
        checks, which is that the message reports the deadline it enforced.
        """
        _, plan = _make_workspace(tmp_path, ("stalled", "MEDIUM"))
        release = threading.Event()
        FakeOrchestrator.behaviour["stalled"] = {"block": release}
        try:
            outcome = _run(tmp_path, plan, project_timeout=PROJECT_TIMEOUT)
        finally:
            release.set()

        error = outcome.payload.projects[0].error or ""
        assert "timed out" in error.lower()
        # The budget as every timeout message prints its limit: whole, in its
        # quoted token ('3' s), never the float's own "3.0s". Spelled here from
        # the constant, not by the code under test's limit_text, so a change in
        # how a limit prints fails this cell too.
        assert PROJECT_TIMEOUT.is_integer(), PROJECT_TIMEOUT
        assert f"'{int(PROJECT_TIMEOUT)}' s project_timeout" in error, error

    def test_the_timeout_bounds_wall_clock_when_the_bound_is_smaller(self, tmp_path):
        """The defect: a queued project was never given a deadline.

        The deadline check skipped any project with no start time, which is
        exactly a queued one. An abandoned worker keeps its slot, so at a bound
        smaller than the project count the queue could never drain and the loop
        waited on threads that were not coming back. Measured before the fix:
        three projects at bound 1 with a 1s budget ran past 12s. The shipped
        default bound is 4, so every workspace of five or more was exposed.

        The wedge here releases on an event rather than sleeping, so the test
        asserts the workspace returned while the worker was still running --
        which is the whole property -- without depending on a sleep duration.

        The bound allows for the one grace the pool gives every abandoned
        worker's stop after the loop (``_ABANDONED_STOP_GRACE_SECONDS``), paid
        on this path too so a worker that comes back inside it brings the
        secret values its findings exposed into the cross-project masking set.
        That wait is bounded and part of the contract; the open-ended wait on a
        held slot is the defect this test pins.
        """
        _, plan = _make_workspace(
            tmp_path,
            ("wedged", "MEDIUM"),
            ("queued-a", "MEDIUM"),
            ("queued-b", "MEDIUM"),
        )
        release = threading.Event()
        FakeOrchestrator.behaviour["wedged"] = {"block": release}
        try:
            started = time.monotonic()
            outcome = _run(
                tmp_path, plan, project_timeout=PROJECT_TIMEOUT, max_parallel_projects=1
            )
            elapsed = time.monotonic() - started
        finally:
            release.set()

        bound = PROJECT_TIMEOUT + _ABANDONED_STOP_GRACE_SECONDS + 2.0
        assert elapsed < bound, (
            f"took {elapsed:.1f}s; the project_timeout was {PROJECT_TIMEOUT}s plus "
            f"the {_ABANDONED_STOP_GRACE_SECONDS}s stop grace, bound {bound}s"
        )
        statuses = {p.project: p.status for p in outcome.payload.projects}
        assert statuses == {
            "wedged": ProjectRunStatus.FAILED,
            "queued-a": ProjectRunStatus.FAILED,
            "queued-b": ProjectRunStatus.FAILED,
        }
        assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR

    def test_a_never_started_project_says_why_and_how_to_fix_it(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"), ("queued", "MEDIUM"))
        release = threading.Event()
        FakeOrchestrator.behaviour["wedged"] = {"block": release}
        try:
            outcome = _run(
                tmp_path, plan, project_timeout=PROJECT_TIMEOUT, max_parallel_projects=1
            )
        finally:
            release.set()

        error = (
            next(p.error for p in outcome.payload.projects if p.project == "queued")
            or ""
        )
        assert "never started" in error
        assert "project_timeout" in error

    def test_every_project_timeout_text_prints_the_shared_limit_token(
        self, tmp_path, caplog, monkeypatch
    ):
        """The budget goes through error_text.timeout_limit_token, the one
        formatter every timeout message prints its limit with, so these texts
        cannot drift from the scanners': the start line, the abandoned
        project's ERROR line and reason, and the never-started project's ERROR
        line and reason all show the stand-in token."""
        import logging

        from automated_security_helper.utils import error_text
        from automated_security_helper.utils.log import ASH_LOGGER

        caplog.set_level(logging.INFO, logger=ASH_LOGGER.name)
        monkeypatch.setattr(
            error_text,
            "timeout_limit_token",
            lambda limit, values: "<the shared token>",
        )
        _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"), ("queued", "MEDIUM"))
        release = threading.Event()
        FakeOrchestrator.behaviour["wedged"] = {"block": release}
        try:
            outcome = _run(
                tmp_path, plan, project_timeout=PROJECT_TIMEOUT, max_parallel_projects=1
            )
        finally:
            release.set()

        errors = {p.project: p.error or "" for p in outcome.payload.projects}
        lines = caplog.text.splitlines()

        def line_with(words: str) -> str:
            return next((line for line in lines if words in line), "")

        for text in (
            line_with("workspace project(s)"),
            line_with("and was abandoned"),
            line_with("never started"),
            errors["wedged"],
            errors["queued"],
        ):
            assert "<the shared token>" in text, (text, caplog.text)

    def test_spare_capacity_still_drains_the_queue(self, tmp_path):
        """Only a fully-exhausted pool gives up; one lost slot of two does not."""
        _, plan = _make_workspace(
            tmp_path,
            ("wedged", "MEDIUM"),
            ("queued-a", "MEDIUM"),
            ("queued-b", "MEDIUM"),
        )
        release = threading.Event()
        FakeOrchestrator.behaviour["wedged"] = {"block": release}
        try:
            outcome = _run(
                tmp_path, plan, project_timeout=PROJECT_TIMEOUT, max_parallel_projects=2
            )
        finally:
            release.set()

        statuses = {p.project: p.status for p in outcome.payload.projects}
        assert statuses["wedged"] is ProjectRunStatus.FAILED
        assert statuses["queued-a"] is ProjectRunStatus.COMPLETED
        assert statuses["queued-b"] is ProjectRunStatus.COMPLETED

    def test_a_worker_back_from_an_abandoned_project_is_not_counted_lost(
        self, tmp_path
    ):
        """An abandoned project that ends on its own gives its worker back.

        Lost workers were a tally that only went up, so once a second project was
        abandoned the pool counted as exhausted although the first had finished
        and its worker was running the next project: what was still queued was
        failed as never started. Two workers and a 2s budget: ``slow`` overruns
        and ends at 2.5s, ``then`` runs on its worker from 2.5s to 4s, and
        ``wedged``, started at 1s, is abandoned at 3s with ``last`` still queued.
        """
        _, plan = _make_workspace(
            tmp_path,
            ("slow", "MEDIUM"),
            ("first", "MEDIUM"),
            ("wedged", "MEDIUM"),
            ("then", "MEDIUM"),
            ("last", "MEDIUM"),
        )
        release = threading.Event()
        FakeOrchestrator.behaviour["slow"] = {"sleep": 2.5}
        FakeOrchestrator.behaviour["first"] = {"sleep": 1.0}
        FakeOrchestrator.behaviour["wedged"] = {"block": release}
        FakeOrchestrator.behaviour["then"] = {"sleep": 1.5}
        try:
            outcome = _run(tmp_path, plan, project_timeout=2.0, max_parallel_projects=2)
        finally:
            release.set()

        errors = {p.project: p.error for p in outcome.payload.projects}
        statuses = {p.project: p.status for p in outcome.payload.projects}
        assert "never started" not in (errors["last"] or ""), errors
        assert statuses["last"] is ProjectRunStatus.COMPLETED, errors
        assert statuses["then"] is ProjectRunStatus.COMPLETED, errors
        assert statuses["slow"] is ProjectRunStatus.FAILED, errors
        assert statuses["wedged"] is ProjectRunStatus.FAILED, errors

    def test_an_abandoned_project_with_a_cancel_event_is_logged_as_stopped(
        self, tmp_path, caplog
    ):
        """A project the caller gave a cancel event is stopped, not left running.

        The abandonment was logged the same way with or without one: "Its worker
        cannot be interrupted and will run to completion in the background". With
        an event the project is cancelled at once and its worker comes back, so the
        log said the opposite of what happened.
        """
        from automated_security_helper.core.cancellation import CancelEvent

        _, plan = _make_workspace(tmp_path, ("slow", "MEDIUM"))
        FakeOrchestrator.behaviour["slow"] = {"sleep": 1.0}
        events = {"slow": CancelEvent()}

        execute_workspace(
            plan,
            _settings(tmp_path, project_timeout=0.3),
            orchestrator_factory=FakeOrchestrator.create,
            cancel_events=events,
        )

        assert events["slow"].is_set()
        assert "will run to completion in the background" not in caplog.text, (
            caplog.text
        )
        assert "is being stopped" in caplog.text, caplog.text

    def test_an_abandoned_project_without_one_is_stopped_but_not_waited_for(
        self, tmp_path, caplog
    ):
        """Without a caller event the pool builds one, so the abandon is a stop
        there too; what the log must still say is that the workspace result
        does not wait for that stop to finish."""
        _, plan = _make_workspace(tmp_path, ("slow", "MEDIUM"))
        FakeOrchestrator.behaviour["slow"] = {"sleep": 1.0}

        _run(tmp_path, plan, project_timeout=0.3)

        assert "will run to completion in the background" not in caplog.text, (
            caplog.text
        )
        assert "is being stopped" in caplog.text, caplog.text
        assert "does not wait for its stop to finish" in caplog.text, caplog.text

    def test_an_abandoned_project_does_not_write_a_results_file(self, tmp_path):
        """Otherwise its subtree contradicts the workspace verdict.

        The unified file records FAILED with finding_count=0 while
        projects/<key>/ash_aggregated_results.json holds real findings, and an
        operator can only resolve that by guessing which to trust.
        """
        _, plan = _make_workspace(tmp_path, ("wedged", "MEDIUM"))
        release = threading.Event()
        FakeOrchestrator.behaviour["wedged"] = {
            "block": release,
            "sarif": _sarif(level="error", count=3),
        }
        try:
            outcome = _run(tmp_path, plan, project_timeout=PROJECT_TIMEOUT)
            # Let the abandoned worker finish and attempt its write.
            release.set()
            time.sleep(0.4)
        finally:
            release.set()

        entry = outcome.payload.projects[0]
        assert entry.status is ProjectRunStatus.FAILED
        assert entry.finding_count == 0
        results = (
            tmp_path / "out" / "projects" / "wedged" / "ash_aggregated_results.json"
        )
        assert not results.exists(), (
            "the abandoned worker wrote per-project results that contradict the "
            "FAILED verdict already recorded for it"
        )

    def test_no_timeout_lets_a_slow_project_finish(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("slow", "MEDIUM"))
        FakeOrchestrator.behaviour["slow"] = {"sleep": 0.3}
        outcome = _run(tmp_path, plan, project_timeout=None)
        assert outcome.payload.projects[0].status is ProjectRunStatus.COMPLETED


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConcurrencyBound:
    def test_max_parallel_projects_is_honoured(self, tmp_path):
        """Counts concurrent occupancy rather than timing it.

        A timing-based assertion on a shared CI runner is a flake generator. This
        instruments the fake orchestrator to record peak concurrency directly, so
        the assertion is exact regardless of how loaded the host is.
        """
        keys = [(f"p{index}", "MEDIUM") for index in range(6)]
        _, plan = _make_workspace(tmp_path, *keys)
        for key, _ in keys:
            FakeOrchestrator.behaviour[key] = {"sleep": 0.15}

        in_flight = 0
        peak = 0
        lock = threading.Lock()
        original = FakeOrchestrator.execute_scan

        def counting_execute(self, phases=None):
            nonlocal in_flight, peak
            with lock:
                in_flight += 1
                peak = max(peak, in_flight)
            try:
                return original(self, phases=phases)
            finally:
                with lock:
                    in_flight -= 1

        FakeOrchestrator.execute_scan = counting_execute
        try:
            _run(tmp_path, plan, max_parallel_projects=2)
        finally:
            FakeOrchestrator.execute_scan = original
        assert peak <= 2
        assert peak >= 2, "the bound was never reached, so the test proved nothing"

    def test_a_bound_of_one_serialises(self, tmp_path):
        keys = [(f"p{index}", "MEDIUM") for index in range(3)]
        _, plan = _make_workspace(tmp_path, *keys)
        for key, _ in keys:
            FakeOrchestrator.behaviour[key] = {"sleep": 0.05}

        in_flight = 0
        peak = 0
        lock = threading.Lock()
        original = FakeOrchestrator.execute_scan

        def counting_execute(self, phases=None):
            nonlocal in_flight, peak
            with lock:
                in_flight += 1
                peak = max(peak, in_flight)
            try:
                return original(self, phases=phases)
            finally:
                with lock:
                    in_flight -= 1

        FakeOrchestrator.execute_scan = counting_execute
        try:
            _run(tmp_path, plan, max_parallel_projects=1)
        finally:
            FakeOrchestrator.execute_scan = original
        assert peak == 1

    def test_projects_are_reported_in_workspace_file_order(self, tmp_path):
        """Completion order is not reproducible; the operator's order is."""
        keys = [("zulu", "MEDIUM"), ("alpha", "MEDIUM"), ("mike", "MEDIUM")]
        _, plan = _make_workspace(tmp_path, *keys)
        FakeOrchestrator.behaviour["zulu"] = {"sleep": 0.15}
        outcome = _run(tmp_path, plan, max_parallel_projects=3)
        assert [p.project for p in outcome.payload.projects] == [
            "zulu",
            "alpha",
            "mike",
        ]


# ---------------------------------------------------------------------------
# Changed-files gate
# ---------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    """git for a fixture repository, reading none of the developer's own config.

    A global or system config, or the ignore file git reads by default from
    ``$XDG_CONFIG_HOME/git/ignore``, can list ``.ash/``, and ``git add`` of a
    fixture's ``.ash/ash_output`` then staged nothing. Each test's own home
    (tests/conftest.py) hides the developer's ``~/.gitconfig`` and default ignore
    file, but not a config ``GIT_CONFIG_GLOBAL`` names or the system config. Measured
    on the scan-set and committed-output modules, with ``GIT_CONFIG_GLOBAL`` naming a
    config whose ``core.excludesFile`` lists it: 85 tests failed, and one passed with
    nothing staged. ``GIT_CONFIG_GLOBAL`` and ``GIT_CONFIG_NOSYSTEM`` keep those
    configs out, and ``core.excludesFile`` given on the command line takes the place
    of the default ignore file. The fixture repository's own config and
    ``.gitignore`` still apply.
    """
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(  # nosec B603 B607 -- list args, no shell, fixture repo only
        ["git", "-c", f"core.excludesFile={os.devnull}", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        env=env,
    )


def _init_repo(path: Path, *, commit_extra: bool = False) -> None:
    """A throwaway repository with a base branch, and optionally a change on top."""
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "fixture@example.invalid")
    _git(path, "config", "user.name", "Fixture")
    _git(path, "add", ".")
    _git(path, "commit", "-q", "-m", "base")
    _git(path, "branch", "-f", "base-ref")
    if commit_extra:
        (path / "src" / "changed.py").write_text("print('changed')\n", encoding="utf-8")
        _git(path, "add", ".")
        _git(path, "commit", "-q", "-m", "change")


@pytest.fixture
def git_available() -> bool:
    return run_git("--version", timeout=30).returncode == 0


class TestChangedFilesGate:
    @pytest.mark.integration
    def test_a_project_with_no_changes_is_skipped_and_recorded(
        self, tmp_path, git_available
    ):
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("unchanged", "MEDIUM"))
        _init_repo(root / "unchanged", commit_extra=False)
        outcome = _run(tmp_path, plan, changed_files_only=True, base_ref="base-ref")
        entry = outcome.payload.projects[0]
        assert entry.status is ProjectRunStatus.SKIPPED
        assert entry.skip_reason is SkippedProjectReason.NO_CHANGES
        assert entry.skip_detail

    @pytest.mark.integration
    def test_a_no_changes_skip_is_in_the_payload_not_just_the_log(
        self, tmp_path, git_available
    ):
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("unchanged", "MEDIUM"))
        _init_repo(root / "unchanged", commit_extra=False)
        outcome = _run(tmp_path, plan, changed_files_only=True, base_ref="base-ref")
        payload = outcome.payload.skipped_projects
        assert [(e.project, e.reason.value) for e in payload] == [
            ("unchanged", "no-changes")
        ]

    @pytest.mark.integration
    def test_a_no_changes_skip_does_not_fail_the_workspace(
        self, tmp_path, git_available
    ):
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(
            tmp_path, ("unchanged", "MEDIUM"), ("changed", "MEDIUM")
        )
        _init_repo(root / "unchanged", commit_extra=False)
        _init_repo(root / "changed", commit_extra=True)
        outcome = _run(tmp_path, plan, changed_files_only=True, base_ref="base-ref")
        assert outcome.exit_code == WorkspaceExitCode.SUCCESS

    @pytest.mark.integration
    def test_a_workspace_where_every_project_is_unchanged_exits_zero(
        self, tmp_path, git_available
    ):
        """The diff-scoped no-op, end to end.

        In a monorepo the common case is an edit outside every project directory
        -- a README at the workspace root -- so every project skips no-changes.
        This used to exit 4, failing a clean run on a workspace where nothing
        needed scanning. Single-project mode exits 0 for exactly this.
        """
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        for key in ("api", "web"):
            _init_repo(root / key, commit_extra=False)
        # The edit that prompted the scan lands outside every project.
        (root / "README.md").write_text("docs only\n", encoding="utf-8")

        outcome = _run(tmp_path, plan, changed_files_only=True, base_ref="base-ref")

        assert outcome.exit_code == WorkspaceExitCode.SUCCESS
        assert all(
            p.status is ProjectRunStatus.SKIPPED for p in outcome.payload.projects
        )
        assert [e.reason.value for e in outcome.payload.skipped_projects] == [
            "no-changes",
            "no-changes",
        ]
        assert FakeOrchestrator.built == []

    @pytest.mark.integration
    def test_a_changed_project_is_scanned(self, tmp_path, git_available):
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("changed", "MEDIUM"))
        _init_repo(root / "changed", commit_extra=True)
        outcome = _run(tmp_path, plan, changed_files_only=True, base_ref="base-ref")
        assert outcome.payload.projects[0].status is ProjectRunStatus.COMPLETED
        assert [o.key for o in FakeOrchestrator.built] == ["changed"]

    @pytest.mark.integration
    def test_the_changed_set_is_handed_to_the_projects_engine(
        self, tmp_path, git_available
    ):
        """The project's own scan engine filters with it, before its reports.

        The executor does not filter the results it gets back from the project's
        orchestrator: by then that project's reports have been written from every
        finding, and only the workspace-level merge would see the narrowed set.
        """
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("changed", "MEDIUM"))
        _init_repo(root / "changed", commit_extra=True)

        _run(tmp_path, plan, changed_files_only=True, base_ref="base-ref")

        kwargs = FakeOrchestrator.built[0].kwargs
        assert kwargs["changed_files"] == {
            (root / "changed" / "src" / "changed.py").resolve()
        }
        assert kwargs["metadata"]["changed_files_only"] is True

    @pytest.mark.integration
    def test_without_the_flag_no_changed_set_is_handed_over(
        self, tmp_path, git_available
    ):
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("changed", "MEDIUM"))
        _init_repo(root / "changed", commit_extra=True)

        _run(tmp_path, plan)

        kwargs = FakeOrchestrator.built[0].kwargs
        assert kwargs["changed_files"] is None
        # Written on every run, False on a full scan (see run_ash_scan).
        assert kwargs["metadata"]["changed_files_only"] is False

    @pytest.mark.integration
    def test_each_project_is_evaluated_against_its_own_repository(
        self, tmp_path, git_available
    ):
        """Projects are independently versioned, so one diff cannot answer for both."""
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(
            tmp_path, ("changed", "MEDIUM"), ("still", "MEDIUM")
        )
        _init_repo(root / "changed", commit_extra=True)
        _init_repo(root / "still", commit_extra=False)
        outcome = _run(tmp_path, plan, changed_files_only=True, base_ref="base-ref")
        statuses = {p.project: p.status for p in outcome.payload.projects}
        assert statuses["changed"] is ProjectRunStatus.COMPLETED
        assert statuses["still"] is ProjectRunStatus.SKIPPED

    @pytest.mark.integration
    def test_precommit_alone_does_not_scope_the_scan_to_a_diff(
        self, tmp_path, git_available
    ):
        """``--mode precommit`` selects fast scanners; it does not select files.

        Single-project mode reads ``--changed-files-only`` alone for the diff
        gate, so arming it from the mode here meant the same invocation scanned
        a diff in one mode and the whole tree in the other. It was also diffing
        the wrong thing: ``<base_ref>...HEAD`` cannot see the staged content a
        pre-commit hook is called about, so an unchanged-since-base project was
        skipped however much was staged in it.
        """
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("unchanged", "MEDIUM"))
        _init_repo(root / "unchanged", commit_extra=False)
        outcome = _run(tmp_path, plan, precommit=True, base_ref="base-ref")
        assert outcome.payload.projects[0].status is ProjectRunStatus.COMPLETED
        assert [o.key for o in FakeOrchestrator.built] == ["unchanged"]

    @pytest.mark.unit
    def test_a_non_repository_under_precommit_is_not_an_error(self, tmp_path):
        """Inverted with the gate change above.

        This refusal existed because precommit armed the diff gate and a diff
        needs a repository. Precommit no longer scopes by diff, so a project that
        is not a repository is no longer a contradiction -- and refusing here
        would reject a whole workspace over a mode flag that now only picks
        scanners.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        outcome = _run(tmp_path, plan, precommit=True)
        assert outcome.payload.projects[0].status is ProjectRunStatus.COMPLETED

    @pytest.mark.unit
    def test_the_gate_is_off_without_changed_files_only(self, tmp_path):
        """A plain workspace scan must not care whether a project is a repository."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        outcome = _run(tmp_path, plan)
        assert outcome.payload.projects[0].status is ProjectRunStatus.COMPLETED

    @pytest.mark.integration
    def test_changed_files_only_applies_the_gate(self, tmp_path, git_available):
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("unchanged", "MEDIUM"))
        _init_repo(root / "unchanged", commit_extra=False)
        outcome = _run(tmp_path, plan, changed_files_only=True, base_ref="base-ref")
        assert outcome.payload.projects[0].status is ProjectRunStatus.SKIPPED

    @pytest.mark.integration
    def test_a_non_repository_under_changed_files_only_scans_fully(self, tmp_path):
        """--changed-files-only already documents a full-scan fallback; keep it."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        outcome = _run(tmp_path, plan, changed_files_only=True)
        assert outcome.payload.projects[0].status is ProjectRunStatus.COMPLETED

    @pytest.mark.integration
    def test_allow_missing_projects_does_not_change_the_non_repository_fallback(
        self, tmp_path
    ):
        """Carried over from when the fallback was conditional on this flag.

        The flag used to be what separated a refused workspace from a full scan,
        because the refusal only existed for precommit. With the refusal gone the
        downgrade is unconditional, and this pins that the flag neither restores a
        refusal nor changes the outcome.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        outcome = _run(
            tmp_path, plan, changed_files_only=True, allow_missing_projects=True
        )
        assert outcome.payload.projects[0].status is ProjectRunStatus.COMPLETED

    @pytest.mark.integration
    def test_an_option_like_base_ref_is_refused_before_any_project_runs(
        self, tmp_path, git_available
    ):
        """git would read "-p" as an option; the workspace is refused, not scanned.

        Before, git refused the option, so the diff had no answer and the project
        fell back to a full scan.
        """
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("changed", "MEDIUM"))
        _init_repo(root / "changed", commit_extra=True)

        with pytest.raises(ValueError, match=r"starts with '-'"):
            _run(tmp_path, plan, changed_files_only=True, base_ref="-p")

        assert FakeOrchestrator.built == []
        assert not (tmp_path / "out").exists()

    @pytest.mark.integration
    def test_a_missing_base_ref_scans_in_full_whatever_files_the_project_holds(
        self, tmp_path, git_available
    ):
        """A file named ``origin/main...HEAD`` does not stand in for the diff.

        The project has no ``origin``. Read as a path, the argument named that
        untracked file, the diff came back empty, and the project was skipped as
        unchanged. Read as a revision it does not exist, so the project is scanned.
        """
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        _init_repo(root / "api", commit_extra=True)
        (root / "api" / "origin").mkdir()
        (root / "api" / "origin" / "main...HEAD").write_text("x\n", encoding="utf-8")

        outcome = _run(tmp_path, plan, changed_files_only=True, base_ref="origin/main")

        assert outcome.payload.projects[0].status is ProjectRunStatus.COMPLETED
        assert [o.key for o in FakeOrchestrator.built] == ["api"]


# ---------------------------------------------------------------------------
# Output tree and payload
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestWorkspaceOutput:
    def test_the_unified_results_file_is_written(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        outcome = _run(tmp_path, plan)
        assert outcome.results_path == tmp_path / "out" / "ash_aggregated_results.json"
        assert outcome.results_path.exists()

    def test_the_unified_file_carries_one_run_per_project(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        for key in ("api", "web"):
            FakeOrchestrator.behaviour[key] = {"sarif": _sarif()}
        outcome = _run(tmp_path, plan)
        parsed = json.loads(outcome.results_path.read_text(encoding="utf-8"))
        assert len(parsed["sarif"]["runs"]) == 2

    def test_findings_are_attributed_to_the_project_that_produced_them(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(uri="src/api.py")}
        FakeOrchestrator.behaviour["web"] = {"sarif": _sarif(uri="src/web.py")}
        outcome = _run(tmp_path, plan)
        parsed = json.loads(outcome.results_path.read_text(encoding="utf-8"))
        seen = {}
        for run in parsed["sarif"]["runs"]:
            for result in run["results"]:
                seen[result["properties"]["workspace_uri"]] = result["properties"][
                    "workspace_project"
                ]
        assert seen == {"api/src/api.py": "api", "web/src/web.py": "web"}

    def test_the_payload_records_the_concurrency_settings_used(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        outcome = _run(tmp_path, plan, max_parallel_projects=3, project_timeout=42.0)
        assert outcome.payload.max_parallel_projects == 3
        assert outcome.payload.project_timeout == pytest.approx(42.0)

    def test_the_payload_records_wall_clock(self, tmp_path):
        """The field is populated with a real, non-negative measurement.

        Deliberately ``>= 0`` and not ``> 0``. ``wall_clock`` is
        ``time.monotonic() - started``, so a strict comparison asserts that the
        run outlasted the host's clock granularity rather than asserting
        anything about this code. On Windows that granularity is coarse enough
        that a fully-faked run can finish inside one tick, making the delta
        exactly ``0.0``; the strict form failed one CI row out of four while
        passing on every other platform and version. The exact value is pinned
        by the test below, against a clock this test controls.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        outcome = _run(tmp_path, plan)
        assert outcome.payload.wall_clock_seconds is not None
        assert outcome.payload.wall_clock_seconds >= 0

    def test_the_wall_clock_is_the_elapsed_time_not_a_constant(
        self, tmp_path, monkeypatch
    ):
        """Pin the arithmetic by driving the clock instead of racing it.

        WHY THIS IS NOT "first call is the start stamp"

        It was, and that form failed on one CI row with ``Obtained: 0.0,
        Expected: 42.5`` while passing on the other seventeen. The reason is that
        ``monkeypatch.setattr`` on ``time.monotonic`` replaces the attribute on
        the ``time`` MODULE, so the fake is process-global: thread-pool warmup,
        logging and executor internals consult it too, and how many calls they
        take before ``execute_workspace`` reaches its own ``started`` varies by
        platform. When one of them consumed the single 100.0, the workspace's
        start stamp became the same value as its end stamp and the difference
        was exactly zero.

        Note the old assertion ``calls[0] == 100.0`` still passed in that state,
        because it only proved SOMETHING read 100.0 first -- not that the
        workspace's own start stamp was that read. A control that cannot fail on
        the thing it is guarding is not a control.

        The fix is to stop patching the global clock at all. This module reads
        ``time.monotonic`` and nothing else from ``time`` -- nine call sites, no
        ``sleep``, no ``time()`` -- so replacing the module's own ``time``
        reference with a stand-in confines the fake to the code under test.
        Thread pools, logging and executors keep the real clock and cannot
        consume a read.

        That restores the premise the exact assertion needs: among this module's
        own calls, ``execute_workspace``'s ``started`` really is the first,
        because the per-project stamps are taken by workers it launches later.
        So the recorded wall clock must be exactly the difference, and a
        constant fails.

        A weaker form was tried first -- a strictly increasing clock, asserting
        only that the result was *some* difference of two observed reads. It was
        rejected on review: with reads one apart, every integer up to the call
        count is a valid difference, so a hardcoded constant passes as soon as
        enough reads happen. It survived a mutation check only by luck of how
        many calls that run made.

        The control records the CALLER, not the value. `calls[0] == 100.0` would be
        a tautology: the fake returns 100.0 exactly when `calls` is empty, so the
        first recorded value is 100.0 in every possible execution. Asserting it
        proves nothing, and giving it a message about the start stamp moving is
        worse than omitting it, because that message can never fire. Recording
        which function took each read is what makes "execute_workspace's stamp is
        the first one" falsifiable.

        WHAT THIS STILL DOES NOT CATCH, stated so nobody assumes otherwise

        Moving ``started`` LATER inside ``execute_workspace`` -- after the plugin
        prewarm, say, or after the changed-file gate loop -- leaves it the first
        read by this module and by this function, so the caller check passes and
        the difference is still exactly 42.5. Production would then under-report
        the wall clock by however long that skipped work took, which under
        ``--precommit`` is real seconds. This test pins "the field is a
        subtraction of the first module read from a later one"; it does not pin
        "the first read happens before all the work". A hardcoded 42.5 also
        passes, for the same reason any exact-value assertion does.
        WHY THE PATCH TARGETS THE NAME AND NOT THE ATTRIBUTE

        The stand-in replaces the ``time`` *name* in ``execution``'s namespace
        rather than the ``monotonic`` attribute on the module that name refers
        to. ``execution.time`` IS the stdlib ``time`` module, so patching
        ``execution.time.monotonic`` would mutate it process-wide and every
        unrelated caller of ``time.monotonic()`` would land in ``calls``. That
        defeats the control instead of tripping it: a foreign call consumes the
        ``100.0``, so ``execute_workspace`` reads ``142.5`` for both of its own
        stamps and records a difference of ``0.0``. The failure surfaces only
        once enough other tests have run to warm the plugin caches, which reads
        as flake rather than as an order-dependent patch. Keep the patch narrow:
        ``execution`` only ever uses ``time.monotonic``, so a stand-in exposing
        that one name is sufficient, and ``calls`` then records solely the reads
        made by the code under test.
        """
        calls: List[tuple[str, float]] = []

        def fake_monotonic() -> float:
            caller = sys._getframe(1).f_code.co_name
            value = 100.0 if not calls else 142.5
            calls.append((caller, value))
            return value

        monkeypatch.setattr(
            "automated_security_helper.workspace.execution.time",
            SimpleNamespace(monotonic=fake_monotonic),
        )
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        outcome = _run(tmp_path, plan)
        assert len(calls) >= 2, "the clock was consulted too few times to subtract"
        assert calls[0] == ("execute_workspace", 100.0), (
            "the module's first clock read was not execute_workspace's start stamp, "
            f"so the subtraction below is not the one under test: {calls!r}"
        )
        assert outcome.payload.wall_clock_seconds == pytest.approx(42.5)

    def test_the_payload_status_is_completed(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        assert _run(tmp_path, plan).payload.status == "completed"

    def test_the_workspace_root_is_recorded_not_a_project_path(self, tmp_path):
        root, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        outcome = _run(tmp_path, plan)
        assert Path(outcome.payload.workspace_root) == root


@pytest.mark.unit
class TestFolderNamedSrc:
    """A workspace containing a project literally named ``src``.

    In container mode the workspace root is mounted at ``/src``, so this project
    becomes ``/src/src`` -- the shape that re-enters the #361 basename heuristic.
    The path handling in ``sarif_utils`` is covered per project in
    ``tests/unit/interactions/test_workspace_container_mode.py``; what is checked
    here is that the workspace layer keeps such a project distinct from its
    siblings all the way through attribution and output.
    """

    def test_a_project_named_src_gets_its_own_subtree(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("src", "MEDIUM"), ("api", "MEDIUM"))
        _run(tmp_path, plan)
        for key in ("src", "api"):
            assert (tmp_path / "out" / "projects" / key).is_dir()

    def test_findings_in_src_are_attributed_to_src(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("src", "MEDIUM"), ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["src"] = {"sarif": _sarif(uri="app.py")}
        FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(uri="app.py")}
        outcome = _run(tmp_path, plan)
        parsed = json.loads(outcome.results_path.read_text(encoding="utf-8"))
        pairs = {
            (
                result["properties"]["workspace_project"],
                result["properties"]["workspace_uri"],
            )
            for run in parsed["sarif"]["runs"]
            for result in run["results"]
        }
        assert pairs == {("src", "src/app.py"), ("api", "api/app.py")}

    def test_the_two_projects_do_not_share_a_sarif_run(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("src", "MEDIUM"), ("api", "MEDIUM"))
        for key in ("src", "api"):
            FakeOrchestrator.behaviour[key] = {"sarif": _sarif()}
        outcome = _run(tmp_path, plan)
        parsed = json.loads(outcome.results_path.read_text(encoding="utf-8"))
        roots = {
            run["originalUriBaseIds"]["PROJECTROOT"]["uri"]
            for run in parsed["sarif"]["runs"]
        }
        assert len(roots) == 2


@pytest.mark.unit
class TestSettingsDefaults:
    def test_the_settings_object_is_immutable(self, tmp_path):
        """The same settings are read from several threads; mutation is a data race."""
        settings = _settings(tmp_path)
        with pytest.raises(Exception):
            settings.max_parallel_projects = 9  # type: ignore[misc]

    def test_sequence_fields_reject_a_bare_list(self, tmp_path):
        """Tuples, so a caller cannot hand shared mutable state to N threads."""
        settings = _settings(tmp_path, enabled_scanners=("bandit",))
        assert isinstance(settings.enabled_scanners, tuple)

    @staticmethod
    def _phases_of(settings: ProjectScanSettings) -> List[str]:
        return list(settings.phases)

    def test_phases_default_to_the_full_set(self, tmp_path):
        settings = ProjectScanSettings(output_dir=tmp_path / "out")
        assert self._phases_of(settings) == ["convert", "scan", "report"]


@pytest.mark.unit
class TestOptionalOrchestratorFactory:
    def test_the_real_orchestrator_is_the_default(self):
        """Injected only for tests; production must not have to pass one."""
        import inspect

        signature = inspect.signature(execute_workspace)
        assert signature.parameters["orchestrator_factory"].default is None


@pytest.mark.unit
class TestProjectThreadsKeepTheWorkspaceScope:
    def test_each_project_is_built_with_the_workspace_root_registered(self, tmp_path):
        """Project threads start with a copy of the run's context, which holds it."""
        from automated_security_helper.utils import subprocess_utils

        root, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        seen: List[List[str]] = []

        def factory(**kwargs: Any) -> "FakeOrchestrator":
            seen.append(subprocess_utils.scanned_trees())
            return FakeOrchestrator.create(**kwargs)

        with subprocess_utils.scanning_tree(root):
            execute_workspace(plan, _settings(tmp_path), orchestrator_factory=factory)

        assert seen == [[str(root.absolute())], [str(root.absolute())]]
