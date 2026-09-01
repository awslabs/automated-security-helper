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
import subprocess  # nosec B404 -- builds throwaway git repositories for the changed-files gate
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    WorkspaceDefinitionError,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceExitCode,
)
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan


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
        from automated_security_helper.models.asharp_model import AshAggregatedResults
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
        model.sarif = SarifReport.model_validate(spec.get("sarif") or _sarif(count=0))
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
# Failures and timeouts
# ---------------------------------------------------------------------------


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

    def test_a_failing_project_does_not_mask_another_project_findings(self, tmp_path):
        """A gate that retries 1 as infrastructure trouble would never block.

        The failed project stays disclosed in the payload; what changes is that it
        no longer decides the exit code when a real finding is present.
        """
        _, plan = _make_workspace(tmp_path, ("broken", "MEDIUM"), ("dirty", "LOW"))
        FakeOrchestrator.behaviour["broken"] = {"raise": RuntimeError("boom")}
        FakeOrchestrator.behaviour["dirty"] = {"sarif": _sarif(level="error", count=7)}

        outcome = _run(tmp_path, plan)

        assert outcome.exit_code == WorkspaceExitCode.ACTIONABLE_FINDINGS
        statuses = {p.project: p.status for p in outcome.payload.projects}
        assert statuses["broken"] is ProjectRunStatus.FAILED
        errors = {p.project: p.error for p in outcome.payload.projects}
        assert "boom" in (errors["broken"] or "")

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

        The slow project sleeps only slightly longer than its budget, so the
        abandoned worker finishes during the test rather than outliving it. That
        is a property of the test, not of the timeout: see the module docstring in
        workspace/execution.py for why a thread cannot be preempted.
        """
        _, plan = _make_workspace(tmp_path, ("slow", "MEDIUM"), ("quick", "MEDIUM"))
        FakeOrchestrator.behaviour["slow"] = {"sleep": 1.5}
        outcome = _run(tmp_path, plan, project_timeout=0.2, max_parallel_projects=2)
        statuses = {p.project: p.status for p in outcome.payload.projects}
        assert statuses["slow"] is ProjectRunStatus.FAILED
        assert statuses["quick"] is ProjectRunStatus.COMPLETED
        assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR

    def test_a_timeout_says_so_in_the_error(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("slow", "MEDIUM"))
        FakeOrchestrator.behaviour["slow"] = {"sleep": 1.5}
        outcome = _run(tmp_path, plan, project_timeout=0.2)
        error = outcome.payload.projects[0].error or ""
        assert "timed out" in error.lower()
        assert "0.2" in error

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
            outcome = _run(tmp_path, plan, project_timeout=0.2, max_parallel_projects=1)
            elapsed = time.monotonic() - started
        finally:
            release.set()

        assert elapsed < 5.0, f"took {elapsed:.1f}s; the budget was 0.2s"
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
            outcome = _run(tmp_path, plan, project_timeout=0.2, max_parallel_projects=1)
        finally:
            release.set()

        error = (
            next(p.error for p in outcome.payload.projects if p.project == "queued")
            or ""
        )
        assert "never started" in error
        assert "project_timeout" in error

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
            outcome = _run(tmp_path, plan, project_timeout=0.2, max_parallel_projects=2)
        finally:
            release.set()

        statuses = {p.project: p.status for p in outcome.payload.projects}
        assert statuses["wedged"] is ProjectRunStatus.FAILED
        assert statuses["queued-a"] is ProjectRunStatus.COMPLETED
        assert statuses["queued-b"] is ProjectRunStatus.COMPLETED

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
            outcome = _run(tmp_path, plan, project_timeout=0.2)
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
    return subprocess.run(  # nosec B603 B607 -- list args, no shell, fixture repo only
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
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
    probe = subprocess.run(  # nosec B603 B607 -- probing for git on PATH
        ["git", "--version"], capture_output=True, text=True, check=False, timeout=30
    )
    return probe.returncode == 0


class TestChangedFilesGate:
    def test_a_project_with_no_changes_is_skipped_and_recorded(
        self, tmp_path, git_available
    ):
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("unchanged", "MEDIUM"))
        _init_repo(root / "unchanged", commit_extra=False)
        outcome = _run(tmp_path, plan, precommit=True, base_ref="base-ref")
        entry = outcome.payload.projects[0]
        assert entry.status is ProjectRunStatus.SKIPPED
        assert entry.skip_reason is SkippedProjectReason.NO_CHANGES
        assert entry.skip_detail

    def test_a_no_changes_skip_is_in_the_payload_not_just_the_log(
        self, tmp_path, git_available
    ):
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("unchanged", "MEDIUM"))
        _init_repo(root / "unchanged", commit_extra=False)
        outcome = _run(tmp_path, plan, precommit=True, base_ref="base-ref")
        payload = outcome.payload.skipped_projects
        assert [(e.project, e.reason.value) for e in payload] == [
            ("unchanged", "no-changes")
        ]

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
        outcome = _run(tmp_path, plan, precommit=True, base_ref="base-ref")
        assert outcome.exit_code == WorkspaceExitCode.SUCCESS

    def test_a_workspace_where_every_project_is_unchanged_exits_zero(
        self, tmp_path, git_available
    ):
        """The precommit no-op, end to end.

        In a monorepo the common case is an edit outside every project directory
        -- a README at the workspace root -- so every project skips no-changes.
        This used to exit 4, failing a clean hook run on a workspace where
        nothing needed scanning. Single-project mode exits 0 for exactly this.
        """
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
        for key in ("api", "web"):
            _init_repo(root / key, commit_extra=False)
        # The edit that triggered the hook lands outside every project.
        (root / "README.md").write_text("docs only\n", encoding="utf-8")

        outcome = _run(tmp_path, plan, precommit=True, base_ref="base-ref")

        assert outcome.exit_code == WorkspaceExitCode.SUCCESS
        assert all(
            p.status is ProjectRunStatus.SKIPPED for p in outcome.payload.projects
        )
        assert [e.reason.value for e in outcome.payload.skipped_projects] == [
            "no-changes",
            "no-changes",
        ]
        assert FakeOrchestrator.built == []

    def test_a_changed_project_is_scanned(self, tmp_path, git_available):
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("changed", "MEDIUM"))
        _init_repo(root / "changed", commit_extra=True)
        outcome = _run(tmp_path, plan, precommit=True, base_ref="base-ref")
        assert outcome.payload.projects[0].status is ProjectRunStatus.COMPLETED
        assert [o.key for o in FakeOrchestrator.built] == ["changed"]

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
        outcome = _run(tmp_path, plan, precommit=True, base_ref="base-ref")
        statuses = {p.project: p.status for p in outcome.payload.projects}
        assert statuses["changed"] is ProjectRunStatus.COMPLETED
        assert statuses["still"] is ProjectRunStatus.SKIPPED

    def test_a_non_repository_under_precommit_is_a_workspace_error(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            _run(tmp_path, plan, precommit=True)
        assert "api" in str(excinfo.value)

    def test_allow_missing_projects_downgrades_a_non_repository_to_a_full_scan(
        self, tmp_path
    ):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        outcome = _run(tmp_path, plan, precommit=True, allow_missing_projects=True)
        assert outcome.payload.projects[0].status is ProjectRunStatus.COMPLETED

    def test_the_gate_is_off_without_precommit_or_changed_files_only(self, tmp_path):
        """A plain workspace scan must not care whether a project is a repository."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        outcome = _run(tmp_path, plan)
        assert outcome.payload.projects[0].status is ProjectRunStatus.COMPLETED

    def test_changed_files_only_applies_the_same_gate(self, tmp_path, git_available):
        if not git_available:
            pytest.skip("git is not available on PATH")
        root, plan = _make_workspace(tmp_path, ("unchanged", "MEDIUM"))
        _init_repo(root / "unchanged", commit_extra=False)
        outcome = _run(tmp_path, plan, changed_files_only=True, base_ref="base-ref")
        assert outcome.payload.projects[0].status is ProjectRunStatus.SKIPPED

    def test_a_non_repository_under_changed_files_only_scans_fully(self, tmp_path):
        """--changed-files-only already documents a full-scan fallback; keep it."""
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        outcome = _run(tmp_path, plan, changed_files_only=True)
        assert outcome.payload.projects[0].status is ProjectRunStatus.COMPLETED


# ---------------------------------------------------------------------------
# Output tree and payload
# ---------------------------------------------------------------------------


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


class TestOptionalOrchestratorFactory:
    def test_the_real_orchestrator_is_the_default(self):
        """Injected only for tests; production must not have to pass one."""
        import inspect

        signature = inspect.signature(execute_workspace)
        assert signature.parameters["orchestrator_factory"].default is None
