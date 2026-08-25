# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace-level report step, and the four behaviours it enforces.

What these tests are for
------------------------
``test_reporter_workspace_behaviour.py`` asserts that every reporter *declares*
something. This file asserts that the declaration *does* something -- that the
driver emits a merged artefact for MERGED, withholds one for PER_PROJECT while
recording where the per-project files are, emits a workspace-scoped artefact for
WORKSPACE_SCOPED, and refuses with a non-zero exit for UNSUPPORTED.

A declaration the driver ignored would be worse than no declaration at all: it
would read as a guarantee in every reporter docstring while the shipped behaviour
was whatever the code happened to do. So the two files are deliberately split,
and neither is sufficient alone.

Driven through the real ``WorkspaceAggregator``
----------------------------------------------
The unified results file these tests read is produced by the real aggregator, not
hand-written. Writing the N-run SARIF by hand would let a test pass against a
shape the aggregator does not actually produce -- and the shape is the entire
subject here, since it is the shape that broke ``runs[0]``.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
)
from automated_security_helper.workspace.aggregation import (
    PROJECT_ROOT_URI_BASE_ID,
    WorkspaceAggregator,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from automated_security_helper.workspace.reporting import (
    MANIFEST_FILENAME,
    REPORTS_DIR_NAME,
    emit_workspace_reports,
)

# --------------------------------------------------------------------------- #
# Fixtures: a real two-project workspace, aggregated the way production does.
# --------------------------------------------------------------------------- #


def _plan(root: Path, *keys: str) -> WorkspacePlan:
    return WorkspacePlan(
        workspace_file=(root / "fixture.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key=key,
                relative_path=key,
                path=(root / key).as_posix(),
                label=key,
                display_label=key,
                severity_threshold="MEDIUM",
            )
            for key in keys
        ],
    )


def _run(project_key: str, *, rule: str, uri: str) -> dict:
    """One project's SARIF run, shaped the way a real project scan emits it.

    Rule ids differ per project so a merged artefact that dropped a project can
    be caught by a positive assertion -- "RULE-WEB is present" -- rather than
    only by a count, which a duplicated first project would also satisfy.
    """
    return {
        "tool": {"driver": {"name": "ASH", "rules": [{"id": rule}]}},
        "results": [
            {
                "ruleId": rule,
                "level": "error",
                "message": {"text": f"finding in {project_key}"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": uri}}},
                ],
                "properties": {"scanner_name": "bandit"},
            }
        ],
        "invocations": [],
    }


def _outcome(project: ProjectPlan) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=project.key,
        relative_path=project.relative_path,
        display_label=project.display_label,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        finding_count=1,
        actionable_finding_count=1,
        exceeds_threshold=True,
        output_path=f"projects/{project.key}",
        scanners={"bandit": "FAILED"},
    )


@pytest.fixture
def workspace(tmp_path):
    """A written two-project workspace: output tree, unified results, and plan.

    Each project also gets a populated ``projects/<key>/reports/`` directory,
    because that is what a real per-project scan leaves behind and it is what the
    PER_PROJECT manifest entries have to find.
    """
    root = tmp_path / "ws"
    output_dir = tmp_path / "out"
    plan = _plan(root, "api", "web")

    aggregator = WorkspaceAggregator(plan=plan, output_dir=output_dir)
    for project, rule in zip(plan.projects, ("RULE-API", "RULE-WEB")):
        aggregator.add(
            _outcome(project),
            _run(project.key, rule=rule, uri=f"src/{project.key}.py"),
            project,
        )
    results_path = aggregator.write(exit_code=2, wall_clock_seconds=1.5)

    for project in plan.projects:
        reports = output_dir / "projects" / project.key / REPORTS_DIR_NAME
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "ash.ghas.sarif").write_text("{}", encoding="utf-8")
        (reports / "ash.cdx.json").write_text("{}", encoding="utf-8")

    return plan, output_dir, results_path


# --------------------------------------------------------------------------- #
# Test doubles: one reporter per behaviour, so the driver is what is under test.
# --------------------------------------------------------------------------- #


class _MergedConfig(ReporterPluginConfigBase):
    name: str = "fake-merged"
    extension: str = "merged.txt"
    enabled: bool = True


class FakeMergedReporter(ReporterPluginBase[_MergedConfig]):
    """Reports the rule id of every run it was given, one per line."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _MergedConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:
        rules = [
            result.ruleId
            for run in (model.sarif.runs or [])
            for result in (run.results or [])
        ]
        return "\n".join(rules)


class _PerProjectConfig(ReporterPluginConfigBase):
    name: str = "fake-per-project"
    extension: str = "ghas.sarif"
    enabled: bool = True


class FakePerProjectReporter(ReporterPluginBase[_PerProjectConfig]):
    """Stands in for ``github_ghas``: reads ``runs[0]`` and would drop the rest."""

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

    def model_post_init(self, context):
        if self.config is None:
            self.config = _PerProjectConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:  # pragma: no cover - must never be reached
        raise AssertionError(
            "a PER_PROJECT reporter was invoked at workspace level; that is the "
            "silent-under-report bug this contract exists to prevent"
        )


class _ScopedConfig(ReporterPluginConfigBase):
    name: str = "fake-workspace-scoped"
    extension: str = "scoped.json"
    enabled: bool = True


class FakeWorkspaceScopedReporter(ReporterPluginBase[_ScopedConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.WORKSPACE_SCOPED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _ScopedConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:
        return json.dumps({"scope": "workspace"})


class _UnsupportedConfig(ReporterPluginConfigBase):
    name: str = "fake-unsupported"
    extension: str = "unsupported.txt"
    enabled: bool = True


class FakeUnsupportedReporter(ReporterPluginBase[_UnsupportedConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.UNSUPPORTED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _UnsupportedConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("an UNSUPPORTED reporter must not be invoked")


class _RaisingConfig(ReporterPluginConfigBase):
    name: str = "fake-raising"
    extension: str = "raising.txt"
    enabled: bool = True


class FakeRaisingReporter(ReporterPluginBase[_RaisingConfig]):
    """A MERGED reporter that blows up, to pin that one failure is not fatal."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _RaisingConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:
        raise RuntimeError("fixture explosion")


class _DisabledConfig(ReporterPluginConfigBase):
    name: str = "fake-disabled"
    extension: str = "disabled.txt"
    enabled: bool = False


class FakeDisabledReporter(ReporterPluginBase[_DisabledConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _DisabledConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("a disabled reporter must not be invoked")


def _emit(workspace, *reporter_classes, **kwargs):
    plan, output_dir, results_path = workspace
    return emit_workspace_reports(
        plan=plan,
        output_dir=output_dir,
        results_path=results_path,
        reporter_classes=list(reporter_classes),
        **kwargs,
    )


def _manifest(output_dir: Path) -> dict:
    return json.loads(
        (output_dir / REPORTS_DIR_NAME / MANIFEST_FILENAME).read_text(encoding="utf-8")
    )


# --------------------------------------------------------------------------- #


class TestMergedReporters:
    def test_a_merged_reporter_writes_one_workspace_artefact(self, workspace):
        _, output_dir, _ = workspace
        outcome = _emit(workspace, FakeMergedReporter)

        artefact = output_dir / REPORTS_DIR_NAME / "ash.merged.txt"
        assert artefact.is_file()
        assert outcome.workspace_artifacts == {"fake-merged": artefact}

    def test_the_merged_artefact_covers_every_project(self, workspace):
        """The positive control for the whole feature.

        ``RULE-WEB`` comes only from the second run. A reporter that read
        ``runs[0]`` -- the shipped ``github_ghas`` behaviour -- produces a file
        containing ``RULE-API`` alone, and this is the assertion that catches it.
        Asserted by presence of both ids rather than by a line count, because a
        reporter that emitted the first project twice would satisfy a count.
        """
        _, output_dir, _ = workspace
        _emit(workspace, FakeMergedReporter)

        content = (output_dir / REPORTS_DIR_NAME / "ash.merged.txt").read_text(
            encoding="utf-8"
        )
        assert "RULE-API" in content
        assert "RULE-WEB" in content

    def test_a_reporter_that_raises_does_not_sink_the_others(self, workspace):
        """One broken reporter must not cost the operator every other report."""
        _, output_dir, _ = workspace
        outcome = _emit(workspace, FakeRaisingReporter, FakeMergedReporter)

        assert (output_dir / REPORTS_DIR_NAME / "ash.merged.txt").is_file()
        assert not (output_dir / REPORTS_DIR_NAME / "ash.raising.txt").exists()
        assert "fake-raising" in outcome.failed_reporters
        assert "fixture explosion" in outcome.failed_reporters["fake-raising"]

    def test_a_reporter_failure_is_recorded_in_the_manifest(self, workspace):
        _, output_dir, _ = workspace
        _emit(workspace, FakeRaisingReporter)

        entry = _manifest(output_dir)["reporters"]["fake-raising"]
        assert entry["workspace_artifact"] is None
        assert "fixture explosion" in entry["error"]

    def test_a_disabled_reporter_is_not_invoked(self, workspace):
        outcome = _emit(workspace, FakeDisabledReporter)
        assert outcome.workspace_artifacts == {}


class TestPerProjectReporters:
    def test_a_per_project_reporter_gets_no_workspace_artefact(self, workspace):
        """Withheld, not attempted.

        ``FakePerProjectReporter.report`` raises if called, so this asserts the
        driver never reaches it -- rather than asserting only that no file
        appeared, which a reporter returning an empty string would also satisfy.
        """
        _, output_dir, _ = workspace
        outcome = _emit(workspace, FakePerProjectReporter)

        assert outcome.workspace_artifacts == {}
        assert outcome.per_project_reporters == ("fake-per-project",)
        assert not (output_dir / REPORTS_DIR_NAME / "ash.ghas.sarif").exists()

    def test_the_manifest_names_every_per_project_artefact(self, workspace):
        """The absence of a merged file has to be stated, not merely true.

        Silence is the defect the whole contract is against, so a withheld
        workspace artefact must come with a machine-readable pointer to the N
        files that replace it.
        """
        _, output_dir, _ = workspace
        _emit(workspace, FakePerProjectReporter)

        entry = _manifest(output_dir)["reporters"]["fake-per-project"]
        assert entry["behaviour"] == "per-project"
        assert entry["workspace_artifact"] is None
        assert entry["per_project_artifacts"] == [
            {"project": "api", "path": "projects/api/reports/ash.ghas.sarif"},
            {"project": "web", "path": "projects/web/reports/ash.ghas.sarif"},
        ]

    def test_a_per_project_artefact_that_was_not_written_is_reported_missing(
        self, workspace, tmp_path
    ):
        """A path in the manifest that names nothing is worse than no path.

        The per-project report is written by that project's own report phase,
        which can be skipped, disabled, or have failed. The manifest says which
        of the N actually exist so an operator is never sent to a file that is
        not there.
        """
        _, output_dir, _ = workspace
        (output_dir / "projects" / "web" / REPORTS_DIR_NAME / "ash.ghas.sarif").unlink()

        _emit(workspace, FakePerProjectReporter)
        entry = _manifest(output_dir)["reporters"]["fake-per-project"]
        assert entry["missing_per_project_artifacts"] == ["web"]


class TestWorkspaceScopedReporters:
    def test_a_workspace_scoped_reporter_writes_a_workspace_artefact(self, workspace):
        _, output_dir, _ = workspace
        outcome = _emit(workspace, FakeWorkspaceScopedReporter)

        assert (output_dir / REPORTS_DIR_NAME / "ash.scoped.json").is_file()
        assert "fake-workspace-scoped" in outcome.workspace_artifacts

    def test_the_manifest_marks_it_as_not_a_merge(self, workspace):
        """A consumer must not read a workspace-scoped file as covering projects.

        ``unused_suppressions`` is the real case: read as a merge, its zero
        counts would mean "no unused suppressions anywhere", when what they mean
        is "no workspace-level suppressions". The behaviour string in the
        manifest is what keeps those apart.
        """
        _, output_dir, _ = workspace
        _emit(workspace, FakeWorkspaceScopedReporter)

        entry = _manifest(output_dir)["reporters"]["fake-workspace-scoped"]
        assert entry["behaviour"] == "workspace-scoped"
        assert entry["covers_projects"] is False

    def test_a_merged_reporter_is_marked_as_covering_projects(self, workspace):
        """The companion assertion, so ``covers_projects`` is not always False."""
        _, output_dir, _ = workspace
        _emit(workspace, FakeMergedReporter)

        entry = _manifest(output_dir)["reporters"]["fake-merged"]
        assert entry["covers_projects"] is True


class TestUnsupportedReportersAreRefusedBeforeAnythingIsScanned:
    """The production gate for acceptance criterion 23's non-zero exit.

    ``emit_workspace_reports`` records an ``UNSUPPORTED`` reporter in the
    manifest, but it is not what fails the run -- by the time it runs, the
    aggregator has already written the exit code *into* the results file, and a
    refusal discovered then could only be surfaced by exiting with a status the
    file does not contain. So the same declaration is checked before any project
    is scanned, where refusing costs nothing and nothing has been written that a
    process exit could contradict.
    """

    def test_the_detection_needs_no_scan_and_no_results_file(self, workspace, tmp_path):
        from automated_security_helper.workspace.reporting import (
            unsupported_reporter_names,
        )

        plan, _, _ = workspace
        # A directory with nothing in it: no results file, no projects subtree.
        assert unsupported_reporter_names(
            plan,
            tmp_path / "never-written",
            reporter_classes=[FakeUnsupportedReporter, FakeMergedReporter],
        ) == ("fake-unsupported",)

    def test_nothing_is_reported_when_every_reporter_can_participate(
        self, workspace, tmp_path
    ):
        """The companion assertion: the detector is not stuck returning a name."""
        from automated_security_helper.workspace.reporting import (
            unsupported_reporter_names,
        )

        plan, _, _ = workspace
        assert (
            unsupported_reporter_names(
                plan,
                tmp_path / "never-written",
                reporter_classes=[
                    FakeMergedReporter,
                    FakePerProjectReporter,
                    FakeWorkspaceScopedReporter,
                ],
            )
            == ()
        )

    def test_a_disabled_unsupported_reporter_does_not_refuse_the_run(
        self, workspace, tmp_path
    ):
        """Disabling it is the documented way out, so it has to actually work."""
        from automated_security_helper.workspace.reporting import (
            unsupported_reporter_names,
        )

        class _DisabledUnsupportedConfig(ReporterPluginConfigBase):
            name: str = "fake-unsupported-disabled"
            extension: str = "unsupported.txt"
            enabled: bool = False

        class FakeDisabledUnsupportedReporter(
            ReporterPluginBase[_DisabledUnsupportedConfig]
        ):
            workspace_behaviour = ReporterWorkspaceBehaviour.UNSUPPORTED

            def model_post_init(self, context):
                if self.config is None:
                    self.config = _DisabledUnsupportedConfig()
                return super().model_post_init(context)

            def report(self, model) -> str:  # pragma: no cover - never invoked
                raise AssertionError("must not be invoked")

        plan, _, _ = workspace
        assert (
            unsupported_reporter_names(
                plan,
                tmp_path / "never-written",
                reporter_classes=[FakeDisabledUnsupportedReporter],
            )
            == ()
        )

    def test_no_shipped_reporter_declares_itself_unsupported(self, workspace, tmp_path):
        """Recorded as a fact about the shipped set, not as an assumption.

        Every one of the 19 has a defensible merged or per-project answer, so this
        gate never fires in practice today. Asserting it means a future reporter
        that does declare ``UNSUPPORTED`` cannot slip in and start failing every
        workspace run without someone reading this test and deciding that is what
        they want.
        """
        from automated_security_helper.workspace.reporting import (
            unsupported_reporter_names,
        )
        from tests.unit.workspace.test_reporter_workspace_behaviour import (
            _iter_reporter_classes,
        )

        plan, _, _ = workspace
        assert (
            unsupported_reporter_names(
                plan,
                tmp_path / "never-written",
                reporter_classes=list(_iter_reporter_classes().values()),
            )
            == ()
        )


class TestUnsupportedReportersRefuseLoudly:
    def test_an_unsupported_reporter_is_refused_and_fails_the_run(self, workspace):
        """Acceptance criterion 23's deliberate non-zero exit.

        No reporter shipped in this repository declares UNSUPPORTED -- every one
        has a defensible merged or per-project answer -- so the mechanism is
        proven here with a test double rather than left to be discovered by the
        first external plugin that needs it. Building it untested would have made
        the enum member a comment.
        """
        outcome = _emit(workspace, FakeUnsupportedReporter)

        assert outcome.unsupported_reporters == ("fake-unsupported",)
        assert outcome.refused is True

    def test_the_refusal_names_the_reporter_in_the_manifest(self, workspace):
        _, output_dir, _ = workspace
        _emit(workspace, FakeUnsupportedReporter)

        entry = _manifest(output_dir)["reporters"]["fake-unsupported"]
        assert entry["behaviour"] == "unsupported"
        assert entry["workspace_artifact"] is None

    def test_a_run_with_no_unsupported_reporter_is_not_refused(self, workspace):
        """The companion assertion: ``refused`` is not stuck True."""
        outcome = _emit(workspace, FakeMergedReporter, FakePerProjectReporter)
        assert outcome.refused is False
        assert outcome.unsupported_reporters == ()


class TestTheOutputFormatFilter:
    def test_a_reporter_outside_the_requested_formats_is_skipped(self, workspace):
        outcome = _emit(
            workspace,
            FakeMergedReporter,
            FakeWorkspaceScopedReporter,
            output_formats=("scoped.json",),
        )
        assert set(outcome.workspace_artifacts) == {"fake-workspace-scoped"}

    def test_an_empty_format_filter_means_every_reporter(self, workspace):
        """Matches ``ReportPhase``: no ``--output-format`` is not "none"."""
        outcome = _emit(
            workspace,
            FakeMergedReporter,
            FakeWorkspaceScopedReporter,
            output_formats=(),
        )
        assert set(outcome.workspace_artifacts) == {
            "fake-merged",
            "fake-workspace-scoped",
        }


class TestTheManifestIsExhaustive:
    def test_every_reporter_appears_whatever_its_behaviour(self, workspace):
        """The property that makes the manifest trustworthy.

        An operator asking "where is my csv report" must get an answer for every
        reporter, including the ones that deliberately produced nothing. A
        manifest that listed only successes would leave the withheld ones
        indistinguishable from reporters that were never considered.
        """
        _, output_dir, _ = workspace
        _emit(
            workspace,
            FakeMergedReporter,
            FakePerProjectReporter,
            FakeWorkspaceScopedReporter,
            FakeUnsupportedReporter,
            FakeRaisingReporter,
        )

        assert set(_manifest(output_dir)["reporters"]) == {
            "fake-merged",
            "fake-per-project",
            "fake-workspace-scoped",
            "fake-unsupported",
            "fake-raising",
        }

    def test_the_manifest_records_the_workspace_root(self, workspace):
        plan, output_dir, _ = workspace
        _emit(workspace, FakeMergedReporter)
        assert _manifest(output_dir)["workspace_root"] == plan.workspace_root


class TestExecuteWorkspaceRunsTheReportStep:
    """The wiring, driven through the real ``execute_workspace``.

    Asserted end to end rather than by checking that a mock was called, because
    the two things most likely to be wrong are the *gate* (does it run when the
    operator asked for the report phase, and not otherwise) and the *ordering*
    (the manifest is written after the results file it describes). Neither is
    visible to a call assertion.
    """

    @staticmethod
    def _scanned_workspace(tmp_path):
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import SarifReport

        root = tmp_path / "ws"
        for key in ("api", "web"):
            (root / key / "src").mkdir(parents=True, exist_ok=True)
        (root / "fixture.code-workspace").write_text(
            json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
            encoding="utf-8",
        )
        plan = _plan(root, "api", "web")

        class _Orchestrator:
            def __init__(self, **kwargs):
                self.key = Path(kwargs["source_dir"]).name

            @classmethod
            def create(cls, **kwargs):
                return cls(**kwargs)

            def execute_scan(self, phases=None):
                model = AshAggregatedResults()
                model.sarif = SarifReport.model_validate(
                    {
                        "version": "2.1.0",
                        "runs": [
                            _run(
                                self.key,
                                rule=f"RULE-{self.key.upper()}",
                                uri=f"src/{self.key}.py",
                            )
                        ],
                    }
                )
                return model

        return plan, _Orchestrator

    def _execute(self, tmp_path, *, phases, reporter_classes=None):
        from automated_security_helper.workspace.execution import (
            ProjectScanSettings,
            execute_workspace,
        )

        plan, orchestrator = self._scanned_workspace(tmp_path)
        settings = ProjectScanSettings(
            output_dir=tmp_path / "out",
            phases=phases,
            max_parallel_projects=2,
        )
        result = execute_workspace(
            plan,
            settings,
            orchestrator_factory=orchestrator.create,
            reporter_classes=reporter_classes,
        )
        return plan, tmp_path / "out", result

    def test_the_report_step_runs_when_the_report_phase_was_requested(self, tmp_path):
        _, output_dir, result = self._execute(
            tmp_path,
            phases=("scan", "report"),
            reporter_classes=[FakeMergedReporter],
        )
        assert (output_dir / REPORTS_DIR_NAME / MANIFEST_FILENAME).is_file()
        assert result.report_outcome is not None
        assert "fake-merged" in result.report_outcome.workspace_artifacts

    def test_the_report_step_is_skipped_when_the_phase_was_not_requested(
        self, tmp_path
    ):
        """``--phases scan`` must not produce reports, at workspace level either.

        The companion assertion to the test above: without it, a gate that was
        wired backwards -- or not wired at all -- would still pass the positive
        case.
        """
        _, output_dir, result = self._execute(
            tmp_path, phases=("scan",), reporter_classes=[FakeMergedReporter]
        )
        assert not (output_dir / REPORTS_DIR_NAME / MANIFEST_FILENAME).exists()
        assert result.report_outcome is None

    def test_the_merged_artefact_covers_both_projects_end_to_end(self, tmp_path):
        _, output_dir, _ = self._execute(
            tmp_path,
            phases=("scan", "report"),
            reporter_classes=[FakeMergedReporter],
        )
        content = (output_dir / REPORTS_DIR_NAME / "ash.merged.txt").read_text(
            encoding="utf-8"
        )
        assert "RULE-API" in content
        assert "RULE-WEB" in content

    def test_an_unsupported_reporter_refuses_before_any_project_is_scanned(
        self, tmp_path
    ):
        """Refused up front, so no results file exists to contradict the exit.

        The absence of ``ash_aggregated_results.json`` is the load-bearing
        assertion, not the exception type. If the refusal happened after the scan,
        that file would exist carrying ``exit_code`` 0 or 2 while the process
        exited non-zero for a reason the file does not mention.
        """
        from automated_security_helper.core.exceptions import WorkspaceDefinitionError

        with pytest.raises(WorkspaceDefinitionError) as caught:
            self._execute(
                tmp_path,
                phases=("scan", "report"),
                reporter_classes=[FakeUnsupportedReporter],
            )

        assert "fake-unsupported" in str(caught.value)
        assert not (tmp_path / "out" / "ash_aggregated_results.json").exists()
        assert not (tmp_path / "out" / "projects").exists()

    def test_an_unsupported_reporter_does_not_refuse_without_the_report_phase(
        self, tmp_path
    ):
        """The gate is the same one, so a scan-only run is unaffected.

        An operator running ``--phases scan`` has not asked for a report, so a
        reporter that cannot produce one is not their problem yet.
        """
        _, _, result = self._execute(
            tmp_path, phases=("scan",), reporter_classes=[FakeUnsupportedReporter]
        )
        assert result.exit_code == 2  # the fixture findings, not a refusal


class TestSarifStaysOneRunPerProject:
    """Acceptance criterion 24, asserted on the file a reporter actually wrote.

    Phase 2a asserted this on the aggregator's output. It is re-asserted here on
    the ``sarif`` reporter's output because that is a different artefact: the
    reporter dumps ``model.sarif``, and ``SarifReport.merge_sarif_report`` -- a
    method on that very object -- collapses every run into ``runs[0]``. Nothing
    but a test stops a future change from calling it on the way out.
    """

    def test_the_sarif_report_carries_one_run_per_project(self, workspace):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
            SarifReporter,
        )

        _, output_dir, _ = workspace
        _emit(workspace, SarifReporter)

        document = json.loads(
            (output_dir / REPORTS_DIR_NAME / "ash.sarif").read_text(encoding="utf-8")
        )
        assert len(document["runs"]) == 2

    def test_each_run_declares_its_own_project_root(self, workspace):
        plan, output_dir, _ = workspace
        from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
            SarifReporter,
        )

        _emit(workspace, SarifReporter)
        document = json.loads(
            (output_dir / REPORTS_DIR_NAME / "ash.sarif").read_text(encoding="utf-8")
        )

        roots = [
            run["originalUriBaseIds"][PROJECT_ROOT_URI_BASE_ID]["uri"]
            for run in document["runs"]
        ]
        assert len(set(roots)) == 2
        for project, root in zip(plan.projects, roots):
            assert root.endswith(f"/{project.key}/")

    def test_one_project_is_extractable_by_selecting_its_run(self, workspace):
        """The other half of criterion 24.

        ``workspace.projects[i].sarif_run_index`` names the run, and taking that
        run whole must yield a document valid for one project on its own -- which
        is what makes a per-project ``github_ghas`` artefact derivable from the
        merged SARIF rather than only from the per-project subtree.
        """
        _, output_dir, results_path = workspace
        from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
            SarifReporter,
        )

        _emit(workspace, SarifReporter)
        document = json.loads(
            (output_dir / REPORTS_DIR_NAME / "ash.sarif").read_text(encoding="utf-8")
        )
        unified = json.loads(results_path.read_text(encoding="utf-8"))

        for entry in unified["workspace"]["projects"]:
            selected = document["runs"][entry["sarif_run_index"]]
            assert list(selected["originalUriBaseIds"]) == [PROJECT_ROOT_URI_BASE_ID]
            for result in selected["results"]:
                assert result["properties"]["workspace_project"] == entry["project"]
                for location in result["locations"]:
                    artifact = location["physicalLocation"]["artifactLocation"]
                    assert not artifact["uri"].startswith("/")
                    assert artifact["uriBaseId"] == PROJECT_ROOT_URI_BASE_ID
