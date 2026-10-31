# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The manifest accounts for every reporter, under every failure the base lost.

Each test plants one shape the step mishandled: a reporter that cannot be
constructed (absent from the manifest and from ``failed_reporters``), one whose
``is_python_only`` raises (took the step down), a disabled reporter the formats
excluded (listed as considered with an earlier run's files), a merged reporter
that raised (kept ``covers_projects: true``), two reporters with one name (one
record lost), a disabled merged reporter whose projects wrote artefacts (recorded
as disabled with none), a results file that cannot be loaded (no manifest at
all), an error carrying an environment value (written raw), a link that appeared
at a report's name after the pre-write check (earlier reports written, no
manifest), and a cancel during the step (every reporter ran).
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
)
from automated_security_helper.utils.error_text import carry_environment_values
from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused
from automated_security_helper.workspace import reporting
from automated_security_helper.workspace.aggregation import WorkspaceAggregator
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from automated_security_helper.workspace.reporting import (
    MANIFEST_FILENAME,
    REPORTS_DIR_NAME,
    SKIP_DISABLED,
    SKIP_NOT_PYTHON_ONLY,
    SKIP_NOT_REQUESTED,
    emit_workspace_reports,
)

pytestmark = pytest.mark.unit

CANARY = "env-canary-value-q7k2"


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
        (reports / "ash.cdx.json").write_text("{}", encoding="utf-8")
    return plan, output_dir, results_path


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
# Test doubles
# --------------------------------------------------------------------------- #


class _MergedConfig(ReporterPluginConfigBase):
    name: str = "fake-merged"
    extension: str = "merged.txt"
    enabled: bool = True


class FakeMergedReporter(ReporterPluginBase[_MergedConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _MergedConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:
        return "\n".join(
            result.ruleId
            for run in (model.sarif.runs or [])
            for result in (run.results or [])
        )


class _UnconstructibleConfig(ReporterPluginConfigBase):
    name: str = "fake-unconstructible"
    extension: str = "unconstructible.txt"
    enabled: bool = True


class FakeUnconstructibleReporter(ReporterPluginBase[_UnconstructibleConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        raise RuntimeError("cannot be built")

    def report(self, model) -> str:  # pragma: no cover - never constructed
        raise AssertionError("never constructed")


class _UnconstructibleOffConfig(ReporterPluginConfigBase):
    name: str = "fake-unconstructible-off"
    extension: str = "unconstructible-off.txt"
    enabled: bool = False


class FakeUnconstructibleOffReporter(ReporterPluginBase[_UnconstructibleOffConfig]):
    """Off in its config, and raises in its constructor: the shape of a disabled
    AWS reporter whose ``__init__`` reaches for credentials."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        raise RuntimeError("cannot be built either")

    def report(self, model) -> str:  # pragma: no cover - never constructed
        raise AssertionError("never constructed")


class _OffHostConfig(ReporterPluginConfigBase):
    name: str = "fake-off-host"
    extension: str = "offhost.txt"
    enabled: bool = True


class FakeOffHostReporter(ReporterPluginBase[_OffHostConfig]):
    """Sends findings off the host and ships enabled, with no section in the
    default config (a plugin's reporter): it runs only if an operator's section
    says ``enabled: true``, so the step never writes its report."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED
    sends_off_host = True

    def model_post_init(self, context):
        if self.config is None:
            self.config = _OffHostConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:  # pragma: no cover - refused as off-host
        raise AssertionError("an off-host reporter that is not enabled ran")


class _OffHostUnbuildableConfig(ReporterPluginConfigBase):
    name: str = "fake-off-host-unbuildable"
    extension: str = "offhost-unbuildable.txt"
    enabled: bool = True


class FakeOffHostUnbuildableReporter(ReporterPluginBase[_OffHostUnbuildableConfig]):
    """The same off-host reporter, whose constructor raises."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED
    sends_off_host = True

    def model_post_init(self, context):
        raise RuntimeError("cannot be built either way")

    def report(self, model) -> str:  # pragma: no cover - never constructed
        raise AssertionError("never constructed")


class _NotPythonOnlyConfig(ReporterPluginConfigBase):
    name: str = "fake-python-only-raises"
    extension: str = "pyonly.txt"
    enabled: bool = True


class FakePythonOnlyRaisesReporter(ReporterPluginBase[_NotPythonOnlyConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _NotPythonOnlyConfig()
        return super().model_post_init(context)

    def is_python_only(self) -> bool:
        raise RuntimeError("cannot say")

    def report(self, model) -> str:  # pragma: no cover - excluded before it runs
        return "unreachable"


class _DefaultOffPerProjectConfig(ReporterPluginConfigBase):
    name: str = "fake-default-off-per-project"
    extension: str = "cdx.json"
    enabled: bool = False


class FakeDefaultOffPerProjectReporter(ReporterPluginBase[_DefaultOffPerProjectConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

    def model_post_init(self, context):
        if self.config is None:
            self.config = _DefaultOffPerProjectConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:  # pragma: no cover - never invoked
        raise AssertionError("a PER_PROJECT reporter was invoked at workspace level")


class _DefaultOffMergedConfig(ReporterPluginConfigBase):
    name: str = "fake-default-off-merged"
    extension: str = "cdx.json"
    enabled: bool = False


class FakeDefaultOffMergedReporter(ReporterPluginBase[_DefaultOffMergedConfig]):
    """A merged reporter the default config leaves off; projects enabled it."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _DefaultOffMergedConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:  # pragma: no cover - disabled here
        raise AssertionError("a disabled reporter must not be invoked")


class _RaisingConfig(ReporterPluginConfigBase):
    name: str = "fake-raising"
    extension: str = "raising.txt"
    enabled: bool = True


class FakeRaisingReporter(ReporterPluginBase[_RaisingConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _RaisingConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:
        error = RuntimeError(f"token {CANARY} leaked")
        carry_environment_values(error, (CANARY,))
        raise error


class _TwinAConfig(ReporterPluginConfigBase):
    name: str = "fake-twin"
    extension: str = "twin-a.txt"
    enabled: bool = True


class _TwinBConfig(ReporterPluginConfigBase):
    name: str = "fake-twin"
    extension: str = "twin-b.txt"
    enabled: bool = True


class FakeTwinA(ReporterPluginBase[_TwinAConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _TwinAConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:
        return "a"


class FakeTwinB(ReporterPluginBase[_TwinBConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _TwinBConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:
        return "b"


# --------------------------------------------------------------------------- #


class TestEveryReporterIsAccountedFor:
    def test_a_reporter_that_cannot_be_constructed_is_recorded_and_fails(
        self, workspace
    ):
        _, output_dir, _ = workspace
        outcome = _emit(workspace, FakeUnconstructibleReporter, FakeMergedReporter)

        entry = _manifest(output_dir)["reporters"]["fake-unconstructible"]
        assert entry["considered"] is False
        assert "could not be constructed" in entry["error"]
        assert "cannot be built" in entry["error"]
        assert "fake-unconstructible" in outcome.failed_reporters
        assert "fake-merged" in outcome.workspace_artifacts

    def test_a_reporter_whose_python_only_check_raises_is_excluded_not_fatal(
        self, workspace
    ):
        _, output_dir, _ = workspace
        outcome = _emit(
            workspace, FakePythonOnlyRaisesReporter, python_based_plugins_only=True
        )

        entry = _manifest(output_dir)["reporters"]["fake-python-only-raises"]
        assert entry["skipped"] == SKIP_NOT_PYTHON_ONLY
        assert outcome.failed_reporters == {}

    def test_a_disabled_reporter_the_formats_excluded_is_not_considered(
        self, workspace
    ):
        """The exclusion applied to every project's report phase too, so the
        per-project file on disk is an earlier run's, not this run's."""
        _, output_dir, _ = workspace
        outcome = _emit(
            workspace,
            FakeMergedReporter,
            FakeDefaultOffPerProjectReporter,
            output_formats=("fake-merged",),
        )

        entry = _manifest(output_dir)["reporters"]["fake-default-off-per-project"]
        assert entry["skipped"] == SKIP_NOT_REQUESTED
        assert entry["considered"] is False
        assert entry["per_project_artifacts"] == []
        assert outcome.per_project_reporters == ()

    def test_a_disabled_merged_reporter_lists_what_its_projects_wrote(self, workspace):
        _, output_dir, _ = workspace
        _emit(workspace, FakeDefaultOffMergedReporter)

        entry = _manifest(output_dir)["reporters"]["fake-default-off-merged"]
        assert "skipped" not in entry
        assert entry["covers_projects"] is False
        assert entry["per_project_artifacts"] == [
            {"project": "api", "path": "projects/api/reports/ash.cdx.json"},
            {"project": "web", "path": "projects/web/reports/ash.cdx.json"},
        ]

    def test_two_reporters_with_one_name_keep_two_records(self, workspace):
        _, output_dir, _ = workspace
        outcome = _emit(workspace, FakeTwinA, FakeTwinB)

        reporters = _manifest(output_dir)["reporters"]
        assert "fake-twin" in reporters
        assert "fake-twin (FakeTwinB)" in reporters
        assert set(outcome.workspace_artifacts) == {
            "fake-twin",
            "fake-twin (FakeTwinB)",
        }
        assert (output_dir / REPORTS_DIR_NAME / "ash.twin-a.txt").is_file()
        assert (output_dir / REPORTS_DIR_NAME / "ash.twin-b.txt").is_file()


class TestAnUnbuildableReporterFailsOnlyWhatItOwed:
    """A construction failure fails the step only for a reporter the step would
    have run. A disabled or unrequested one is recorded with its skip reason, as
    a built one would be: before this, a disabled reporter raising in its
    constructor turned a run with ``--output-format sarif`` into exit 1 after
    every project was scanned, where a single-directory scan of the same project
    passed."""

    def test_a_disabled_reporter_that_cannot_be_built_does_not_fail_the_run(
        self, workspace
    ):
        _, output_dir, _ = workspace
        outcome = _emit(workspace, FakeUnconstructibleOffReporter, FakeMergedReporter)

        entry = _manifest(output_dir)["reporters"]["fake-unconstructible-off"]
        assert "could not be constructed" in entry["error"]
        assert entry["skipped"] == SKIP_DISABLED
        assert entry["considered"] is False
        assert "fake-unconstructible-off" not in outcome.failed_reporters
        assert outcome.failed is False
        assert "fake-merged" in outcome.workspace_artifacts

    def test_an_unrequested_reporter_that_cannot_be_built_does_not_fail_the_run(
        self, workspace
    ):
        _, output_dir, _ = workspace
        outcome = _emit(
            workspace,
            FakeUnconstructibleReporter,
            FakeMergedReporter,
            output_formats=("fake-merged",),
        )

        entry = _manifest(output_dir)["reporters"]["fake-unconstructible"]
        assert "could not be constructed" in entry["error"]
        assert entry["skipped"] == SKIP_NOT_REQUESTED
        assert "fake-unconstructible" not in outcome.failed_reporters
        assert outcome.failed is False

    def test_an_off_host_reporter_that_cannot_be_built_is_skipped_as_a_built_one_is(
        self, workspace
    ):
        """A built off-host reporter with no enabled section is skipped as
        disabled; the unbuildable one took the branch that never asked, so the
        run failed for a report it would never have written."""
        _, output_dir, _ = workspace
        outcome = _emit(
            workspace,
            FakeOffHostReporter,
            FakeOffHostUnbuildableReporter,
            FakeMergedReporter,
        )

        reporters = _manifest(output_dir)["reporters"]
        assert reporters["fake-off-host"]["skipped"] == SKIP_DISABLED
        entry = reporters["fake-off-host-unbuildable"]
        assert "could not be constructed" in entry["error"]
        assert entry["skipped"] == SKIP_DISABLED
        assert "fake-off-host-unbuildable" not in outcome.failed_reporters
        assert outcome.failed is False
        assert "fake-merged" in outcome.workspace_artifacts

    def test_a_requested_reporter_that_cannot_be_built_still_fails(self, workspace):
        """The control: asked for by name, the missing report is the step's."""
        _, output_dir, _ = workspace
        outcome = _emit(
            workspace,
            FakeUnconstructibleReporter,
            FakeMergedReporter,
            output_formats=("fake-unconstructible", "fake-merged"),
        )

        entry = _manifest(output_dir)["reporters"]["fake-unconstructible"]
        assert "skipped" not in entry
        assert "fake-unconstructible" in outcome.failed_reporters
        assert outcome.failed is True

    def test_a_name_that_cannot_be_read_is_recorded_under_the_class_name(
        self, workspace, monkeypatch
    ):
        """The handler re-read ``plugin_config_key``; when that is what raised,
        the error escaped and the step died with no manifest."""
        _, output_dir, _ = workspace
        real_key = reporting.plugin_config_key

        def key(reporter_class):
            if reporter_class is FakeUnconstructibleReporter:
                raise RuntimeError("no name can be read")
            return real_key(reporter_class)

        monkeypatch.setattr(reporting, "plugin_config_key", key)

        outcome = _emit(workspace, FakeUnconstructibleReporter, FakeMergedReporter)

        assert outcome.manifest_path is not None
        entry = _manifest(output_dir)["reporters"]["FakeUnconstructibleReporter"]
        assert "no name can be read" in entry["error"]
        assert "FakeUnconstructibleReporter" in outcome.failed_reporters
        assert "fake-merged" in outcome.workspace_artifacts


class TestFailuresAreRecordedNotRaised:
    def test_a_merged_reporter_that_raised_covers_no_project(self, workspace):
        _, output_dir, _ = workspace
        _emit(workspace, FakeRaisingReporter)

        entry = _manifest(output_dir)["reporters"]["fake-raising"]
        assert "error" in entry
        assert entry["covers_projects"] is False

    def test_an_error_carrying_an_environment_value_is_redacted(self, workspace):
        _, output_dir, _ = workspace
        outcome = _emit(workspace, FakeRaisingReporter)

        entry = _manifest(output_dir)["reporters"]["fake-raising"]
        assert CANARY not in entry["error"]
        assert CANARY not in outcome.failed_reporters["fake-raising"]
        assert "RuntimeError" in entry["error"]

    def test_a_results_file_that_cannot_be_loaded_still_gets_a_manifest(
        self, workspace
    ):
        plan, output_dir, results_path = workspace
        Path(results_path).write_text("not json", encoding="utf-8")

        outcome = _emit(workspace, FakeMergedReporter)

        assert outcome.manifest_path is not None
        entry = _manifest(output_dir)["reporters"]["fake-merged"]
        assert "could not be loaded" in entry["error"]
        assert entry["covers_projects"] is False
        assert "fake-merged" in outcome.failed_reporters

    def test_a_link_that_appears_after_the_check_is_recorded_against_its_reporter(
        self, workspace, monkeypatch
    ):
        _, output_dir, _ = workspace
        original = reporting.write_report_file

        def planted(reports_dir, filename, content):
            if filename == "ash.twin-a.txt":
                raise OutputDirLinkRefused("a link appeared at ash.twin-a.txt")
            return original(reports_dir, filename, content)

        monkeypatch.setattr(reporting, "write_report_file", planted)

        outcome = _emit(workspace, FakeTwinA, FakeTwinB)

        assert outcome.manifest_path is not None
        reporters = _manifest(output_dir)["reporters"]
        assert "could not be written" in reporters["fake-twin"]["error"]
        assert "fake-twin" in outcome.failed_reporters
        assert (output_dir / REPORTS_DIR_NAME / "ash.twin-b.txt").is_file()
        assert not (output_dir / REPORTS_DIR_NAME / "ash.twin-a.txt").exists()


class TestACancelIsHonored:
    def test_no_further_reporter_runs_and_no_manifest_is_written(self, workspace):
        _, output_dir, _ = workspace
        event = CancelEvent()

        class FakeCancellingReporter(FakeTwinA):
            def report(self, model) -> str:
                event.set()
                return "a"

        with cancel_scope(event):
            with pytest.raises(ScanCancelled):
                _emit(workspace, FakeCancellingReporter, FakeTwinB)

        reports = output_dir / REPORTS_DIR_NAME
        assert not (reports / "ash.twin-b.txt").exists()
        assert not (reports / MANIFEST_FILENAME).exists()
