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
from automated_security_helper.core.exceptions import WorkspaceDefinitionError
from automated_security_helper.utils.error_text import carry_environment_values
from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused
from automated_security_helper.workspace import reporting
from automated_security_helper.workspace.aggregation import WorkspaceAggregator
from automated_security_helper.workspace.reporting import (
    MANIFEST_FILENAME,
    REPORTS_DIR_NAME,
    SKIP_DISABLED,
    SKIP_NOT_PYTHON_ONLY,
    SKIP_NOT_REQUESTED,
    refuse_linked_workspace_report_paths,
)
from tests.unit.workspace.test_workspace_reporting import (
    FakeDefaultOffPerProjectReporter,
    FakeMergedReporter,
    _emit,
    _manifest,
    _outcome,
    _plan,
    _run,
)

pytestmark = pytest.mark.unit

CANARY = "env-canary-value-q7k2"


@pytest.fixture
def workspace(tmp_path):
    # Not the sibling module's fixture: that one also writes a ``ash.ghas.sarif``
    # into each project's reports, and several cases here depend on only
    # ``ash.cdx.json`` being there.
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


# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #


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


class _UnbuildablePerProjectConfig(ReporterPluginConfigBase):
    name: str = "fake-unbuildable-per-project"
    extension: str = "cdx.json"
    enabled: bool = True


class FakeUnbuildablePerProjectReporter(
    ReporterPluginBase[_UnbuildablePerProjectConfig]
):
    """Per-project, enabled, and raising in the workspace step's constructor: the
    step owes no workspace file for it, because each project's own report phase
    writes its files."""

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

    def model_post_init(self, context):
        raise RuntimeError("cannot be built in the workspace context")

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


class _CanaryRaisingConfig(ReporterPluginConfigBase):
    name: str = "fake-canary-raising"
    extension: str = "canary-raising.txt"
    enabled: bool = True


class FakeCanaryRaisingReporter(ReporterPluginBase[_CanaryRaisingConfig]):
    """Raises an error that carries an environment value, to pin its redaction.

    Not the sibling module's ``FakeRaisingReporter``, which raises a plain error."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _CanaryRaisingConfig()
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
        self, workspace, caplog
    ):
        import logging

        from automated_security_helper.utils.log import ASH_LOGGER

        caplog.set_level(logging.WARNING, logger=ASH_LOGGER.name)
        _, output_dir, _ = workspace
        outcome = _emit(
            workspace, FakePythonOnlyRaisesReporter, python_based_plugins_only=True
        )

        entry = _manifest(output_dir)["reporters"]["fake-python-only-raises"]
        assert entry["skipped"] == SKIP_NOT_PYTHON_ONLY
        assert outcome.failed_reporters == {}
        # The exclusion is said in the log, with the reporter's name and why.
        assert "fake-python-only-raises" in caplog.text, caplog.text
        assert "raised while reporting whether it is Python-only" in caplog.text, (
            caplog.text
        )

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

    def test_a_class_whose_declarations_cannot_be_read_does_not_take_the_step_down(
        self, workspace, monkeypatch
    ):
        """The skip reason is read inside the handler of the constructor's own
        failure, so a class whose config model cannot be read raised from there
        and no manifest was written."""
        _, output_dir, _ = workspace
        real = reporting.declared_config_model

        def unreadable(reporter_class, base):
            if reporter_class is FakeUnconstructibleReporter:
                raise RuntimeError("no model can be read")
            return real(reporter_class, base)

        monkeypatch.setattr(reporting, "declared_config_model", unreadable)

        outcome = _emit(workspace, FakeUnconstructibleReporter, FakeMergedReporter)

        assert outcome.manifest_path is not None
        entry = _manifest(output_dir)["reporters"]["fake-unconstructible"]
        assert "cannot be built" in entry["error"]
        assert "skipped" not in entry
        assert "fake-unconstructible" in outcome.failed_reporters
        assert "fake-merged" in outcome.workspace_artifacts

    def test_a_disabled_reporter_the_formats_leave_out_is_not_requested(
        self, workspace
    ):
        """The same label a built reporter gets for the same two facts: the
        formats are applied before the config's switch."""
        _, output_dir, _ = workspace
        outcome = _emit(
            workspace,
            FakeUnconstructibleOffReporter,
            FakeDefaultOffMergedReporter,
            FakeMergedReporter,
            output_formats=("fake-merged",),
        )

        reporters = _manifest(output_dir)["reporters"]
        assert reporters["fake-default-off-merged"]["skipped"] == SKIP_NOT_REQUESTED
        entry = reporters["fake-unconstructible-off"]
        assert "could not be constructed" in entry["error"]
        assert entry["skipped"] == SKIP_NOT_REQUESTED
        assert outcome.failed is False

    def test_a_reporter_that_cannot_be_built_leaves_no_earlier_file(self, workspace):
        """The earlier run's report stayed beside a manifest saying the reporter
        could not be constructed, and read as this run's."""
        _, output_dir, _ = workspace
        reports = output_dir / REPORTS_DIR_NAME
        reports.mkdir(parents=True, exist_ok=True)
        stale = reports / "ash.unconstructible.txt"
        stale.write_text("from an earlier run", encoding="utf-8")

        outcome = _emit(workspace, FakeUnconstructibleReporter, FakeMergedReporter)

        assert not stale.exists()
        assert "fake-unconstructible" in outcome.failed_reporters
        assert (reports / "ash.merged.txt").is_file()

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
        assert entry["behaviour"] == ReporterWorkspaceBehaviour.MERGED.value
        assert "fake-unconstructible" in outcome.failed_reporters
        assert outcome.failed is True

    def test_a_per_project_reporter_that_cannot_be_built_does_not_fail_the_run(
        self, workspace
    ):
        """The step writes nothing at workspace level for a per-project reporter,
        so a constructor that raises here fails nothing it owed. The entry names
        the declared behaviour (it was null) and lists the projects' files."""
        _, output_dir, _ = workspace
        outcome = _emit(
            workspace, FakeUnbuildablePerProjectReporter, FakeMergedReporter
        )

        entry = _manifest(output_dir)["reporters"]["fake-unbuildable-per-project"]
        assert entry["behaviour"] == ReporterWorkspaceBehaviour.PER_PROJECT.value
        assert "could not be constructed" in entry["error"]
        assert "skipped" not in entry
        assert entry["per_project_artifacts"] == [
            {"project": "api", "path": "projects/api/reports/ash.cdx.json"},
            {"project": "web", "path": "projects/web/reports/ash.cdx.json"},
        ]
        assert entry["missing_per_project_artifacts"] == []
        assert "fake-unbuildable-per-project" not in outcome.failed_reporters
        assert outcome.per_project_reporters == ("fake-unbuildable-per-project",)
        assert outcome.failed is False
        assert "fake-merged" in outcome.workspace_artifacts

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


class TestAnUnbuildableReporterIsRefusedBeforeAnythingIsScanned:
    """The post-scan step fails the run for a report it owed and could not build
    (``TestAnUnbuildableReporterFailsOnlyWhatItOwed``); the pre-scan check finds
    the same reporters first, so the operator learns before paying for the scans."""

    def test_a_reporter_the_step_would_run_refuses_the_run(self, workspace):
        plan, output_dir, _ = workspace

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            refuse_linked_workspace_report_paths(
                plan,
                output_dir,
                reporter_classes=[FakeUnconstructibleReporter, FakeMergedReporter],
            )

        message = str(excinfo.value)
        assert "fake-unconstructible" in message
        assert "cannot be built" in message
        assert "Nothing was scanned" in message

    def test_control_a_reporter_the_step_would_not_run_refuses_nothing(self, workspace):
        plan, output_dir, _ = workspace

        # Disabled, a per-project reporter, and one the formats leave out.
        refuse_linked_workspace_report_paths(
            plan,
            output_dir,
            reporter_classes=[
                FakeUnconstructibleOffReporter,
                FakeUnbuildablePerProjectReporter,
                FakeMergedReporter,
            ],
        )
        refuse_linked_workspace_report_paths(
            plan,
            output_dir,
            output_formats=("fake-merged",),
            reporter_classes=[FakeUnconstructibleReporter, FakeMergedReporter],
        )


class _RaisingDependencyCheck:
    """A reporter whose own dependency check raises an error carrying a secret."""

    config = _CanaryRaisingConfig()

    def validate_plugin_dependencies(self) -> bool:
        error = RuntimeError(f"token {CANARY} leaked")
        carry_environment_values(error, (CANARY,))
        raise error


class TestADependencyCheckThatRaisesIsLoggedWithoutItsSecrets:
    def test_the_warning_hides_an_environment_value_the_error_carries(self, caplog):
        import logging

        from automated_security_helper.utils.log import ASH_LOGGER

        caplog.set_level(logging.WARNING, logger=ASH_LOGGER.name)

        assert reporting._dependencies_unsatisfied(_RaisingDependencyCheck()) is True

        assert "raised while validating its dependencies" in caplog.text, caplog.text
        assert "RuntimeError" in caplog.text, caplog.text
        assert CANARY not in caplog.text, caplog.text


class TestFailuresAreRecordedNotRaised:
    def test_a_merged_reporter_that_raised_covers_no_project(self, workspace):
        _, output_dir, _ = workspace
        _emit(workspace, FakeCanaryRaisingReporter)

        entry = _manifest(output_dir)["reporters"]["fake-canary-raising"]
        assert "error" in entry
        assert entry["covers_projects"] is False

    def test_an_error_carrying_an_environment_value_is_redacted(
        self, workspace, caplog
    ):
        import logging

        from automated_security_helper.utils.log import ASH_LOGGER

        caplog.set_level(logging.DEBUG, logger=ASH_LOGGER.name)
        _, output_dir, _ = workspace
        outcome = _emit(workspace, FakeCanaryRaisingReporter)

        entry = _manifest(output_dir)["reporters"]["fake-canary-raising"]
        assert CANARY not in entry["error"]
        assert CANARY not in outcome.failed_reporters["fake-canary-raising"]
        assert "RuntimeError" in entry["error"]
        # The log is a sink too: the error line and the debug traceback are both
        # written, and neither may carry the value. The first assertion is the
        # control that the failure was logged at all, so the second is not vacuous.
        assert "failed at workspace level" in caplog.text, caplog.text
        assert CANARY not in caplog.text, caplog.text

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
        # An earlier run's file at the name the refused write was for. It is the
        # file the refusal must not leave behind: without it the final assertion
        # below holds whatever the step did, as the refused write creates nothing.
        stale = output_dir / REPORTS_DIR_NAME / "ash.twin-a.txt"
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text("from an earlier run", encoding="utf-8")

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


def _answering(answer):
    """A merged reporter whose ``report()`` returns ``answer``."""

    class _Answering(FakeMergedReporter):
        def report(self, model):
            return answer

    return _Answering


class TestCoversProjectsIsOnOnlyForAWrittenMergedFile:
    """``covers_projects`` says a merged file exists, whatever the other fields say."""

    def test_it_is_on_when_the_merged_file_is_written(self, workspace):
        _, output_dir, _ = workspace
        _emit(workspace, _answering("content"))

        entry = _manifest(output_dir)["reporters"]["fake-merged"]
        assert entry["workspace_artifact"] is not None
        assert entry["covers_projects"] is True

    @pytest.mark.parametrize("answer", [None, ""], ids=["none", "empty"])
    def test_it_is_off_when_the_reporter_wrote_nothing(self, workspace, answer):
        _, output_dir, _ = workspace
        _emit(workspace, _answering(answer))

        entry = _manifest(output_dir)["reporters"]["fake-merged"]
        assert entry["workspace_artifact"] is None
        assert entry["covers_projects"] is False

    @pytest.mark.parametrize("failure", ["raises", "returns_none"])
    def test_it_is_off_when_the_file_could_not_be_written(
        self, workspace, monkeypatch, failure
    ):
        _, output_dir, _ = workspace
        original = reporting.write_report_file

        def refused(reports_dir, filename, content):
            if filename == "ash.merged.txt":
                if failure == "raises":
                    raise OutputDirLinkRefused("a link appeared")
                return None
            return original(reports_dir, filename, content)

        monkeypatch.setattr(reporting, "write_report_file", refused)

        _emit(workspace, _answering("content"))

        entry = _manifest(output_dir)["reporters"]["fake-merged"]
        assert entry["workspace_artifact"] is None
        assert entry["covers_projects"] is False


class TestACancelIsHonored:
    def test_no_further_reporter_runs_and_no_manifest_is_written(self, workspace):
        _, output_dir, _ = workspace
        event = CancelEvent()

        class FakeCancellingReporter(FakeMergedReporter):
            def report(self, model) -> str:
                event.set()
                return "written before the cancel is read"

        with cancel_scope(event):
            with pytest.raises(ScanCancelled):
                _emit(workspace, FakeCancellingReporter, FakeTwinB)

        reports = output_dir / REPORTS_DIR_NAME
        assert not (reports / "ash.twin-b.txt").exists()
        assert not (reports / MANIFEST_FILENAME).exists()
        # What the reporter that cancelled had already produced stays, as the
        # results file does (the module docstring): the cancel is read before
        # the next reporter, not between a reporter's report and its write.
        written = reports / "ash.merged.txt"
        assert written.read_text(encoding="utf-8") == (
            "written before the cancel is read"
        )
