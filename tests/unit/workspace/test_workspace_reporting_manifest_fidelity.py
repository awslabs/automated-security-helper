# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The manifest describes this run, not what an earlier run left on disk.

``test_workspace_reporting.py`` pins the four behaviours. This file pins what
the report step says about files it did not write: a per-project report that a
previous run wrote for a project this run did not complete is not this run's;
a workspace-level report a previous run wrote for a reporter this run skips, or
that raises or returns nothing, does not outlive this run; a reporter whose
output cannot be written does not take the manifest down with it; and the
pre-scan link check builds the same reporter set the report step builds.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.workspace import reporting
from automated_security_helper.workspace.aggregation import WorkspaceAggregator
from automated_security_helper.workspace.reporting import (
    MANIFEST_FILENAME,
    REPORTS_DIR_NAME,
    emit_workspace_reports,
    refuse_linked_workspace_report_paths,
)
from tests.unit.workspace.test_workspace_reporting import (
    FakeMergedReporter,
    FakePerProjectReporter,
    FakeRaisingReporter,
    FakeWorkspaceScopedReporter,
    _outcome,
    _plan,
    _run,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def workspace(tmp_path):
    """A written two-project workspace, as the sibling file builds it."""
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


class _EmptyConfig(ReporterPluginConfigBase):
    name: str = "fake-empty"
    extension: str = "empty.txt"
    enabled: bool = True


class FakeEmptyReporter(ReporterPluginBase[_EmptyConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _EmptyConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:
        return ""


class _NotTextConfig(ReporterPluginConfigBase):
    name: str = "fake-not-text"
    extension: str = "nottext.json"
    enabled: bool = True


class FakeNotTextReporter(ReporterPluginBase[_NotTextConfig]):
    """Returns a dict where the contract says str: the write raises TypeError."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _NotTextConfig()
        return super().model_post_init(context)

    def report(self, model):
        return {"not": "text"}


class TestAPerProjectArtefactBelongsToTheRunThatWroteIt:
    def _results_with(self, tmp_path, statuses):
        results = tmp_path / "results.json"
        results.write_text(
            json.dumps(
                {
                    "workspace": {
                        "projects": [
                            {"project": key, "status": status}
                            for key, status in statuses.items()
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )
        return results

    def test_a_file_for_a_project_that_did_not_complete_is_missing(
        self, workspace, tmp_path
    ):
        """``web`` failed before its own output was set up; the ghas file in its
        reports directory is an earlier run's and was listed as this run's."""
        plan, output_dir, _ = workspace
        results = self._results_with(tmp_path, {"api": "completed", "web": "failed"})

        emit_workspace_reports(
            plan=plan,
            output_dir=output_dir,
            results_path=results,
            reporter_classes=[FakePerProjectReporter],
        )

        entry = _manifest(output_dir)["reporters"]["fake-per-project"]
        # Named as missing and not offered as an artefact: the file on disk is
        # not this run's, and listing it beside api's told a consumer it was.
        assert [item["project"] for item in entry["per_project_artifacts"]] == ["api"]
        assert entry["missing_per_project_artifacts"] == ["web"]

    def test_a_file_for_a_skipped_project_is_missing_too(self, workspace, tmp_path):
        plan, output_dir, _ = workspace
        results = self._results_with(tmp_path, {"api": "completed"})

        emit_workspace_reports(
            plan=plan,
            output_dir=output_dir,
            results_path=results,
            reporter_classes=[FakePerProjectReporter],
        )

        entry = _manifest(output_dir)["reporters"]["fake-per-project"]
        assert entry["missing_per_project_artifacts"] == ["web"]

    def test_a_completed_project_with_its_file_is_present(self, workspace):
        _, output_dir, _ = workspace

        _emit(workspace, FakePerProjectReporter)

        entry = _manifest(output_dir)["reporters"]["fake-per-project"]
        assert entry["missing_per_project_artifacts"] == []

    def test_the_callers_completed_set_governs_over_the_file(self, workspace):
        """The results file in this fixture says both projects completed; the
        caller, which holds every outcome in memory, says only ``api`` did."""
        _, output_dir, _ = workspace

        _emit(workspace, FakePerProjectReporter, completed_projects=["api"])

        entry = _manifest(output_dir)["reporters"]["fake-per-project"]
        assert [item["project"] for item in entry["per_project_artifacts"]] == ["api"]
        assert entry["missing_per_project_artifacts"] == ["web"]

    def test_a_failed_project_with_output_is_listed_when_the_caller_says_so(
        self, workspace, tmp_path
    ):
        """The control for the test above: the results file calls ``web`` failed,
        and the caller, which knows its output was written, lists it. A status of
        COMPLETED is not what makes a file this run's."""
        plan, output_dir, _ = workspace
        results = self._results_with(tmp_path, {"api": "completed", "web": "failed"})

        emit_workspace_reports(
            plan=plan,
            output_dir=output_dir,
            results_path=results,
            reporter_classes=[FakePerProjectReporter],
            completed_projects=["api", "web"],
        )

        entry = _manifest(output_dir)["reporters"]["fake-per-project"]
        assert [item["project"] for item in entry["per_project_artifacts"]] == [
            "api",
            "web",
        ]
        assert entry["missing_per_project_artifacts"] == []

    def test_with_the_callers_set_the_results_file_is_not_parsed_for_it(
        self, workspace, monkeypatch
    ):
        """Every report step parsed the whole unified file for one field, on
        a default run's six disabled reporters too; the caller's set spares it."""
        _, output_dir, _ = workspace
        calls: list = []

        def recording(results_path):
            # Records and answers; it does not raise, because the step records a
            # failure of its own reporters and an exception raised here could be
            # swallowed by a handler around the call, which would pass this test
            # whether or not the file was parsed.
            calls.append(results_path)
            return set()

        monkeypatch.setattr(reporting, "_projects_with_a_completed_run", recording)

        _emit(workspace, FakePerProjectReporter, completed_projects=["api", "web"])

        assert calls == []
        entry = _manifest(output_dir)["reporters"]["fake-per-project"]
        assert entry["missing_per_project_artifacts"] == []

    def test_without_the_callers_set_the_results_file_is_read_once(
        self, workspace, monkeypatch
    ):
        """The control for the test above: the same stub is reached when the
        caller gives no set, so an empty ``calls`` there means the file was not
        read, not that the stub was never in the way."""
        _, output_dir, _ = workspace
        calls: list = []

        def recording(results_path):
            calls.append(results_path)
            return {"api", "web"}

        monkeypatch.setattr(reporting, "_projects_with_a_completed_run", recording)

        _emit(workspace, FakePerProjectReporter)

        assert len(calls) == 1, calls
        entry = _manifest(output_dir)["reporters"]["fake-per-project"]
        assert entry["missing_per_project_artifacts"] == []


class TestAPreviousRunsWorkspaceReportDoesNotOutliveThisRun:
    def _stale(self, output_dir: Path, name: str) -> Path:
        reports = output_dir / REPORTS_DIR_NAME
        reports.mkdir(parents=True, exist_ok=True)
        path = reports / name
        path.write_text("from an earlier run", encoding="utf-8")
        return path

    def test_a_reporter_that_raises_leaves_no_earlier_file(self, workspace):
        _, output_dir, _ = workspace
        stale = self._stale(output_dir, "ash.raising.txt")

        outcome = _emit(workspace, FakeRaisingReporter)

        assert not stale.exists()
        assert "fake-raising" in outcome.failed_reporters

    def test_a_reporter_that_returns_nothing_leaves_no_earlier_file(self, workspace):
        _, output_dir, _ = workspace
        stale = self._stale(output_dir, "ash.empty.txt")

        _emit(workspace, FakeEmptyReporter)

        assert not stale.exists()
        entry = _manifest(output_dir)["reporters"]["fake-empty"]
        assert entry["note"] == "the reporter returned no content"
        assert "error" not in entry

    def test_a_reporter_this_run_does_not_select_leaves_no_earlier_file(
        self, workspace
    ):
        _, output_dir, _ = workspace
        stale = self._stale(output_dir, "ash.scoped.json")

        _emit(
            workspace,
            FakeMergedReporter,
            FakeWorkspaceScopedReporter,
            output_formats=["fake-merged"],
        )

        assert not stale.exists()
        assert (output_dir / REPORTS_DIR_NAME / "ash.merged.txt").is_file()
        entry = _manifest(output_dir)["reporters"]["fake-workspace-scoped"]
        assert entry["skipped"] == reporting.SKIP_NOT_REQUESTED

    def test_this_runs_file_replaces_an_earlier_one(self, workspace):
        _, output_dir, _ = workspace
        path = self._stale(output_dir, "ash.merged.txt")

        _emit(workspace, FakeMergedReporter)

        content = path.read_text(encoding="utf-8")
        assert "from an earlier run" not in content
        assert "RULE-API" in content

    def test_the_previous_manifest_is_removed_with_the_reports(self, tmp_path):
        """The manifest is written last, after every reporter. Removing the
        reports and keeping the old manifest left a manifest naming files that
        were gone whenever the step stopped before writing its own."""
        reports = tmp_path / REPORTS_DIR_NAME
        reports.mkdir()
        manifest = reports / MANIFEST_FILENAME
        manifest.write_text("{}", encoding="utf-8")

        reporting._remove_previous_workspace_reports(reports, [])

        assert not manifest.exists()

    def test_a_step_that_stops_before_its_manifest_leaves_no_stale_one(
        self, workspace, monkeypatch
    ):
        _, output_dir, _ = workspace
        stale_report = self._stale(output_dir, "ash.merged.txt")
        stale_manifest = self._stale(output_dir, MANIFEST_FILENAME)

        def cancelled() -> None:
            raise ScanCancelled("the scan was cancelled")

        monkeypatch.setattr(reporting, "raise_if_cancelled", cancelled)
        with pytest.raises(ScanCancelled):
            _emit(workspace, FakeMergedReporter)

        assert not stale_report.exists()
        assert not stale_manifest.exists()


class TestAWriteThatFailsDoesNotSinkTheManifest:
    def test_a_non_text_report_is_a_recorded_failure(self, workspace):
        """``write_text_atomically`` raises TypeError for a dict; the step used
        to abort there with no manifest and the other reports unwritten."""
        _, output_dir, _ = workspace

        outcome = _emit(workspace, FakeNotTextReporter, FakeMergedReporter)

        assert outcome.manifest_path is not None
        assert (output_dir / REPORTS_DIR_NAME / "ash.merged.txt").is_file()
        assert not (output_dir / REPORTS_DIR_NAME / "ash.nottext.json").exists()
        assert "TypeError" in outcome.failed_reporters["fake-not-text"]
        entry = _manifest(output_dir)["reporters"]["fake-not-text"]
        assert "TypeError" in entry["error"]
        assert outcome.failed


def _returning(value):
    """A merged reporter, named ``fake-empty``, whose ``report()`` returns *value*."""

    class _Returning(FakeEmptyReporter):
        def report(self, model):
            return value

    return _Returning


class TestOnlyTheEmptyStringIsNothingToSay:
    @pytest.mark.parametrize(
        "value",
        [{}, [], b"", 0, False, {"not": "text"}, b"bytes"],
        ids=["dict", "list", "bytes", "zero", "false", "full-dict", "full-bytes"],
    )
    def test_a_report_that_is_not_text_is_a_failure_whatever_its_truth(
        self, workspace, value
    ):
        """``if not content`` read ``{}``, ``[]`` and ``b""`` as "no content", a
        note, while the same kinds of value non-empty failed at the write."""
        _, output_dir, _ = workspace
        stale = output_dir / REPORTS_DIR_NAME / "ash.empty.txt"
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text("from an earlier run", encoding="utf-8")

        outcome = _emit(workspace, _returning(value))

        assert "TypeError" in outcome.failed_reporters["fake-empty"]
        entry = _manifest(output_dir)["reporters"]["fake-empty"]
        assert "TypeError" in entry["error"]
        assert "note" not in entry
        assert entry["workspace_artifact"] is None
        assert not stale.exists()
        assert outcome.failed

    def test_the_empty_string_stays_a_note(self, workspace):
        """The control: the one falsy value that is text is still not a failure."""
        _, output_dir, _ = workspace

        outcome = _emit(workspace, _returning(""))

        assert outcome.failed_reporters == {}
        entry = _manifest(output_dir)["reporters"]["fake-empty"]
        assert entry["note"] == "the reporter returned no content"
        assert "error" not in entry


class TestThePreScanLinkCheckBuildsTheSameReporterSet:
    def test_plugin_modules_reach_the_reporter_selection(self, workspace, monkeypatch):
        plan, output_dir, _ = workspace
        seen = {}

        def selected(**kwargs):
            seen.update(kwargs)
            return iter(())

        monkeypatch.setattr(reporting, "_selected_reporters", selected)

        refuse_linked_workspace_report_paths(
            plan, output_dir, plugin_modules=["my_org.ash_plugins"]
        )

        assert seen["plugin_modules"] == ["my_org.ash_plugins"]

    def test_the_three_callers_hand_the_selection_the_same_inputs(
        self, workspace, monkeypatch
    ):
        """The pre-scan link check, the pre-scan refusal and the report step each
        build the set from the same four inputs; given the same ones they pass the
        selection the same values, so the set cannot drift on any of them. Only
        ``check_dependencies`` differs, by design: the pre-scan callers must not
        contact a remote service."""
        plan, output_dir, results_path = workspace
        inputs = {
            "output_formats": ("fake-merged",),
            "python_based_plugins_only": True,
            "reporter_classes": [FakeMergedReporter],
            "plugin_modules": ["my_org.ash_plugins"],
        }
        recorded: dict = {}
        label = [""]
        real = reporting._selected_reporters

        def recording(**kwargs):
            recorded[label[0]] = {key: kwargs[key] for key in inputs}
            recorded[label[0] + " dependencies"] = kwargs.get("check_dependencies")
            return real(**kwargs)

        monkeypatch.setattr(reporting, "_selected_reporters", recording)

        label[0] = "link check"
        refuse_linked_workspace_report_paths(plan, output_dir, **inputs)
        label[0] = "unsupported"
        reporting.unsupported_reporter_names(plan, output_dir, **inputs)
        label[0] = "report step"
        emit_workspace_reports(plan, output_dir, results_path, **inputs)

        assert recorded["link check"] == inputs
        assert recorded["unsupported"] == inputs
        assert recorded["report step"] == inputs
        # The one argument that differs, and which way: checking a reporter's
        # dependencies can call a remote service, so only the report step does.
        assert recorded["link check dependencies"] is False
        assert recorded["unsupported dependencies"] is False
        assert recorded["report step dependencies"] in (None, True)


class _NoneConfig(ReporterPluginConfigBase):
    name: str = "fake-none"
    extension: str = "none.txt"
    enabled: bool = True


class FakeNoneReporter(ReporterPluginBase[_NoneConfig]):
    """Does not return: the contract says str, and None is not "nothing to say"."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _NoneConfig()
        return super().model_post_init(context)

    def report(self, model):
        return None


class _StringBehaviourConfig(ReporterPluginConfigBase):
    name: str = "fake-string-behaviour"
    extension: str = "strbeh.txt"
    enabled: bool = True


class FakeStringBehaviourReporter(ReporterPluginBase[_StringBehaviourConfig]):
    """Declares the behaviour as the member's value, a plain string."""

    workspace_behaviour = "merged"  # type: ignore[assignment]

    def model_post_init(self, context):
        if self.config is None:
            self.config = _StringBehaviourConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:
        return "declared as a string"


class _BadBehaviourConfig(ReporterPluginConfigBase):
    name: str = "fake-bad-behaviour"
    extension: str = "badbeh.txt"
    enabled: bool = True


class FakeBadBehaviourReporter(ReporterPluginBase[_BadBehaviourConfig]):
    """Declares a behaviour ASH cannot read."""

    workspace_behaviour = "sideways"  # type: ignore[assignment]

    def model_post_init(self, context):
        if self.config is None:
            self.config = _BadBehaviourConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("a reporter with an unreadable declaration ran")


class TestAReporterThatReturnsNoneFailed:
    def test_none_is_a_failure_and_the_empty_string_is_not(self, workspace):
        _, output_dir, _ = workspace

        outcome = _emit(workspace, FakeNoneReporter, FakeEmptyReporter)

        assert "fake-none" in outcome.failed_reporters
        assert "None" in outcome.failed_reporters["fake-none"]
        assert "fake-empty" not in outcome.failed_reporters
        reporters = _manifest(output_dir)["reporters"]
        assert "None" in reporters["fake-none"]["error"]
        assert reporters["fake-empty"]["note"] == "the reporter returned no content"
        assert "error" not in reporters["fake-empty"]
        assert outcome.failed


class TestADeclarationIsReadAsTheEnum:
    def test_a_string_naming_a_member_is_that_member(self, workspace):
        """A plain-string declaration reached ``behaviour.value`` and took the
        whole report step down with an AttributeError."""
        _, output_dir, _ = workspace

        outcome = _emit(workspace, FakeStringBehaviourReporter)

        artefact = output_dir / REPORTS_DIR_NAME / "ash.strbeh.txt"
        assert artefact.is_file()
        assert outcome.workspace_artifacts == {"fake-string-behaviour": artefact}
        entry = _manifest(output_dir)["reporters"]["fake-string-behaviour"]
        assert entry["behaviour"] == ReporterWorkspaceBehaviour.MERGED.value

    def test_an_unreadable_declaration_is_unsupported_not_a_crash(self, workspace):
        _, output_dir, _ = workspace

        outcome = _emit(workspace, FakeBadBehaviourReporter, FakeMergedReporter)

        assert outcome.manifest_path is not None
        assert outcome.unsupported_reporters == ("fake-bad-behaviour",)
        assert (output_dir / REPORTS_DIR_NAME / "ash.merged.txt").is_file()
        entry = _manifest(output_dir)["reporters"]["fake-bad-behaviour"]
        assert entry["behaviour"] == ReporterWorkspaceBehaviour.UNSUPPORTED.value

    def test_the_manifest_names_the_declaration_not_a_claim_the_reporter_made(
        self, workspace
    ):
        """An unreadable declaration is a typo to fix, so the entry says that,
        and does not say the reporter declared itself unable to work."""
        _, output_dir, _ = workspace

        _emit(workspace, FakeBadBehaviourReporter)

        error = _manifest(output_dir)["reporters"]["fake-bad-behaviour"]["error"]
        assert "'sideways'" in error, error
        assert "per-project" in error, error
        assert "fix the declaration" in error, error
        assert "declares that it cannot produce" not in error, error

    def test_an_unreadable_declaration_is_an_error_once_however_often_it_is_read(
        self, caplog
    ):
        import logging

        from automated_security_helper.utils.log import ASH_LOGGER

        class FreshBadBehaviourReporter(FakeBadBehaviourReporter):
            workspace_behaviour = "sideways-once"  # type: ignore[assignment]

        caplog.set_level(logging.DEBUG, logger=ASH_LOGGER.name)

        for _ in range(3):
            behaviour = reporting._declared_behaviour(
                FreshBadBehaviourReporter, "fake-bad-behaviour"
            )
            assert behaviour is ReporterWorkspaceBehaviour.UNSUPPORTED

        errors = [
            r
            for r in caplog.records
            if r.levelno >= logging.ERROR and "sideways-once" in r.getMessage()
        ]
        assert len(errors) == 1, caplog.text
