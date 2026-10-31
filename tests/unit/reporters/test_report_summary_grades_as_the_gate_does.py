# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The human reports' summary grades findings and coverage the way the gate does.

Five readings the content emitter made on its own, each disagreeing with the
exit code or the project outcome for the same results:

* a finding whose severity is not one of the five ladder names was mapped onto
  INFO (or onto nothing) and labelled "Below threshold", while the ladder fails
  such a finding closed;
* a workspace finding was graded against the scanner resolver's answer, which
  with the merged file's missing ash_config is ASH's default, while each
  project's outcome used the project's own recorded gate;
* a project skipped as no-changes made the whole run "Scan incomplete", while the
  workspace exit code treats that skip as a clean no-op;
* a scanner recorded ERROR only because its content database was stale counted
  as not completed and "needing attention", so a one-scanner run read "No
  scanners completed" beside the stale-database notice that named it;
* a raw-data ``snippet`` that was not a string was returned as the code snippet
  and crashed the Markdown renderer.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.content_db_staleness import (
    STALE_NOTIFICATION_ID,
    ContentDbAgeRecord,
)

pytestmark = pytest.mark.unit


def _vuln(**overrides) -> FlatVulnerability:
    fields = {
        "id": "f-1",
        "title": "a finding",
        "description": "",
        "severity": "MEDIUM",
        "scanner": "bandit",
        "scanner_type": "SAST",
    }
    fields.update(overrides)
    return FlatVulnerability(**fields)


class TestAnUnrecognisedSeverityFailsClosed:
    def test_an_unknown_severity_is_actionable_under_every_threshold(self):
        emitter = ReportContentEmitter(AshAggregatedResults())
        for threshold in ("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            assert emitter._is_severity_actionable("UNKNOWN", threshold), threshold
            assert emitter._is_severity_actionable("BOGUS", threshold), threshold

    def test_the_ladder_s_own_answers_are_unchanged(self):
        emitter = ReportContentEmitter(AshAggregatedResults())
        assert emitter._is_severity_actionable("HIGH", "MEDIUM")
        assert not emitter._is_severity_actionable("LOW", "MEDIUM")
        assert not emitter._is_severity_actionable("INFO", "LOW")
        assert emitter._is_severity_actionable("INFO", "ALL")

    def test_a_flat_finding_with_an_unknown_severity_is_actionable(self):
        emitter = ReportContentEmitter(AshAggregatedResults())
        assert emitter.is_finding_actionable(_vuln(severity="UNKNOWN"))


def _project(key: str, **overrides) -> WorkspaceProjectResult:
    fields = {
        "project": key,
        "relative_path": key,
        "display_label": key,
        "status": ProjectRunStatus.COMPLETED,
        "severity_threshold": "MEDIUM",
        "output_path": f"projects/{key}",
    }
    fields.update(overrides)
    return WorkspaceProjectResult(**fields)


def _workspace(tmp_path, *projects) -> WorkspaceResults:
    return WorkspaceResults(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        exit_code=0,
        projects=list(projects),
    )


def _one_medium_finding_model(project: "str | None") -> AshAggregatedResults:
    """One MEDIUM (SARIF ``warning``) bandit finding, attributed to *project*
    when one is named; no recorded config, so the scanner resolver grades at
    ASH's default."""
    properties = {"scanner_name": "bandit"}
    if project is not None:
        properties["workspace_project"] = project
    model = AshAggregatedResults()
    model.ash_config = None
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": [
                        {
                            "ruleId": "RULE-MEDIUM",
                            "level": "warning",
                            "message": {"text": "a medium finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/a.py"}
                                    }
                                }
                            ],
                            "properties": properties,
                        }
                    ],
                    "invocations": [],
                }
            ],
        }
    )
    return model


def _assert_rows_grade_by_another_gate(
    emitter: ReportContentEmitter, model: AshAggregatedResults, project_gate: str
) -> None:
    """The fixture's precondition: the scanner rows do not grade at the project's gate.

    The scanner rows count by the scanner resolver, which with the merged file's
    missing ash_config answers ASH's default for every project. A test of the
    headline's recount is only meaningful while that answer differs from the gate
    the project recorded, so the precondition is stated as that difference and not
    as a disagreement between a row and the headline.
    """
    assert emitter.get_scanner_results(), "the fixture must exercise the scanner rows"
    resolved, _source = ScannerStatisticsCalculator.get_scanner_threshold_info(
        model, "bandit"
    )
    assert resolved != project_gate, resolved


def _one_bandit_finding_model(
    level: str, project: str, **properties
) -> AshAggregatedResults:
    """One bandit finding of SARIF *level* in *project*, bandit among the scanners run.

    No recorded config, so the scanner resolver grades at ASH's default; *properties*
    are written on the result beside the scanner name and the project.
    """
    model = AshAggregatedResults()
    model.ash_config = None
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": [
                        {
                            "ruleId": "RULE-ONE",
                            "level": level,
                            "message": {"text": "one finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/a.py"}
                                    }
                                }
                            ],
                            "properties": {
                                "scanner_name": "bandit",
                                "workspace_project": project,
                                **properties,
                            },
                        }
                    ],
                    "invocations": [],
                }
            ],
        }
    )
    model.scanner_results["bandit"] = ScannerTargetStatusInfo(duration=1.0)
    return model


class TestAWorkspaceHeadlineGradesAsTheProjectOutcomeDid:
    """The headline recounts findings the way the project's outcome graded them.

    The outcome (and the exit code that follows it) resolves a finding's gate
    from the scanner's own recorded threshold first and the project's second,
    and leaves out the findings of a scanner only the workspace policy added
    when that policy does not gate. The recount used the project's gate alone,
    so a headline could read "No actionable findings" above a project row that
    failed, or "Review required" for a run that exits clean.
    """

    def test_a_scanners_own_gate_decides_before_the_projects(self, tmp_path):
        """Project gate HIGH, bandit's own gate LOW, one LOW bandit finding.

        RED at the base: graded at the project's HIGH the LOW finding is not
        actionable, so the headline read "No actionable findings" in the success
        tone for a project whose outcome failed on that finding.
        """
        model = _one_bandit_finding_model("note", "svc")
        model.workspace = _workspace(
            tmp_path,
            _project(
                "svc", severity_threshold="HIGH", scanner_thresholds={"bandit": "LOW"}
            ),
        )

        summary = ReportContentEmitter(
            model, human_presentation=True
        ).get_scan_summary()

        assert summary["actionable"] == 1, summary
        assert summary["title"] == "Review required", summary
        assert summary["tone"] == "danger", summary

    def test_a_scanners_gate_does_not_move_another_scanners_findings(self, tmp_path):
        """The control: a scanner with no gate of its own is graded at the project's."""
        model = _one_bandit_finding_model("note", "svc")
        model.workspace = _workspace(
            tmp_path,
            _project(
                "svc", severity_threshold="HIGH", scanner_thresholds={"semgrep": "LOW"}
            ),
        )

        summary = ReportContentEmitter(
            model, human_presentation=True
        ).get_scan_summary()

        assert summary["actionable"] == 0, summary
        assert summary["title"] == "No actionable findings", summary

    def test_a_non_gating_policy_finding_is_not_actionable(self, tmp_path):
        """A policy scanner's finding, with the policy's gate off, left the outcome.

        RED at the base: the MEDIUM finding was graded at the project's MEDIUM
        gate, so the headline read "Review required" in the danger tone for a
        run whose exit code is clean.
        """
        model = _one_bandit_finding_model("warning", "svc", origin="workspace-policy")
        model.workspace = _workspace(
            tmp_path,
            _project("svc", policy_scanners_gate=False, policy_origin_finding_count=1),
        )

        summary = ReportContentEmitter(
            model, human_presentation=True
        ).get_scan_summary()

        assert summary["actionable"] == 0, summary
        assert summary["title"] == "No actionable findings", summary
        assert summary["tone"] == "success", summary

    def test_a_gating_policy_finding_is_actionable(self, tmp_path):
        """The control: with the policy's gate on the outcome counted it."""
        model = _one_bandit_finding_model("warning", "svc", origin="workspace-policy")
        model.workspace = _workspace(
            tmp_path,
            _project("svc", policy_scanners_gate=True, policy_origin_finding_count=1),
        )

        summary = ReportContentEmitter(
            model, human_presentation=True
        ).get_scan_summary()

        assert summary["actionable"] == 1, summary
        assert summary["title"] == "Review required", summary

    def test_a_policy_tag_without_the_origin_is_actionable(self, tmp_path):
        """The outcome reads the origin alone; a tag does not leave a finding out."""
        model = _one_bandit_finding_model("warning", "svc", tags=["workspace-policy"])
        model.workspace = _workspace(
            tmp_path, _project("svc", policy_scanners_gate=False)
        )

        summary = ReportContentEmitter(
            model, human_presentation=True
        ).get_scan_summary()

        assert summary["actionable"] == 1, summary


class TestAScannersGateIsResolvedOncePerScanner:
    def test_the_resolver_runs_once_however_many_times_findings_are_graded(
        self, monkeypatch
    ):
        """The summary, the hotspots, the cards and the detailed findings each
        grade every finding; the resolver dumps the whole scanners section per
        call, so it is asked once for a scanner and the answer is kept.

        RED at the base: one resolver call for every finding graded.
        """
        # Built first: constructing the emitter reads the scanners' metrics,
        # which ask the resolver too, and only the grading is counted here.
        emitter = ReportContentEmitter(_one_bandit_finding_model("note", "svc"))
        calls = []
        real = ScannerStatisticsCalculator.get_scanner_threshold_info

        def counting(model, scanner_name):
            calls.append(scanner_name)
            return real(model, scanner_name)

        monkeypatch.setattr(
            ScannerStatisticsCalculator,
            "get_scanner_threshold_info",
            staticmethod(counting),
        )

        for _ in range(3):
            emitter.is_finding_actionable(_vuln(scanner="bandit"))
        emitter.is_finding_actionable(_vuln(scanner="semgrep"))

        assert calls == ["bandit", "semgrep"], calls


class TestAWorkspaceFindingIsGradedByItsProjectsGate:
    @pytest.fixture
    def model(self, tmp_path) -> AshAggregatedResults:
        """One INFO finding in a project whose gate is ALL; no recorded config."""
        model = AshAggregatedResults()
        model.ash_config = None
        model.sarif = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "ASH"}},
                        "results": [
                            {
                                "ruleId": "RULE-STRICT",
                                "level": "none",
                                "message": {"text": "info-level finding"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/a.py"}
                                        }
                                    }
                                ],
                                "properties": {
                                    "scanner_name": "bandit",
                                    "workspace_project": "strict",
                                },
                            }
                        ],
                        "invocations": [],
                    }
                ],
            }
        )
        model.workspace = _workspace(
            tmp_path, _project("strict", severity_threshold="ALL")
        )
        return model

    def test_the_finding_is_actionable_under_the_projects_gate(self, model):
        emitter = ReportContentEmitter(model, human_presentation=True)
        (finding,) = emitter.flat_vulns
        assert finding.workspace_project == "strict"
        assert emitter.is_finding_actionable(finding)
        assert emitter.get_scan_summary()["actionable"] == 1

    def test_the_html_card_reads_actionable(self, model, test_plugin_context):
        document = HtmlReporter(context=test_plugin_context).report(model)
        assert 'data-status="actionable"' in document
        assert 'data-status="below-threshold"' not in document

    def test_the_headline_count_agrees_with_the_cards_when_scanner_rows_exist(
        self, model
    ):
        """The scanner rows grade by ASH's default; the headline must not.

        A merged workspace file carries scanner rows (the SARIF names bandit,
        and the merge writes ``scanner_results``), and each row's actionable
        count comes from the scanner resolver, which with no ash_config grades
        at ASH's default. Summing those rows into the headline read "0
        actionable" above a card marked actionable under the project's ALL.
        """
        model.scanner_results["bandit"] = ScannerTargetStatusInfo(duration=1.0)
        emitter = ReportContentEmitter(model, human_presentation=True)
        _assert_rows_grade_by_another_gate(emitter, model, "ALL")
        assert emitter.get_scan_summary()["actionable"] == 1

    def test_the_title_follows_the_recount_when_a_project_gate_is_stricter(
        self, tmp_path
    ):
        """A project gated at HIGH with one MEDIUM finding is not "Review required".

        The recount above fixed the headline's number and left its title on the
        rows: the bandit row, graded at ASH's default MEDIUM, reads FAILED, so
        the summary read title "Review required", tone danger, over the
        description "0 findings at or above the configured scanner
        thresholds". The title follows the recount now, as the description and
        the cards already did.
        """
        model = _one_medium_finding_model("svc")
        model.workspace = _workspace(
            tmp_path, _project("svc", severity_threshold="HIGH")
        )
        model.scanner_results["bandit"] = ScannerTargetStatusInfo(duration=1.0)
        emitter = ReportContentEmitter(model, human_presentation=True)
        _assert_rows_grade_by_another_gate(emitter, model, "HIGH")

        summary = emitter.get_scan_summary()

        assert summary["actionable"] == 0
        assert summary["title"] == "No actionable findings", summary
        assert summary["tone"] == "success", summary

    def test_a_coverage_gaps_tone_follows_the_recount_when_a_project_gate_is_stricter(
        self, tmp_path
    ):
        """The same project, with a coverage gap: the gap is a warning, not a danger.

        The gap's tone read the rows' FAILED status directly, so a project gated
        at HIGH with one MEDIUM finding and a partial scanner read "Scan
        incomplete" in the danger tone over "0 actionable findings". The tone
        follows the recount, as the title does.
        """
        model = _one_medium_finding_model("svc")
        model.workspace = _workspace(
            tmp_path, _project("svc", severity_threshold="HIGH")
        )
        model.scanner_results["bandit"] = ScannerTargetStatusInfo(duration=1.0)
        model.additional_reports["bandit"] = {
            "source": {
                "scanner_name": "bandit",
                "status": "PASSED",
                "duration": 1.0,
                "targets_attempted": 4,
                "targets_failed": 2,
            }
        }
        emitter = ReportContentEmitter(model, human_presentation=True)
        _assert_rows_grade_by_another_gate(emitter, model, "HIGH")

        summary = emitter.get_scan_summary()

        assert summary["actionable"] == 0
        assert summary["title"] == "Scan incomplete", summary
        assert summary["tone"] == "warning", summary

    def test_the_same_finding_in_a_single_directory_scan_needs_review(self):
        """The control: with no workspace the default gate grades it, and the
        title says so."""
        model = _one_medium_finding_model(None)
        model.scanner_results["bandit"] = ScannerTargetStatusInfo(duration=1.0)
        emitter = ReportContentEmitter(model, human_presentation=True)
        assert any(row["status"] == "FAILED" for row in emitter.get_scanner_results())

        summary = emitter.get_scan_summary()

        assert summary["actionable"] == 1
        assert summary["title"] == "Review required", summary
        assert summary["tone"] == "danger", summary

    def test_a_lowercase_recorded_gate_grades_as_its_upper_case_name(self, model):
        """A recorded ``"medium"`` grades at MEDIUM in every report.

        The JUnit reporter normalized the recorded gate and the emitter passed
        it to the case-sensitive ladder as stored, which read an unknown name
        as CRITICAL: the same finding was below threshold in the HTML report
        and actionable in the JUnit one.
        """
        model.workspace.projects[0].severity_threshold = "medium"
        emitter = ReportContentEmitter(model, human_presentation=True)
        (finding,) = emitter.flat_vulns
        assert not emitter.is_finding_actionable(finding), "INFO is below MEDIUM"
        finding.severity = "MEDIUM"
        assert emitter.is_finding_actionable(finding)

    @pytest.mark.parametrize(
        ("written", "severity"), [("all", "INFO"), ("low", "LOW")], ids=["all", "low"]
    )
    def test_a_lowercase_gate_below_the_default_grades_by_its_own_name(
        self, model, written, severity
    ):
        """``"medium"`` is also ASH's default gate, so the test above cannot tell
        a reader that normalizes the recorded name from one that ignores a name it
        does not know and falls back to the default; the old reading of an
        unknown name as CRITICAL is the only one it rules out. A gate below the
        default tells them apart: normalized, a finding at its level is
        actionable; under the default fallback or under CRITICAL it is not."""
        model.workspace.projects[0].severity_threshold = written
        emitter = ReportContentEmitter(model, human_presentation=True)
        (finding,) = emitter.flat_vulns
        finding.severity = severity
        assert emitter.is_finding_actionable(finding)

    def test_a_single_directory_finding_keeps_the_scanner_threshold(self):
        """The control: with no workspace the recorded config still decides."""
        emitter = ReportContentEmitter(AshAggregatedResults())
        assert not emitter.is_finding_actionable(_vuln(severity="INFO"))


class TestALowercaseRecordedGateLabelsAFindingActionableInEveryReport:
    """A project declared ``low`` fails on a LOW finding; the reports say so.

    The exit code upper-cases a project's gate before the ladder reads it. The
    emitter passed the recorded spelling to the case-sensitive ladder, which
    reads a name it does not know as CRITICAL, so the HTML, Markdown and text
    reports labelled a finding "below threshold" for a project the exit code
    failed. The three reports read one normalized table now. The gate and the
    finding are both below ASH's default (MEDIUM), so a reader that ignored the
    unknown name and fell back to the default would label the finding below
    threshold too, and the reports tell it from one that normalizes.
    """

    @pytest.fixture
    def model(self, tmp_path) -> AshAggregatedResults:
        model = AshAggregatedResults()
        model.ash_config = None
        model.sarif = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "ASH"}},
                        "results": [
                            {
                                "ruleId": "RULE-LOW",
                                "level": "note",
                                "message": {"text": "a low finding"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/a.py"}
                                        }
                                    }
                                ],
                                "properties": {
                                    "scanner_name": "bandit",
                                    "workspace_project": "lower",
                                },
                            }
                        ],
                        "invocations": [],
                    }
                ],
            }
        )
        model.workspace = _workspace(
            tmp_path, _project("lower", severity_threshold="low")
        )
        return model

    def test_the_html_card_is_actionable(self, model, test_plugin_context):
        document = HtmlReporter(context=test_plugin_context).report(model)
        assert 'data-status="actionable"' in document
        assert 'data-status="below-threshold"' not in document

    def test_the_markdown_summary_counts_it_actionable(
        self, model, test_plugin_context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
            MarkdownReporter,
        )

        document = MarkdownReporter(context=test_plugin_context).report(model)
        assert "**1 actionable**" in document
        assert "0 below threshold" in document

    def test_the_text_summary_counts_it_actionable(self, model, test_plugin_context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
            TextReporter,
        )

        document = TextReporter(context=test_plugin_context).report(model)
        assert "1 actionable | 0 below threshold" in document


class TestANoChangesSkipIsNotAnIncompleteScan:
    @staticmethod
    def _model(tmp_path, reason: SkippedProjectReason) -> AshAggregatedResults:
        model = AshAggregatedResults()
        model.scanner_results["bandit"] = ScannerTargetStatusInfo(duration=1.0)
        model.workspace = _workspace(
            tmp_path,
            _project("api"),
            _project(
                "docs",
                status=ProjectRunStatus.SKIPPED,
                skip_reason=reason,
                skip_detail="skip detail",
                severity_threshold=None,
            ),
        )
        return model

    def test_a_no_changes_skip_leaves_the_run_complete(self, tmp_path):
        summary = ReportContentEmitter(
            self._model(tmp_path, SkippedProjectReason.NO_CHANGES)
        ).get_scan_summary()
        # The exact reading: a clean no-op over a completed scanner. Any title
        # other than "Scan incomplete" would pass the weaker check, a "Review
        # required" over findings that do not exist among them.
        assert summary["title"] == "No actionable findings", summary
        assert summary["tone"] == "success", summary

    def test_an_error_skip_still_makes_the_run_incomplete(self, tmp_path):
        summary = ReportContentEmitter(
            self._model(tmp_path, SkippedProjectReason.ERROR)
        ).get_scan_summary()
        assert summary["title"] == "Scan incomplete", summary


class TestAScannerInErrorForAStaleDatabaseCounts:
    @staticmethod
    def _model() -> AshAggregatedResults:
        """grype ran against a database the fail policy rejects, and nothing else."""
        measured_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        record = ContentDbAgeRecord(
            name="grype-db",
            scanner="grype",
            built=measured_at - timedelta(days=400),
            measured_by="test",
            max_age=timedelta(days=1),
            measured_at=measured_at,
            policy="fail",
            bound_source="test",
            bound_is_tool_default=True,
            refresh="run grype db update",
        )
        assert record.enforced, "fixture: the record must fail the scan"
        model = AshAggregatedResults()
        model.sarif = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "grype"}},
                        "results": [],
                        "invocations": [
                            {
                                "executionSuccessful": True,
                                "toolConfigurationNotifications": [
                                    {
                                        "descriptor": {"id": STALE_NOTIFICATION_ID},
                                        "level": "error",
                                        "message": {"text": "stale"},
                                        "properties": {
                                            "content_database": record.to_dict()
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        model.additional_reports = {
            "grype": {
                "source": {
                    "scanner_name": "grype",
                    "status": "ERROR",
                    "duration": 1.0,
                    "rejected_content_databases": ["grype-db"],
                }
            }
        }
        return model

    def test_the_scanner_counts_as_completed_and_is_not_unavailable(self):
        summary = ReportContentEmitter(self._model()).get_scan_summary()
        assert summary["completed"] == 1, summary
        assert "grype" not in summary["unavailable"], summary
        # The fixture's record fails the scan, so the run exits non-zero. The
        # headline must not read as a clean pass: it names the database, in a
        # tone that is not success. (Any title but "No scanners completed" would
        # accept "No actionable findings" in the success tone, the disagreement
        # with the exit code this module exists to remove.)
        assert summary["title"] == "Scan needs attention", summary
        assert summary["tone"] != "success", summary
        assert summary["stale"], "the stale notice still names the database"

    def test_a_scanner_in_error_for_another_reason_still_needs_attention(self):
        model = AshAggregatedResults()
        model.additional_reports = {
            "grype": {
                "source": {"scanner_name": "grype", "status": "ERROR", "duration": 1.0}
            }
        }
        summary = ReportContentEmitter(model).get_scan_summary()
        assert summary["completed"] == 0
        assert "grype" in summary["unavailable"]


class TestASnippetIsTextOrNothing:
    @staticmethod
    def _snippet(raw) -> object:
        emitter = ReportContentEmitter(AshAggregatedResults())
        return emitter._extract_code_snippet(_vuln(raw_data=json.dumps(raw)))

    def test_an_object_snippet_yields_its_text(self):
        assert self._snippet({"snippet": {"text": "x = 1"}}) == "x = 1"

    def test_a_non_text_snippet_yields_nothing(self):
        assert self._snippet({"snippet": 5}) is None
        assert self._snippet({"snippet": {"binary": "AA=="}}) is None

    def test_a_string_snippet_is_returned_as_written(self):
        assert self._snippet({"snippet": "y = 2"}) == "y = 2"

    @pytest.mark.parametrize(
        "snippet",
        [{"text": 5}, {"text": ["x = 1"]}, {"text": None}, ["x = 1"], None],
        ids=repr,
    )
    def test_a_snippet_whose_text_is_not_a_string_yields_nothing(self, snippet):
        """The object form with a text that is no string: a reader that returns
        ``snippet.get("text")`` without a type check passes the cases above and
        still hands a number or a list to the renderer."""
        assert self._snippet({"snippet": snippet}) is None

    @pytest.mark.parametrize(
        "snippet", [5, {"text": 5}, {"text": ["x = 1"]}, ["x = 1"]], ids=repr
    )
    def test_the_markdown_report_renders_a_finding_whose_snippet_is_not_text(
        self, monkeypatch, test_plugin_context, snippet
    ):
        """The crash this guards was in the Markdown renderer, which passes the
        snippet to the shown-text helpers: it is tested there, not only at the
        private extractor."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
            MarkdownReporter,
        )

        vuln = _vuln(
            severity="HIGH",
            file_path="app.py",
            line_start=1,
            raw_data=json.dumps({"snippet": snippet}),
        )
        monkeypatch.setattr(
            AshAggregatedResults, "to_flat_vulnerabilities", lambda self: [vuln]
        )

        document = MarkdownReporter(context=test_plugin_context).report(
            AshAggregatedResults()
        )

        assert "a finding" in document, document[:2000]
