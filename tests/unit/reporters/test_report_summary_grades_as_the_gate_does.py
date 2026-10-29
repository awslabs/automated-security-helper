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

    def test_a_single_directory_finding_keeps_the_scanner_threshold(self):
        """The control: with no workspace the recorded config still decides."""
        emitter = ReportContentEmitter(AshAggregatedResults())
        assert not emitter.is_finding_actionable(_vuln(severity="INFO"))


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
        assert summary["title"] != "Scan incomplete", summary

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
        assert summary["title"] != "No scanners completed", summary
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
