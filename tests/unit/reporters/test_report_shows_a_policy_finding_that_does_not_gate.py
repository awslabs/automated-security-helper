# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A policy-scanner finding the project's outcome left out is reported as such.

A scanner only the workspace policy added reports its findings, and when the
project's ``policy_scanners_gate`` is off the outcome leaves them out. The
report emitter graded such a finding not actionable, and every report then
filed it with the findings below the threshold: the HTML card read "Below
threshold" and was hidden by the default view, and the masthead and the text
and Markdown summaries counted it with the low-severity findings the threshold
sets aside, whatever its severity. The merged JUnit report gives the same
finding its own skip type.

The finding keeps its own status in every report, is shown by the default view
of the HTML report, and is counted apart.
"""

import re
from pathlib import Path

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters import html_reporter
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit


def _result(rule: str, level: str, **properties) -> dict:
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": f"finding {rule}"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f"src/{rule}.py"}}}
        ],
        "properties": {
            "scanner_name": "bandit",
            "workspace_project": "svc",
            **properties,
        },
    }


def _model(tmp_path, results: list, **project_fields) -> AshAggregatedResults:
    """A workspace run of project ``svc`` (gate HIGH) holding *results*."""
    model = AshAggregatedResults()
    model.ash_config = None
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": results,
                    "invocations": [],
                }
            ],
        }
    )
    model.scanner_results["bandit"] = ScannerTargetStatusInfo(duration=1.0)
    model.workspace = WorkspaceResults(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        exit_code=0,
        projects=[
            WorkspaceProjectResult(
                project="svc",
                relative_path="svc",
                display_label="svc",
                status=ProjectRunStatus.COMPLETED,
                severity_threshold="HIGH",
                output_path="projects/svc",
                **project_fields,
            )
        ],
    )
    return model


def _critical_policy_finding() -> dict:
    # SARIF "error" reads CRITICAL (severity_ladder), above the project's HIGH gate.
    return _result("POLICY-CRIT", "error", origin="workspace-policy")


def _low_ordinary_finding() -> dict:
    return _result("PLAIN-LOW", "note")


@pytest.fixture
def not_gating_model(tmp_path):
    """A CRITICAL policy finding (policy gate off) and a LOW ordinary one."""
    return _model(
        tmp_path,
        [_critical_policy_finding(), _low_ordinary_finding()],
        policy_scanners_gate=False,
        policy_origin_finding_count=1,
    )


@pytest.fixture
def gating_model(tmp_path):
    """The control: the same findings, with the policy's gate on."""
    return _model(
        tmp_path,
        [_critical_policy_finding(), _low_ordinary_finding()],
        policy_scanners_gate=True,
        policy_origin_finding_count=1,
    )


def _card_statuses(document: str) -> dict:
    """Each card's rule id mapped to its data-status."""
    statuses = {}
    for card in re.findall(
        r'<article class="finding-card".*?</article>', document, re.DOTALL
    ):
        status = re.search(r'data-status="([^"]*)"', card).group(1)
        rule = re.search(r"<code>([A-Z]+-[A-Z]+)</code>", card).group(1)
        statuses[rule] = status
    return statuses


class TestTheEmitterCountsItApart:
    def test_a_critical_finding_of_a_non_gating_policy_has_its_own_count(
        self, not_gating_model
    ):
        """RED at the base: ``policy_not_gating`` is not in the summary and the
        finding is counted in ``below_threshold`` (2 there, not 1)."""
        emitter = ReportContentEmitter(not_gating_model, human_presentation=True)

        summary = emitter.get_scan_summary()

        assert summary["actionable"] == 0, summary
        assert summary["policy_not_gating"] == 1, summary
        # The ordinary LOW finding is the only one below the threshold.
        assert summary["below_threshold"] == 1, summary

    def test_the_finding_is_told_apart_from_a_below_threshold_one(
        self, not_gating_model
    ):
        emitter = ReportContentEmitter(not_gating_model, human_presentation=True)

        by_rule = {vuln.rule_id: vuln for vuln in emitter.flat_vulns}

        assert emitter.is_policy_not_gating(by_rule["POLICY-CRIT"])
        assert not emitter.is_policy_not_gating(by_rule["PLAIN-LOW"])
        # Neither is actionable; only one is not gating.
        assert not emitter.is_finding_actionable(by_rule["POLICY-CRIT"])
        assert not emitter.is_finding_actionable(by_rule["PLAIN-LOW"])

    def test_a_gating_policy_finding_is_actionable_and_not_counted_apart(
        self, gating_model
    ):
        """The control: with the policy's gate on the outcome counted it."""
        summary = ReportContentEmitter(
            gating_model, human_presentation=True
        ).get_scan_summary()

        assert summary["actionable"] == 1, summary
        assert summary["policy_not_gating"] == 0, summary
        assert summary["below_threshold"] == 1, summary

    def test_a_suppressed_policy_finding_is_not_counted_apart(self, tmp_path):
        """A suppressed finding is counted as suppressed, whatever its origin."""
        suppressed = _critical_policy_finding()
        suppressed["suppressions"] = [{"kind": "external", "justification": "ok"}]
        model = _model(
            tmp_path,
            [suppressed],
            policy_scanners_gate=False,
            policy_origin_finding_count=1,
        )

        emitter = ReportContentEmitter(model, human_presentation=True)
        (vuln,) = emitter.flat_vulns

        assert vuln.is_suppressed
        assert not emitter.is_policy_not_gating(vuln)
        assert emitter.get_scan_summary()["policy_not_gating"] == 0


class TestTheHtmlReportShowsIt:
    def test_the_card_has_its_own_status_and_label(
        self, not_gating_model, test_plugin_context
    ):
        """RED at the base: the CRITICAL card read ``below-threshold``."""
        document = HtmlReporter(context=test_plugin_context).report(not_gating_model)

        statuses = _card_statuses(document)
        assert statuses["POLICY-CRIT"] == "policy-not-gating", statuses
        assert statuses["PLAIN-LOW"] == "below-threshold", statuses
        assert '<span class="finding-status">Not gating (workspace policy)</span>' in (
            document
        )

    def test_the_masthead_counts_it_apart(self, not_gating_model, test_plugin_context):
        document = HtmlReporter(context=test_plugin_context).report(not_gating_model)

        assert re.search(r"<dt>Not gating</dt><dd>1<", document)
        # The one below-threshold finding is the ordinary LOW one.
        assert re.search(r"<dt>Below threshold</dt><dd>1<", document)

    def test_the_default_view_shows_it(self):
        """The default scope is "Actionable"; the script must keep the status
        in it (the script runs in a browser, so it is read as text)."""
        script = Path(html_reporter.__file__).parent / "assets" / "ash-report.js"
        text = script.read_text(encoding="utf-8")

        assert 'scope.value === "actionable" && status === "policy-not-gating"' in text
        # The "All active" scope shows every status but suppressed.
        assert 'scope.value === "active" && status !== "suppressed"' in text

    def test_a_report_without_one_has_no_such_tile_or_status(
        self, tmp_path, test_plugin_context
    ):
        """The control: the page is what it was when no finding is left out."""
        model = _model(tmp_path, [_low_ordinary_finding()], policy_scanners_gate=False)

        document = HtmlReporter(context=test_plugin_context).report(model)

        assert "Not gating" not in document
        assert 'data-status="policy-not-gating"' not in document
        assert _card_statuses(document) == {"PLAIN-LOW": "below-threshold"}

    def test_a_gating_policy_finding_reads_actionable(
        self, gating_model, test_plugin_context
    ):
        document = HtmlReporter(context=test_plugin_context).report(gating_model)

        assert _card_statuses(document)["POLICY-CRIT"] == "actionable"
        assert "Not gating" not in document


class TestTheTextAndMarkdownSummariesCountItApart:
    def test_the_text_summary_line(self, not_gating_model, test_plugin_context):
        out = TextReporter(context=test_plugin_context).report(not_gating_model)

        assert (
            "0 actionable | 1 below threshold | 1 not gating (workspace policy) | "
            in out
        ), out

    def test_the_text_summary_line_is_unchanged_without_one(
        self, gating_model, test_plugin_context
    ):
        out = TextReporter(context=test_plugin_context).report(gating_model)

        assert "1 actionable | 1 below threshold | 0 suppressed" in out, out
        assert "not gating" not in out

    def test_the_markdown_summary_line(self, not_gating_model, test_plugin_context):
        out = MarkdownReporter(context=test_plugin_context).report(not_gating_model)

        assert (
            "1 below threshold · 1 not gating (workspace policy) · 0 suppressed" in out
        ), out

    def test_the_markdown_summary_line_is_unchanged_without_one(
        self, gating_model, test_plugin_context
    ):
        out = MarkdownReporter(context=test_plugin_context).report(gating_model)

        assert "1 below threshold · 0 suppressed" in out, out
        assert "not gating" not in out
