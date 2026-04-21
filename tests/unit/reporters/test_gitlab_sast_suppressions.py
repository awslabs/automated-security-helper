"""Test that GitLab SAST reporter handles suppressed findings correctly."""

import json
import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporter,
    GitLabSASTReporterConfig,
    GitLabSASTReporterConfigOptions,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Result,
    Suppression,
)


def _make_result(rule_id, level, text, suppressed=False, justification=None):
    r = Result(ruleId=rule_id, level=level, message={"text": text})
    if suppressed:
        r.suppressions = [
            Suppression(
                kind="inSource",
                justification=justification or "Suppressed by test",
            )
        ]
    return r


@pytest.fixture
def plugin_context(tmp_path):
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=AshConfig(),
    )


@pytest.fixture
def model_with_suppressed_finding():
    model = AshAggregatedResults()
    model.sarif.runs[0].results = [
        _make_result(
            "B101",
            "warning",
            "Assert used",
            suppressed=True,
            justification="Assertions used for pytest",
        ),
        _make_result("B201", "error", "Flask debug", suppressed=False),
    ]
    return model


class TestGitLabSASTSuppressions:
    def test_suppressed_findings_downgraded_to_info(
        self, plugin_context, model_with_suppressed_finding
    ):
        """Suppressed findings should appear with Info severity."""
        reporter = GitLabSASTReporter(context=plugin_context)
        report = json.loads(reporter.report(model_with_suppressed_finding))

        vulns = {v["name"]: v for v in report["vulnerabilities"]}
        assert vulns["B101"]["severity"] == "Info"
        assert vulns["B201"]["severity"] == "High"

    def test_suppressed_findings_have_solution(
        self, plugin_context, model_with_suppressed_finding
    ):
        """Suppressed findings should include the suppression reason in solution."""
        reporter = GitLabSASTReporter(context=plugin_context)
        report = json.loads(reporter.report(model_with_suppressed_finding))

        vulns = {v["name"]: v for v in report["vulnerabilities"]}
        assert "solution" in vulns["B101"]
        assert "Assertions used for pytest" in vulns["B101"]["solution"]
        assert "solution" not in vulns["B201"]

    def test_all_findings_included_by_default(
        self, plugin_context, model_with_suppressed_finding
    ):
        """Both suppressed and active findings should be in the report."""
        reporter = GitLabSASTReporter(context=plugin_context)
        report = json.loads(reporter.report(model_with_suppressed_finding))
        assert len(report["vulnerabilities"]) == 2

    def test_exclude_suppressed_when_configured(
        self, plugin_context, model_with_suppressed_finding
    ):
        """When exclude_suppressed=True, suppressed findings are excluded."""
        config = GitLabSASTReporterConfig(
            options=GitLabSASTReporterConfigOptions(exclude_suppressed=True),
        )
        reporter = GitLabSASTReporter(context=plugin_context, config=config)
        report = json.loads(reporter.report(model_with_suppressed_finding))

        rule_ids = [v["name"] for v in report["vulnerabilities"]]
        assert "B201" in rule_ids
        assert "B101" not in rule_ids

    def test_exclude_all_suppressed(self, plugin_context):
        """When all findings are suppressed and exclusion is on, report is empty."""
        model = AshAggregatedResults()
        model.sarif.runs[0].results = [
            _make_result("B101", "warning", "Assert", suppressed=True),
        ]
        config = GitLabSASTReporterConfig(
            options=GitLabSASTReporterConfigOptions(exclude_suppressed=True),
        )
        reporter = GitLabSASTReporter(context=plugin_context, config=config)
        report = json.loads(reporter.report(model))

        assert len(report["vulnerabilities"]) == 0
        assert report["scan"]["status"] == "success"
