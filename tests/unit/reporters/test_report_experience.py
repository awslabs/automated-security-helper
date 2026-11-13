# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Outcome accuracy and literal text across ASH's human-readable reports."""

import pytest
from unittest.mock import patch

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
    MarkdownReporterConfig,
    MarkdownReporterConfigOptions,
    _code_block,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Invocation,
    Message,
    PropertyBag,
    Result,
)
from automated_security_helper.cli.inspect.inspect_findings_app import extract_findings

pytestmark = pytest.mark.unit


def model_with_finding():
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [
        Result(
            ruleId="R1",
            level="error",
            message=Message(text="Review the fixture"),
            properties=PropertyBag(scanner_name="bandit"),
        )
    ]
    model.ash_config.global_settings.severity_threshold = "CRITICAL"
    return model


def test_critical_threshold_finding_is_visible_in_human_details_without_changing_flat_export():
    model = model_with_finding()
    original = model.to_flat_vulnerabilities()[0].model_dump()
    emitter = ReportContentEmitter(model, human_presentation=True)
    summary = emitter.get_scan_summary()
    details = emitter.get_detailed_findings()
    assert summary["counts"]["critical"] == 1
    assert summary["actionable"] == 1
    assert len(details) == 1
    assert details[0]["severity"] == "CRITICAL"
    assert extract_findings(model)[0]["severity"] == "critical"
    assert model.to_flat_vulnerabilities()[0].model_dump() == original
    assert ReportContentEmitter(model).flat_vulns[0].severity == original["severity"]


def test_empty_report_makes_no_clean_scan_claim(test_plugin_context):
    model = AshAggregatedResults()
    summary = ReportContentEmitter(model, human_presentation=True).get_scan_summary()
    assert summary["title"] == "No scanners completed"
    assert summary["tone"] == "warning"
    assert "No scanners completed" in HtmlReporter(context=test_plugin_context).report(
        model
    )
    assert "No scanners completed" in MarkdownReporter(
        context=test_plugin_context
    ).report(model)


@pytest.mark.parametrize("compact", [True, False])
def test_partial_coverage_remains_visible_when_summary_is_disabled(
    compact, test_plugin_context
):
    model = model_with_finding()
    model.additional_reports["bandit"] = {
        "source": {
            "scanner_name": "bandit",
            "status": "PASSED",
            "duration": 1.0,
            "targets_attempted": 4,
            "targets_failed": 2,
        },
    }
    reporter = MarkdownReporter(
        context=test_plugin_context,
        config=MarkdownReporterConfig(
            options=MarkdownReporterConfigOptions(
                compact=compact,
                include_summary=False,
            )
        ),
    )
    report = reporter.report(model)
    assert "Scan incomplete" in report
    assert "Incomplete coverage" in report
    assert "evaluated 2 of 4" in report


@pytest.mark.parametrize("gap", ["converter", "rule"])
def test_coverage_gaps_do_not_look_clean_when_scanners_find_nothing(
    gap, test_plugin_context
):
    model = model_with_finding()
    model.sarif.runs[0].results = []
    model.additional_reports["bandit"] = {
        "source": {"scanner_name": "bandit", "status": "PASSED", "duration": 1.0}
    }
    if gap == "converter":
        model.converter_results["jupyter"] = ConverterStatusInfo(
            converted_paths=[], failure="Notebook conversion failed"
        )
        expected = "jupyter"
    else:
        model.sarif.runs[0].invocations = [
            Invocation.model_validate(
                {
                    "executionSuccessful": True,
                    "toolExecutionNotifications": [
                        {
                            "level": "error",
                            "associatedRule": {"id": "RULE-NOT-EVALUATED"},
                            "message": {"text": "Fixture rule reached no verdict"},
                        }
                    ],
                }
            )
        ]
        expected = "RULE-NOT-EVALUATED"
    summary = ReportContentEmitter(model, human_presentation=True).get_scan_summary()
    assert summary["completed"] == 1
    assert summary["actionable"] == 0
    assert summary["title"] == "Scan incomplete"
    for reporter in (
        HtmlReporter(context=test_plugin_context),
        MarkdownReporter(
            context=test_plugin_context,
            config=MarkdownReporterConfig(
                options=MarkdownReporterConfigOptions(
                    compact=True, include_summary=False
                )
            ),
        ),
        TextReporter(context=test_plugin_context),
    ):
        document = reporter.report(model)
        assert "SCAN INCOMPLETE" in document.upper()
        assert expected in document
    with patch(
        "automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter.boto3.Session"
    ) as session:
        document = BedrockSummaryReporter(context=test_plugin_context).report(model)
        assert "Scan incomplete" in document
        assert expected in document
        session.assert_not_called()


def test_report_escapes_scanner_text_and_does_not_load_external_assets(
    test_plugin_context,
):
    model = model_with_finding()
    model.sarif.runs[0].results[0].message = Message(
        text='<script>alert("fixture")</script> | [link](https://example.com)'
    )
    model._flat_cache = None
    document = HtmlReporter(context=test_plugin_context).report(model)
    assert '<script>alert("fixture")</script>' not in document
    assert "&lt;script&gt;alert" in document
    assert "<script src=" not in document
    assert '<link href="http' not in document
    assert '<html lang="en"' in document
    assert 'name="viewport"' in document


def test_scanner_code_cannot_close_the_markdown_fence():
    snippet = "before\n````\n<script>fixture</script>\nafter"
    assert _code_block(snippet) == f"`````\n{snippet}\n`````"
