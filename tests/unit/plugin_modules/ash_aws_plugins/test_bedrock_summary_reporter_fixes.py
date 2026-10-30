# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Bedrock summary reporter's walk, cache, sections and summaries.

Each test here failed at the base and pins one defect of
``bedrock_summary_reporter``: the fallback walk calling further models after a
failure no model answers; the answer cache surviving into a second report();
HTML kept raw inside a code span that holds a table pipe; the dependency check
validating only the first fallback; the simple report's total reading as the
limit; a non-secret excluded type reported as a potential secret; the
summarized findings losing severities, locations and raw evidence; a failed
batch fed to the synthesis as a summary; the builders' placeholders sent to the
model as prompts; and the region pattern refusing published region names.

No test here calls AWS: boto3's session is a double, the model runtime answers by
plan, and the control plane is a MagicMock.
"""

import json
from unittest.mock import MagicMock

import botocore.exceptions
import pytest
from pydantic import ValidationError

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
    CallOutcome,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporterConfigOptions,
    _markdown_as_written,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    ReportingDescriptorReference,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from tests.unit.plugin_modules.ash_aws_plugins.test_bedrock_summary_reporter_paths import (
    FALLBACK_ONE,
    FALLBACK_TWO,
    MODULE,
    PRIMARY_MODEL,
    context,  # noqa: F401  (fixture)
    finding,
    make_reporter,
    sarif_model,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Doubles
# ---------------------------------------------------------------------------


class Runtime:
    """A bedrock-runtime client: converse() answers ``plan`` in order (a text or
    an exception) and records every request."""

    def __init__(self, *plan):
        self.plan = list(plan)
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        step = self.plan.pop(0) if self.plan else "answer"
        if isinstance(step, BaseException):
            raise step
        return {
            "output": {"message": {"role": "assistant", "content": [{"text": step}]}}
        }

    def prompts(self):
        return [call["messages"][0]["content"][0]["text"] for call in self.calls]


class Session:
    """A boto3.Session stand-in handing out the clients it was given."""

    def __init__(self, **clients):
        self.clients = clients

    def __call__(self, **kwargs):
        return self

    def client(self, service, **kwargs):
        return self.clients[service]


def _model_summary(model_id):
    return {
        "modelId": model_id,
        "modelName": "placeholder",
        "modelArn": f"arn:aws:bedrock:::{model_id}",
        "providerName": "placeholder",
        "modelLifecycle": {"status": "ACTIVE"},
        "inputModalities": ["TEXT"],
        "outputModalities": ["TEXT"],
        "inferenceTypesSupported": ["ON_DEMAND"],
    }


def _control_plane(*listed):
    control = MagicMock()
    control.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    control.list_foundation_models.return_value = {
        "modelSummaries": [_model_summary(model) for model in listed]
    }
    return control


def _sts():
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    return sts


def _run(reporter, monkeypatch, runtime, *results):
    """report() with the runtime as the run's bedrock-runtime client."""
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session",
        Session(**{"bedrock-runtime": runtime, "bedrock": _control_plane()}),
    )
    return reporter.report(sarif_model(list(results)))


def _tagged_finding(rule_id, scanner, tool_type):
    """A result from ``scanner`` whose tags say its type, as a few scanners write."""
    result = Result(
        ruleId=rule_id,
        rule=ReportingDescriptorReference(id=rule_id),
        level=Level.error,
        message=Message(text=f"{rule_id} was reported"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="infra/main.tf"),
                    region=Region(startLine=1, endLine=2),
                )
            )
        ],
        properties=PropertyBag(tags=[f"tool_type::{tool_type}"]),
    )
    report = SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name=scanner)), results=[result])],
    )
    attach_scanner_details(report, scanner_name=scanner, scanner_version="1.0.0")
    return report.runs[0].results[0]


# ---------------------------------------------------------------------------
# The fallback walk stops at a failure no model answers
# ---------------------------------------------------------------------------


def test_the_walk_ends_on_a_failure_no_other_model_answers(context, monkeypatch):  # noqa: F811
    """A candidate that fails with no connection or no credentials fails every
    later candidate the same way: the walk returns that error as it is instead
    of calling the rest of the chain and ending on the exhaustion text."""
    reporter = make_reporter(context, enable_caching=False)
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: FALLBACK_TWO}.get,
    )
    monkeypatch.setattr(
        f"{MODULE}.validate_bedrock_model", lambda *a, **k: (True, None)
    )
    called = []

    def call_model(model):
        called.append(model)
        return CallOutcome(
            "*Error generating content with model x: NoCredentialsError: none*",
            ok=False,
            model_specific=False,
        )

    out = reporter._walk_fallbacks(
        _control_plane(), PRIMARY_MODEL, call_model, primary_error="*Error: first*"
    )

    assert called == [FALLBACK_ONE], called
    assert "NoCredentialsError" in out, out
    assert "No suitable fallback model found" not in out, out


def test_the_walk_goes_on_past_a_failure_only_that_model_gave(context, monkeypatch):  # noqa: F811
    """The control for the early return: a model-specific failure (a refused
    request, a model not ready) says nothing about the next candidate, so the
    walk calls the whole chain and ends on the exhaustion text. A walk that
    returned after the first fallback whatever the failure would fail here."""
    reporter = make_reporter(context, enable_caching=False)
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: FALLBACK_TWO}.get,
    )
    monkeypatch.setattr(
        f"{MODULE}.validate_bedrock_model", lambda *a, **k: (True, None)
    )
    called = []

    def call_model(model):
        called.append(model)
        return CallOutcome(
            f"*Error generating content with model {model}: ValidationException: refused*",
            ok=False,
            model_specific=True,
        )

    out = reporter._walk_fallbacks(
        _control_plane(), PRIMARY_MODEL, call_model, primary_error="*Error: first*"
    )

    assert called == [FALLBACK_ONE, FALLBACK_TWO], called
    assert "No suitable fallback model found" in out, out


# ---------------------------------------------------------------------------
# One run's cache
# ---------------------------------------------------------------------------


def test_a_second_report_does_not_read_the_first_runs_answers(context, monkeypatch):  # noqa: F811
    reporter = make_reporter(
        context, add_section_headers=False, output_markdown=False, enable_caching=True
    )
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session",
        Session(**{"bedrock-runtime": Runtime("first run", "second run")}),
    )

    # One model reported twice: the prompts are the same both times, so a
    # cache that survived into the second run would answer "first run" whatever
    # its key is made of (two different models would miss the cache anyway).
    model = sarif_model([finding("R1")])

    first = reporter.report(model)
    second = reporter.report(model)

    assert "first run" in first and "first run" not in second, second
    assert "second run" in second, second


# ---------------------------------------------------------------------------
# HTML inside a code span across a table pipe
# ---------------------------------------------------------------------------


def test_html_in_a_code_span_that_holds_a_table_pipe_is_written_as_text():
    """A GitHub viewer splits a table's row at the pipe before reading the span,
    so the tag after the pipe would be outside any span and render. The row
    sits in a table (a header and a delimiter row before it): a lone line with
    pipes is prose to the viewer and is left as written."""
    table = "| rule | note |\n|---|---|\n| rule | `x | <img src=x onerror=alert(1)>` |"

    written = _markdown_as_written(table)

    assert "<img" not in written, written
    assert "&lt;img" in written, written


def test_html_in_a_code_span_without_a_pipe_stays_as_the_model_wrote_it():
    """The control: the existing rule, a span is code and its HTML is text
    already."""
    text = "use `<b>` for bold"

    assert _markdown_as_written(text) == text


# ---------------------------------------------------------------------------
# The dependency check walks the whole chain
# ---------------------------------------------------------------------------


def test_the_dependency_check_accepts_a_later_fallback(context, monkeypatch):  # noqa: F811
    """Only the second fallback is listed: the run would reach it, so the check
    does too instead of disabling the reporter."""
    control = _control_plane(FALLBACK_TWO)
    monkeypatch.setattr(f"{MODULE}.boto3.Session", Session(sts=_sts(), bedrock=control))
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: FALLBACK_TWO}.get,
    )
    reporter = make_reporter(context, enable_fallback_models=True)

    assert reporter.validate_plugin_dependencies() is True, reporter.errors
    # One listing serves the configured model's check and the chain's walk
    # (ListingsOnce wraps the client before the first check).
    assert control.list_inference_profiles.call_count == 1


# ---------------------------------------------------------------------------
# The simple report's total is the whole list's
# ---------------------------------------------------------------------------


def test_the_simple_reports_total_is_the_whole_list(context, monkeypatch):  # noqa: F811
    reporter = make_reporter(
        context,
        add_section_headers=False,
        output_markdown=False,
        max_findings_to_analyze=2,
    )
    runtime = Runtime("summary")

    _run(reporter, monkeypatch, runtime, *[finding(f"R{i}") for i in range(5)])

    (prompt,) = runtime.prompts()
    assert "Total actionable findings: 5" in prompt, prompt
    assert prompt.count("\nFINDING ") == 2, prompt


# ---------------------------------------------------------------------------
# A non-secret excluded type is not a potential secret
# ---------------------------------------------------------------------------


def test_an_excluded_non_secret_type_is_left_out_not_called_a_secret(context):  # noqa: F811
    reporter = make_reporter(context, exclude_scanner_types=["IAC"])
    model = sarif_model(
        [finding("B1", scanner="bandit"), _tagged_finding("CKV_1", "checkov", "IAC")]
    )

    all_findings, secret_findings, _indexed = reporter._extract_findings(model)

    assert [f["ruleId"] for f in all_findings] == ["B1"], all_findings
    assert secret_findings == [], secret_findings
    assert reporter._secret_findings_exist is False


# ---------------------------------------------------------------------------
# Summaries keep severities, locations and evidence
# ---------------------------------------------------------------------------


def _instance(rule_id, severity, uri):
    return {
        "ruleId": rule_id,
        "level": "error",
        "severity": severity,
        "message": {"text": f"{rule_id} happened"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
    }


def test_summaries_group_by_rule_and_severity_and_carry_every_location(context):  # noqa: F811
    reporter = make_reporter(context, summarize_findings=True)
    findings = [
        _instance("R1", "LOW", "src/a.py"),
        _instance("R1", "LOW", "src/b.py"),
        _instance("R1", "CRITICAL", "src/c.py"),
    ]

    summarized = reporter._summarize_findings(findings)

    by_severity = {reporter._finding_severity(f): f for f in summarized}
    assert set(by_severity) == {"LOW", "CRITICAL"}, summarized
    low = by_severity["LOW"]
    assert low["properties"]["original_count"] == 2
    assert [
        loc["physicalLocation"]["artifactLocation"]["uri"] for loc in low["locations"]
    ] == ["src/a.py", "src/b.py"]
    assert "properties" not in by_severity["CRITICAL"]


def test_the_evidence_section_keeps_every_instances_raw_json(context, monkeypatch):  # noqa: F811
    reporter = make_reporter(
        context,
        summarize_findings=True,
        output_markdown=False,
        include_sections=["executive_summary"],
    )

    report = _run(
        reporter,
        monkeypatch,
        Runtime(),
        *[finding("R1", uri=f"src/{i}.py") for i in range(3)],
    )

    assert report.count("<summary>Raw JSON</summary>") == 3, report


# ---------------------------------------------------------------------------
# A failed batch is named, not synthesized
# ---------------------------------------------------------------------------


def test_a_failed_batch_is_named_and_kept_out_of_the_synthesis(context, monkeypatch):  # noqa: F811
    reporter = make_reporter(
        context,
        batch_processing=True,
        max_findings_to_analyze=1,
        enable_fallback_models=False,
        enable_caching=False,
    )
    runtime = Runtime(
        botocore.exceptions.ClientError(
            {"Error": {"Code": "ValidationException", "Message": "too long"}},
            "Converse",
        ),
        "batch two summary",
        "the synthesis",
    )
    findings = [
        _instance("R1", "HIGH", "src/a.py"),
        _instance("R2", "HIGH", "src/b.py"),
    ]

    out = reporter._process_findings_by_batch(runtime, sarif_model([]), findings)

    # The whole third request (system, every message and block), not only the
    # first text block: the failure must reach the synthesis by no route.
    assert len(runtime.calls) == 3, runtime.calls
    synthesis_request = json.dumps(runtime.calls[2], default=str)
    for text in ("*Error", "too long", "ValidationException"):
        assert text not in synthesis_request, synthesis_request
    assert "batch two summary" in synthesis_request
    assert "the synthesis" in out, out
    assert "Batch 1 of 2 was not summarized" in out, out


# ---------------------------------------------------------------------------
# Nothing to analyze is report text, never a prompt
# ---------------------------------------------------------------------------


def test_a_secrets_only_scan_sends_no_placeholder_prompt(context, monkeypatch):  # noqa: F811
    reporter = make_reporter(
        context,
        output_markdown=False,
        compliance_frameworks=["SOC 2"],
        group_by_severity=False,
        # The secret advice is a section of its own; it is asked for only when
        # the section is included, which the default list does not do.
        include_sections=[
            "executive_summary",
            "risk_assessment",
            "compliance_impact",
            "secret_findings",
        ],
    )
    runtime = Runtime()

    report = _run(
        reporter, monkeypatch, runtime, finding("S1", scanner="detect-secrets")
    )

    placeholders = (
        "No findings to analyze",
        "No findings to assess risk",
        "No compliance frameworks specified",
    )
    # Checked over each whole request (system, every message and block), so a
    # placeholder routed through any part of the request is caught.
    for call in runtime.calls:
        request = json.dumps(call, default=str)
        assert not any(text in request for text in placeholders), request
    assert "No actionable findings to analyze for this section." in report, report
    assert "The secret findings are reported in their own section." in report, report
    # The secret advice is still asked for: those findings exist.
    assert any("potential secrets" in prompt for prompt in runtime.prompts())


# ---------------------------------------------------------------------------
# The region pattern admits every published region name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "region",
    [
        "mx-central-1",
        "us-isof-south-1",
        "eu-isoe-west-1",
        "eusc-de-east-1",
        "us-east-1",
    ],
)
def test_a_published_region_name_is_accepted(region):
    options = BedrockSummaryReporterConfigOptions(aws_region=region)

    assert options.aws_region == region


def test_a_name_that_is_no_region_is_still_refused():
    with pytest.raises(ValidationError):
        BedrockSummaryReporterConfigOptions(aws_region="nowhere-1")
