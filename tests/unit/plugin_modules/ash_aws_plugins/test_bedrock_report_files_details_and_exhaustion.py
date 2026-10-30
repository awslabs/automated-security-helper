# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""What the reporter writes for a clean scan, what its finding details show,
and what a run does after its fallback walk found nothing.

Each test here failed at the base. A run with no findings wrote no files, so
under ``ash report`` the previous run's files stayed in place and a configured
output file never existed for a clean scan; a secret finding's code snippet was
written into the details with include_code_snippets on; a suppressed finding
sat in the finding table with nothing to tell it from an analyzed one; and
after the fallback walk exhausted, every later section walked the whole chain
again.

No test here calls AWS: the sessions and clients are doubles.
"""

import botocore.exceptions
import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactContent,
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
    Suppression,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    MODULE,
    make_reporter,
    plugin_context_in,
)
from tests.unit.plugin_modules.ash_aws_plugins.test_bedrock_summary_reporter_paths import (
    finding,
    sarif_model,
)

pytestmark = pytest.mark.unit

SECRET_SNIPPET = "value = 'SECRET-SNIPPET-MARKER'"
BANDIT_SNIPPET = "subprocess.call(cmd, shell=True)  # BANDIT-SNIPPET-MARKER"


class RuntimeDouble:
    def __init__(self, failure=None):
        self.calls = []
        self.failure = failure

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        if self.failure is not None:
            raise self.failure
        return {
            "output": {
                "message": {"role": "assistant", "content": [{"text": "stub reply"}]}
            }
        }


class ControlPlaneDouble:
    """Lists no model; counts its listing calls."""

    def __init__(self):
        self.listings = 0

    def list_inference_profiles(self, **kwargs):
        return {"inferenceProfileSummaries": []}

    def list_foundation_models(self, **kwargs):
        self.listings += 1
        return {"modelSummaries": []}


def _session_double(runtime, control_plane):
    class SessionDouble:
        def __init__(self, **kwargs):
            pass

        def client(self, service, **kwargs):
            if service == "bedrock-runtime":
                return runtime
            if service == "bedrock":
                return control_plane
            raise AssertionError(service)

    return SessionDouble


def _result(rule_id, scanner, snippet=None, suppressed=False):
    """One result as the engine hands it on for ``scanner``, with a snippet
    and a suppression when asked."""
    tags = None
    if scanner == "detect-secrets":
        tags = ["detect-secrets", "secret", "tool_type::SECRETS"]
    region = Region(startLine=4, endLine=4)
    if snippet is not None:
        region = Region(startLine=4, endLine=4, snippet=ArtifactContent(text=snippet))
    result = Result(
        ruleId=rule_id,
        rule=ReportingDescriptorReference(id=rule_id),
        level=Level.error,
        message=Message(text=f"{rule_id} was reported"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="src/app.py"), region=region
                )
            )
        ],
        properties=PropertyBag(tags=tags) if tags else None,
        suppressions=[Suppression(kind="external")] if suppressed else None,
    )
    report = SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name=scanner)), results=[result])],
    )
    attach_scanner_details(report, scanner_name=scanner, scanner_version="1.0.0")
    return report.runs[0].results[0]


# ---------------------------------------------------------------------------
# A clean scan writes its files
# ---------------------------------------------------------------------------


def test_a_run_with_no_findings_writes_its_files_without_a_model_call(
    monkeypatch, tmp_path
):
    runtime = RuntimeDouble()
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session", _session_double(runtime, ControlPlaneDouble())
    )
    reporter = make_reporter(plugin_context_in(tmp_path), output_file="custom.md")

    text = reporter.report(sarif_model([]))

    reports = tmp_path / "reports"
    assert (reports / "custom.md").read_text(encoding="utf-8") == text
    executive = (reports / "bedrock-executive.md").read_text(encoding="utf-8")
    technical = (reports / "bedrock-technical.md").read_text(encoding="utf-8")
    assert "No actionable findings to analyze for this section." in executive
    assert "No actionable findings to analyze for this section." in technical
    assert runtime.calls == [], "a clean scan asks the model nothing"


def test_a_run_with_no_findings_and_markdown_off_writes_nothing(monkeypatch, tmp_path):
    """The control."""
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session",
        _session_double(RuntimeDouble(), ControlPlaneDouble()),
    )
    reporter = make_reporter(plugin_context_in(tmp_path), output_markdown=False)

    reporter.report(sarif_model([]))

    assert not (tmp_path / "reports").exists()


# ---------------------------------------------------------------------------
# The finding details
# ---------------------------------------------------------------------------


def test_a_secret_findings_snippet_is_not_written(monkeypatch, tmp_path):
    """With include_code_snippets on, the bandit finding's code is written and
    the secret finding's is not: its snippet is the credential."""
    runtime = RuntimeDouble()
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session", _session_double(runtime, ControlPlaneDouble())
    )
    reporter = make_reporter(plugin_context_in(tmp_path), include_code_snippets=True)
    model = sarif_model(
        [
            _result("B602", "bandit", snippet=BANDIT_SNIPPET),
            _result("AWS-KEY", "detect-secrets", snippet=SECRET_SNIPPET),
        ]
    )

    text = reporter.report(model)

    assert "BANDIT-SNIPPET-MARKER" in text
    assert "SECRET-SNIPPET-MARKER" not in text
    assert "Secret findings: 1" in runtime.calls[0]["messages"][0]["content"][0]["text"]


def test_a_suppressed_finding_is_marked_in_the_finding_table(monkeypatch, tmp_path):
    runtime = RuntimeDouble()
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session", _session_double(runtime, ControlPlaneDouble())
    )
    reporter = make_reporter(plugin_context_in(tmp_path))
    model = sarif_model([finding("R1"), _result("R2", "bandit", suppressed=True)])

    text = reporter.report(model)

    rows = [line for line in text.splitlines() if line.startswith("| ")]
    suppressed = [row for row in rows if "| R2 |" in row]
    analyzed = [row for row in rows if "| R1 |" in row]
    assert suppressed and "(suppressed)" in suppressed[0], rows
    assert analyzed and "(" not in analyzed[0], rows


# ---------------------------------------------------------------------------
# An exhausted walk is not walked again
# ---------------------------------------------------------------------------


def test_a_later_section_does_not_walk_an_exhausted_chain_again(monkeypatch, tmp_path):
    """The configured model fails on every call and no fallback is listed. The
    first section walks the chain and exhausts it; the second calls the
    configured model once more and gets the exhaustion back without a second
    listing or a second walk."""
    refusal = botocore.exceptions.ClientError(
        {"Error": {"Code": "ValidationException", "Message": "too long"}}, "Converse"
    )
    runtime = RuntimeDouble(failure=refusal)
    control_plane = ControlPlaneDouble()
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session", _session_double(runtime, control_plane)
    )
    reporter = make_reporter(plugin_context_in(tmp_path), max_retries=0)
    client = reporter._make_model_client(runtime)

    first = reporter._outcome_with_fallback(client, "prompt one", "system")
    calls_after_first = len(runtime.calls)
    second = reporter._outcome_with_fallback(client, "prompt two", "system")

    assert first.ok is False and "No suitable fallback model found" in first.text
    assert second.ok is False and "No suitable fallback model found" in second.text
    assert control_plane.listings == 1, "the chain was listed once"
    assert len(runtime.calls) == calls_after_first + 1, (
        "the second section called the configured model once and no candidate"
    )
