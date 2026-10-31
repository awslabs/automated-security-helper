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
again. What a run keeps from an exhausted walk is what is settled about the
models: the candidates the listing does not name, and the candidates Converse
refused as not permitted or not found. A throttled listing is asked again by
the next section, as the walk tests already pin, and a candidate that failed on
one section's prompt is called again with the next one.

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
    PRIMARY_MODEL,
    finding,
    make_reporter,
    plugin_context_in,
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


def _summary(model_id):
    return {
        "modelId": model_id,
        "modelName": "a model",
        "modelArn": f"arn:aws:bedrock:us-east-1::foundation-model/{model_id}",
        "providerName": "test-vendor",
        "modelLifecycle": {"status": "ACTIVE"},
        "inputModalities": ["TEXT"],
        "outputModalities": ["TEXT"],
        "inferenceTypesSupported": ["ON_DEMAND"],
    }


class ControlPlaneDouble:
    """Lists the models it is given (none by default); counts its listing
    calls. With ``throttled`` every listing call fails with a
    ThrottlingException."""

    def __init__(self, *model_ids, throttled=False):
        self.model_ids = list(model_ids)
        self.listings = 0
        self.throttled = throttled

    def list_inference_profiles(self, **kwargs):
        return {"inferenceProfileSummaries": []}

    def list_foundation_models(self, **kwargs):
        self.listings += 1
        if self.throttled:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ThrottlingException", "Message": "slow down"}},
                "ListFoundationModels",
            )
        return {"modelSummaries": [_summary(model_id) for model_id in self.model_ids]}


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
    # The files say no model was called instead of claiming generated output.
    for written in (executive, technical):
        assert "Generated with Amazon Bedrock" not in written, written
        assert "nothing was sent to Amazon Bedrock" in written, written


def test_a_secrets_only_scans_technical_file_says_its_section_was_not_sent(
    monkeypatch, tmp_path
):
    """With only secret findings the executive summary is generated (it
    counts them) and the technical analysis has nothing to send: the technical
    file says so for its own section, the executive file keeps the
    generated-output notice, and neither claims the other's state."""
    runtime = RuntimeDouble()
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session", _session_double(runtime, ControlPlaneDouble())
    )
    reporter = make_reporter(plugin_context_in(tmp_path))
    model = sarif_model([_result("AWS-KEY", "detect-secrets", snippet=SECRET_SNIPPET)])

    reporter.report(model)

    reports = tmp_path / "reports"
    executive = (reports / "bedrock-executive.md").read_text(encoding="utf-8")
    technical = (reports / "bedrock-technical.md").read_text(encoding="utf-8")
    assert "Generated with Amazon Bedrock" in executive, executive
    assert "nothing was sent to Amazon Bedrock for it" not in executive, executive
    assert "Generated with Amazon Bedrock" not in technical, technical
    assert "No findings matched this section's analysis filters" in technical, technical
    assert "No actionable findings to analyze for this section." in technical
    assert runtime.calls, "the executive summary was sent"


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
    first section walks the chain and finds every candidate unlisted; the
    second calls the configured model once more and names the same candidates
    unavailable without a second listing or a second call."""
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


def test_a_walk_the_control_plane_left_unchecked_is_asked_again(monkeypatch, tmp_path):
    """The boundary of the memory above: when the listing was throttled the
    walk checked nothing, so its exhaustion is not kept and the next section
    asks the control plane again (the throttle may have passed)."""
    refusal = botocore.exceptions.ClientError(
        {"Error": {"Code": "ValidationException", "Message": "too long"}}, "Converse"
    )
    runtime = RuntimeDouble(failure=refusal)
    control_plane = ControlPlaneDouble(throttled=True)
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session", _session_double(runtime, control_plane)
    )
    reporter = make_reporter(plugin_context_in(tmp_path), max_retries=0)
    client = reporter._make_model_client(runtime)

    first = reporter._outcome_with_fallback(client, "prompt one", "system")
    second = reporter._outcome_with_fallback(client, "prompt two", "system")

    assert first.ok is False and "not checked" in first.text, first.text
    assert second.ok is False and "not checked" in second.text, second.text
    assert reporter._unavailable_models == set()
    assert control_plane.listings == 2, "each section asked the control plane once"


class _RuntimeByModel:
    """A runtime whose answer is planned per model id: a list of exceptions
    and replies consumed call by call, the last one repeated."""

    def __init__(self, plan):
        self.plan = {model: list(answers) for model, answers in plan.items()}
        self.models = []

    def converse(self, **kwargs):
        model = kwargs["modelId"]
        self.models.append(model)
        answers = self.plan[model]
        answer = answers.pop(0) if len(answers) > 1 else answers[0]
        if isinstance(answer, Exception):
            raise answer
        return {
            "output": {"message": {"role": "assistant", "content": [{"text": answer}]}}
        }


def test_a_candidate_that_failed_on_one_prompt_is_called_again_for_the_next(
    monkeypatch, tmp_path
):
    """The other boundary: a listed candidate that failed on section one's
    prompt (a refusal tied to that prompt) is not unavailable. Section two
    calls it again with its own prompt, and it answers."""
    refusal = botocore.exceptions.ClientError(
        {"Error": {"Code": "ValidationException", "Message": "too long"}}, "Converse"
    )
    fallback = "test-vendor.test-model-fallback-1-v1:0"
    runtime = _RuntimeByModel(
        {PRIMARY_MODEL: [refusal], fallback: [refusal, "a shorter answer"]}
    )
    control_plane = ControlPlaneDouble(fallback)
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session", _session_double(runtime, control_plane)
    )
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: fallback, fallback: PRIMARY_MODEL}.get,
    )
    reporter = make_reporter(plugin_context_in(tmp_path), max_retries=0)
    client = reporter._make_model_client(runtime)

    first = reporter._outcome_with_fallback(client, "prompt one", "system")
    second = reporter._outcome_with_fallback(client, "prompt two", "system")

    assert first.ok is False and "No suitable fallback model found" in first.text
    assert second.ok is True and second.text == "a shorter answer", second.text
    assert runtime.models == [PRIMARY_MODEL, fallback, PRIMARY_MODEL, fallback]
    assert reporter._unavailable_models == set()


@pytest.mark.parametrize("code", ["AccessDeniedException", "ResourceNotFoundException"])
def test_a_candidate_converse_refused_as_not_permitted_is_not_called_again(
    monkeypatch, tmp_path, code
):
    """The other side of the boundary: a listed candidate Converse refused as
    not permitted or not found is refused on every prompt, so section two
    does not call it again (and does not walk it), while the configured model
    is still called with section two's prompt."""
    prompt_refusal = botocore.exceptions.ClientError(
        {"Error": {"Code": "ValidationException", "Message": "too long"}}, "Converse"
    )
    model_refusal = botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": "no"}}, "Converse"
    )
    fallback = "test-vendor.test-model-fallback-1-v1:0"
    runtime = _RuntimeByModel(
        {PRIMARY_MODEL: [prompt_refusal], fallback: [model_refusal]}
    )
    control_plane = ControlPlaneDouble(fallback)
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session", _session_double(runtime, control_plane)
    )
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: fallback, fallback: PRIMARY_MODEL}.get,
    )
    reporter = make_reporter(plugin_context_in(tmp_path), max_retries=0)
    client = reporter._make_model_client(runtime)

    first = reporter._outcome_with_fallback(client, "prompt one", "system")
    second = reporter._outcome_with_fallback(client, "prompt two", "system")

    assert first.ok is False and second.ok is False
    assert runtime.models == [PRIMARY_MODEL, fallback, PRIMARY_MODEL], runtime.models
    assert reporter._unavailable_models == {fallback}
    assert control_plane.listings == 1, "the chain was listed once"
