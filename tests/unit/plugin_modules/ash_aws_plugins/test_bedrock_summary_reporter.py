# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the BedrockSummaryReporter class."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
    BedrockSummaryReporterConfigOptions,
)
from automated_security_helper.config.ash_config import AshConfig

AshConfig.model_rebuild()
BedrockSummaryReporterConfig.model_rebuild()
BedrockSummaryReporter.model_rebuild()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_context(temp_project_dir, temp_output_dir):
    """Create a PluginContext for the reporter."""
    from automated_security_helper.base.plugin_context import PluginContext

    context = PluginContext(output_dir=temp_output_dir, source_dir=temp_project_dir)
    return context


@pytest.fixture
def bedrock_runtime_ok():
    """Mock bedrock-runtime client that returns a valid converse response."""
    client = MagicMock()
    client.converse.return_value = {
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": "Generated summary from Bedrock."}],
            }
        }
    }
    return client


@pytest.fixture
def bedrock_runtime_multi_content():
    """Mock bedrock-runtime client that returns multiple content blocks."""
    client = MagicMock()
    client.converse.return_value = {
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {"text": "Part one. "},
                    {"text": "Part two."},
                ],
            }
        }
    }
    return client


@pytest.fixture
def bedrock_client_ok():
    """Mock bedrock control-plane client for model validation."""
    client = MagicMock()
    client.list_foundation_models.return_value = {
        "modelSummaries": [
            {
                "modelId": "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
                "modelName": "Claude 3.7 Sonnet",
                "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-7-sonnet",
                "providerName": "Anthropic",
                "inputModalities": ["TEXT"],
                "outputModalities": ["TEXT"],
                "inferenceTypesSupported": ["ON_DEMAND"],
                "modelLifecycle": {"status": "ACTIVE"},
            }
        ]
    }
    client.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    return client


@pytest.fixture
def sts_client_ok():
    """Mock STS client that succeeds."""
    client = MagicMock()
    client.get_caller_identity.return_value = {"Account": "123456789012"}
    return client


@pytest.fixture
def boto3_session(bedrock_client_ok, bedrock_runtime_ok, sts_client_ok):
    """Mock boto3.Session wired to return appropriate clients."""
    session = MagicMock()

    def _client_factory(service, **kwargs):
        return {
            "bedrock": bedrock_client_ok,
            "bedrock-runtime": bedrock_runtime_ok,
            "sts": sts_client_ok,
        }[service]

    session.client.side_effect = _client_factory
    return session


@pytest.fixture
def reporter(mock_context):
    """Create a BedrockSummaryReporter with default config."""
    with patch("boto3.Session"):
        r = BedrockSummaryReporter(context=mock_context)
    return r


@pytest.fixture
def sample_sarif_model():
    """Build an AshAggregatedResults with realistic SARIF findings."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.schemas.sarif_schema_model import (
        SarifReport,
        Run,
        Tool,
        ToolComponent,
        Result,
        Message,
        Location,
        PhysicalLocation,
        ArtifactLocation,
        Region,
        ReportingDescriptorReference,
        PropertyBag,
    )
    from pydantic import AnyUrl

    AshAggregatedResults.model_rebuild()

    findings = [
        Result(
            ruleId="B101",
            rule=ReportingDescriptorReference(id="B101"),
            level="error",
            message=Message(text="Use of dangerous function detected"),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(
                        artifactLocation=ArtifactLocation(uri="src/app.py"),
                        region=Region(startLine=10, endLine=10),
                    )
                )
            ],
            properties=PropertyBag(scanner_type="SAST"),
        ),
        Result(
            ruleId="B108",
            rule=ReportingDescriptorReference(id="B108"),
            level="warning",
            message=Message(text="Hardcoded /tmp path detected"),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(
                        artifactLocation=ArtifactLocation(uri="src/util.py"),
                        region=Region(startLine=5, endLine=7),
                    )
                )
            ],
            properties=PropertyBag(scanner_type="SAST"),
        ),
        Result(
            ruleId="SECRET001",
            rule=ReportingDescriptorReference(id="SECRET001"),
            level="error",
            message=Message(text="Possible AWS access key"),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(
                        artifactLocation=ArtifactLocation(uri="config/.env"),
                        region=Region(startLine=3, endLine=3),
                    )
                )
            ],
            properties=PropertyBag(scanner_type="SECRET"),
        ),
    ]

    run = Run(
        tool=Tool(
            driver=ToolComponent(
                name="ASH",
                version="1.0.0",
            )
        ),
        results=findings,
    )

    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[run])
    model.scanner_results = {"bandit": MagicMock(), "gitleaks": MagicMock()}
    return model


@pytest.fixture
def sample_sarif_model_no_findings():
    """AshAggregatedResults with an empty SARIF run."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.schemas.sarif_schema_model import (
        SarifReport,
        Run,
        Tool,
        ToolComponent,
    )

    AshAggregatedResults.model_rebuild()

    run = Run(
        tool=Tool(driver=ToolComponent(name="ASH", version="1.0.0")),
        results=[],
    )
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[run])
    model.scanner_results = {}
    return model


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------


class TestValidatePluginDependencies:
    """Tests for validate_plugin_dependencies."""

    @patch("boto3.Session")
    def test_success_when_model_available(
        self, mock_session_cls, boto3_session, mock_context
    ):
        mock_session_cls.return_value = boto3_session
        reporter = BedrockSummaryReporter(context=mock_context)

        assert reporter.validate_plugin_dependencies() is True
        assert reporter.dependencies_satisfied is True

    @patch("boto3.Session")
    def test_fails_when_region_is_none(self, mock_session_cls, mock_context):
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.aws_region = None

        assert reporter.validate_plugin_dependencies() is False

    @patch("boto3.Session")
    def test_fails_when_sts_returns_no_account(self, mock_session_cls, mock_context):
        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {}
        session.client.return_value = sts
        mock_session_cls.return_value = session

        reporter = BedrockSummaryReporter(context=mock_context)
        assert reporter.validate_plugin_dependencies() is False

    @patch("boto3.Session")
    def test_fails_on_client_error_from_bedrock(self, mock_session_cls, mock_context):
        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        bedrock = MagicMock()
        bedrock.list_foundation_models.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
            "list_foundation_models",
        )
        session.client.side_effect = lambda svc, **kw: {"sts": sts, "bedrock": bedrock}[
            svc
        ]
        mock_session_cls.return_value = session

        reporter = BedrockSummaryReporter(context=mock_context)
        assert reporter.validate_plugin_dependencies() is False

    @patch("boto3.Session")
    def test_fallback_model_used_when_primary_invalid(
        self, mock_session_cls, mock_context
    ):
        """When primary model is not in the list, fallback should succeed."""
        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        bedrock = MagicMock()
        # The fallback for us.anthropic.claude-3-7-sonnet is claude-3-5-sonnet
        bedrock.list_foundation_models.return_value = {
            "modelSummaries": [
                {
                    "modelId": "us.anthropic.claude-3-5-sonnet-20240620-v1:0",
                    "modelName": "Claude 3.5 Sonnet",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20240620-v1",
                    "providerName": "Anthropic",
                    "inputModalities": ["TEXT"],
                    "outputModalities": ["TEXT"],
                    "inferenceTypesSupported": ["ON_DEMAND"],
                    "modelLifecycle": {"status": "ACTIVE"},
                }
            ]
        }
        bedrock.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
        session.client.side_effect = lambda svc, **kw: {"sts": sts, "bedrock": bedrock}[
            svc
        ]
        mock_session_cls.return_value = session

        reporter = BedrockSummaryReporter(context=mock_context)
        # Primary model not in list, but the fallback (claude-3-5-sonnet) is
        reporter.config.options.model_id = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
        reporter.config.options.enable_fallback_models = True

        assert reporter.validate_plugin_dependencies() is True

    @patch("boto3.Session")
    def test_unexpected_exception_caught(self, mock_session_cls, mock_context):
        mock_session_cls.side_effect = RuntimeError("Boom")
        reporter = BedrockSummaryReporter(context=mock_context)
        assert reporter.validate_plugin_dependencies() is False


# ---------------------------------------------------------------------------
# Prompt construction tests
# ---------------------------------------------------------------------------


class TestPreparePrompt:
    """Tests for _prepare_prompt."""

    @patch("boto3.Session")
    def test_plain_message_unchanged(self, mock_session_cls, mock_context):
        reporter = BedrockSummaryReporter(context=mock_context)
        msg = "Analyze this."
        assert reporter._prepare_prompt(msg) == msg

    @patch("boto3.Session")
    def test_custom_prompt_prepended(self, mock_session_cls, mock_context):
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.custom_prompt = "Focus on OWASP Top 10."
        result = reporter._prepare_prompt("Findings here.")
        assert result.startswith("Focus on OWASP Top 10.")
        assert "Findings here." in result

    @patch("boto3.Session")
    def test_industry_context_appended(self, mock_session_cls, mock_context):
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.industry_context = "Healthcare"
        reporter.config.options.compliance_frameworks = ["HIPAA", "SOC2"]
        result = reporter._prepare_prompt("Data.")
        assert "Healthcare" in result
        assert "HIPAA" in result
        assert "SOC2" in result

    @patch("boto3.Session")
    def test_custom_context_appended(self, mock_session_cls, mock_context):
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.industry_context = "Fintech"
        reporter.config.options.custom_context = "PCI scope applies."
        result = reporter._prepare_prompt("Base.")
        assert "PCI scope applies." in result


# ---------------------------------------------------------------------------
# _try_model_call tests
# ---------------------------------------------------------------------------


class TestTryModelCall:
    """Tests for _try_model_call response parsing and error handling."""

    @patch("boto3.Session")
    def test_parses_single_text_content(
        self, mock_session_cls, mock_context, bedrock_runtime_ok
    ):
        reporter = BedrockSummaryReporter(context=mock_context)
        result = reporter._try_model_call(
            bedrock_runtime_ok,
            "test-model",
            [{"role": "user", "content": [{"text": "hi"}]}],
            [{"text": "sys"}],
            {"temperature": 0.5, "maxTokens": 100, "topP": 0.9},
        )
        assert result == "Generated summary from Bedrock."

    @patch("boto3.Session")
    def test_concatenates_multiple_content_blocks(
        self, mock_session_cls, mock_context, bedrock_runtime_multi_content
    ):
        reporter = BedrockSummaryReporter(context=mock_context)
        result = reporter._try_model_call(
            bedrock_runtime_multi_content,
            "test-model",
            [{"role": "user", "content": [{"text": "hi"}]}],
            [{"text": "sys"}],
            {"temperature": 0.5, "maxTokens": 100, "topP": 0.9},
        )
        assert result == "Part one. Part two."

    @patch("boto3.Session")
    def test_empty_response_returns_error(self, mock_session_cls, mock_context):
        client = MagicMock()
        client.converse.return_value = {}
        reporter = BedrockSummaryReporter(context=mock_context)
        result = reporter._try_model_call(
            client,
            "test-model",
            [{"role": "user", "content": [{"text": "hi"}]}],
            [{"text": "sys"}],
            {"temperature": 0.5, "maxTokens": 100, "topP": 0.9},
        )
        assert "*Error" in result

    @patch("boto3.Session")
    def test_access_denied_error(self, mock_session_cls, mock_context):
        client = MagicMock()
        client.converse.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "No access"}},
            "converse",
        )
        reporter = BedrockSummaryReporter(context=mock_context)
        result = reporter._try_model_call(
            client,
            "my-model",
            [{"role": "user", "content": [{"text": "hi"}]}],
            [{"text": "sys"}],
            {"temperature": 0.5, "maxTokens": 100, "topP": 0.9},
        )
        assert "Access denied" in result
        assert "my-model" in result

    @patch("boto3.Session")
    def test_resource_not_found_error(self, mock_session_cls, mock_context):
        client = MagicMock()
        client.converse.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Not found"}},
            "converse",
        )
        reporter = BedrockSummaryReporter(context=mock_context)
        result = reporter._try_model_call(
            client,
            "bad-model",
            [{"role": "user", "content": [{"text": "hi"}]}],
            [{"text": "sys"}],
            {"temperature": 0.5, "maxTokens": 100, "topP": 0.9},
        )
        assert "not found" in result.lower()

    @patch("boto3.Session")
    def test_throttling_error(self, mock_session_cls, mock_context):
        client = MagicMock()
        client.converse.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Slow down"}},
            "converse",
        )
        reporter = BedrockSummaryReporter(context=mock_context)
        result = reporter._try_model_call(
            client,
            "model",
            [{"role": "user", "content": [{"text": "hi"}]}],
            [{"text": "sys"}],
            {"temperature": 0.5, "maxTokens": 100, "topP": 0.9},
        )
        assert "Rate limit" in result

    @patch("boto3.Session")
    def test_validation_error(self, mock_session_cls, mock_context):
        client = MagicMock()
        client.converse.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "ValidationException", "Message": "Bad input"}},
            "converse",
        )
        reporter = BedrockSummaryReporter(context=mock_context)
        result = reporter._try_model_call(
            client,
            "model",
            [{"role": "user", "content": [{"text": "hi"}]}],
            [{"text": "sys"}],
            {"temperature": 0.5, "maxTokens": 100, "topP": 0.9},
        )
        assert "Validation error" in result

    @patch("boto3.Session")
    def test_generic_exception(self, mock_session_cls, mock_context):
        client = MagicMock()
        client.converse.side_effect = ValueError("something broke")
        reporter = BedrockSummaryReporter(context=mock_context)
        result = reporter._try_model_call(
            client,
            "model",
            [{"role": "user", "content": [{"text": "hi"}]}],
            [{"text": "sys"}],
            {"temperature": 0.5, "maxTokens": 100, "topP": 0.9},
        )
        assert "ValueError" in result
        assert "something broke" in result

    @patch("boto3.Session")
    def test_adds_top_k_for_claude_models(
        self, mock_session_cls, mock_context, bedrock_runtime_ok
    ):
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter._try_model_call(
            bedrock_runtime_ok,
            "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
            [{"role": "user", "content": [{"text": "hi"}]}],
            [{"text": "sys"}],
            {"temperature": 0.5, "maxTokens": 100, "topP": 0.9},
        )
        call_kwargs = bedrock_runtime_ok.converse.call_args[1]
        assert "additionalModelRequestFields" in call_kwargs
        assert call_kwargs["additionalModelRequestFields"]["top_k"] == 200

    @patch("boto3.Session")
    def test_no_additional_fields_for_non_claude(
        self, mock_session_cls, mock_context, bedrock_runtime_ok
    ):
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter._try_model_call(
            bedrock_runtime_ok,
            "us.amazon.nova-pro-v1:0",
            [{"role": "user", "content": [{"text": "hi"}]}],
            [{"text": "sys"}],
            {"temperature": 0.5, "maxTokens": 100, "topP": 0.9},
        )
        call_kwargs = bedrock_runtime_ok.converse.call_args[1]
        assert "additionalModelRequestFields" not in call_kwargs


# ---------------------------------------------------------------------------
# _call_bedrock tests (integration of validation + call + fallback)
# ---------------------------------------------------------------------------


class TestCallBedrock:
    """Tests for _call_bedrock orchestration."""

    @patch("boto3.client")
    @patch("boto3.Session")
    def test_success_on_valid_model(
        self,
        mock_session_cls,
        mock_boto3_client,
        mock_context,
        bedrock_client_ok,
        bedrock_runtime_ok,
    ):
        mock_boto3_client.return_value = bedrock_client_ok
        reporter = BedrockSummaryReporter(context=mock_context)

        result = reporter._call_bedrock(
            bedrock_runtime_ok, "Tell me something", "You are helpful"
        )
        assert result == "Generated summary from Bedrock."

    @patch("boto3.client")
    @patch("boto3.Session")
    def test_returns_error_when_model_invalid_and_no_fallback(
        self, mock_session_cls, mock_boto3_client, mock_context
    ):
        bedrock = MagicMock()
        bedrock.list_foundation_models.return_value = {"modelSummaries": []}
        bedrock.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
        mock_boto3_client.return_value = bedrock

        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.enable_fallback_models = False

        result = reporter._call_bedrock(MagicMock(), "msg", "sys")
        assert "*Error" in result
        assert "validation failed" in result

    @patch("boto3.client")
    @patch("boto3.Session")
    def test_falls_back_on_primary_failure(
        self, mock_session_cls, mock_boto3_client, mock_context, bedrock_client_ok
    ):
        mock_boto3_client.return_value = bedrock_client_ok

        # Primary model call fails
        runtime = MagicMock()
        runtime.converse.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "No"}},
            "converse",
        )

        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.enable_fallback_models = True

        # Patch _try_fallback_models to avoid recursion in test
        with patch.object(reporter, "_try_fallback_models", return_value="Fallback OK"):
            result = reporter._call_bedrock(runtime, "msg", "sys")

        assert result == "Fallback OK"


# ---------------------------------------------------------------------------
# Report generation tests
# ---------------------------------------------------------------------------


class TestReport:
    """Tests for the report() method."""

    @patch("boto3.client")
    @patch("boto3.Session")
    def test_no_findings_returns_message(
        self,
        mock_session_cls,
        mock_boto3_client,
        mock_context,
        sample_sarif_model_no_findings,
    ):
        reporter = BedrockSummaryReporter(context=mock_context)
        result = reporter.report(sample_sarif_model_no_findings)
        assert "No actionable findings" in result

    @patch("boto3.client")
    @patch("boto3.Session")
    def test_report_with_findings_generates_structured_output(
        self,
        mock_session_cls,
        mock_boto3_client,
        mock_context,
        sample_sarif_model,
        bedrock_client_ok,
        bedrock_runtime_ok,
    ):
        session = MagicMock()
        session.client.side_effect = lambda svc, **kw: {
            "bedrock": bedrock_client_ok,
            "bedrock-runtime": bedrock_runtime_ok,
        }.get(svc, MagicMock())
        mock_session_cls.return_value = session
        mock_boto3_client.return_value = bedrock_client_ok

        reporter = BedrockSummaryReporter(context=mock_context)
        result = reporter.report(sample_sarif_model)

        assert "Security Scan Summary Report" in result
        assert "Table of Contents" in result
        assert "Executive Summary" in result
        assert "Finding Details" in result

    @patch("boto3.client")
    @patch("boto3.Session")
    def test_report_writes_markdown_files(
        self,
        mock_session_cls,
        mock_boto3_client,
        mock_context,
        sample_sarif_model,
        bedrock_client_ok,
        bedrock_runtime_ok,
        temp_output_dir,
    ):
        session = MagicMock()
        session.client.side_effect = lambda svc, **kw: {
            "bedrock": bedrock_client_ok,
            "bedrock-runtime": bedrock_runtime_ok,
        }.get(svc, MagicMock())
        mock_session_cls.return_value = session
        mock_boto3_client.return_value = bedrock_client_ok

        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.output_markdown = True
        reporter.report(sample_sarif_model)

        reports_dir = Path(temp_output_dir) / "reports"
        assert reports_dir.exists()
        main_report = reports_dir / "ash.bedrock.summary.md"
        assert main_report.exists()
        content = main_report.read_text()
        assert len(content) > 0

    @patch("boto3.client")
    @patch("boto3.Session")
    def test_report_without_section_headers_uses_simple_summary(
        self,
        mock_session_cls,
        mock_boto3_client,
        mock_context,
        sample_sarif_model,
        bedrock_client_ok,
        bedrock_runtime_ok,
    ):
        session = MagicMock()
        session.client.side_effect = lambda svc, **kw: {
            "bedrock": bedrock_client_ok,
            "bedrock-runtime": bedrock_runtime_ok,
        }.get(svc, MagicMock())
        mock_session_cls.return_value = session
        mock_boto3_client.return_value = bedrock_client_ok

        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.add_section_headers = False
        result = reporter.report(sample_sarif_model)

        # Simple summary does not have the structured TOC
        assert "Table of Contents" not in result
        assert isinstance(result, str)

    @patch("boto3.client")
    @patch("boto3.Session")
    def test_secret_findings_separated(
        self,
        mock_session_cls,
        mock_boto3_client,
        mock_context,
        sample_sarif_model,
        bedrock_client_ok,
        bedrock_runtime_ok,
    ):
        """Secret scanner findings should be tracked separately."""
        session = MagicMock()
        session.client.side_effect = lambda svc, **kw: {
            "bedrock": bedrock_client_ok,
            "bedrock-runtime": bedrock_runtime_ok,
        }.get(svc, MagicMock())
        mock_session_cls.return_value = session
        mock_boto3_client.return_value = bedrock_client_ok

        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.include_sections = [
            "executive_summary",
            "technical_analysis",
            "secret_findings",
            "remediation_guide",
        ]
        result = reporter.report(sample_sarif_model)

        assert "Secret Findings" in result


# ---------------------------------------------------------------------------
# Caching tests
# ---------------------------------------------------------------------------


class TestCaching:
    """Tests for _get_cached_or_generate."""

    @patch("boto3.Session")
    def test_caches_result_on_first_call(self, mock_session_cls, mock_context):
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.enable_caching = True
        call_count = {"n": 0}

        def gen():
            call_count["n"] += 1
            return "result"

        r1 = reporter._get_cached_or_generate("key1", gen)
        r2 = reporter._get_cached_or_generate("key1", gen)
        assert r1 == r2 == "result"
        assert call_count["n"] == 1

    @patch("boto3.Session")
    def test_bypasses_cache_when_disabled(self, mock_session_cls, mock_context):
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.enable_caching = False
        call_count = {"n": 0}

        def gen():
            call_count["n"] += 1
            return "result"

        reporter._get_cached_or_generate("key1", gen)
        reporter._get_cached_or_generate("key1", gen)
        assert call_count["n"] == 2


# ---------------------------------------------------------------------------
# Summarize findings tests
# ---------------------------------------------------------------------------


class TestSummarizeFindings:
    """Tests for _summarize_findings."""

    @patch("boto3.Session")
    def test_groups_duplicate_rules(self, mock_session_cls, mock_context):
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.summarize_findings = True

        findings = [
            {
                "rule": {"id": "B101"},
                "level": "error",
                "message": {"text": "dangerous function use"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "a.py"},
                        }
                    }
                ],
            },
            {
                "rule": {"id": "B101"},
                "level": "error",
                "message": {"text": "dangerous function use"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "b.py"},
                        }
                    }
                ],
            },
            {
                "rule": {"id": "B108"},
                "level": "warning",
                "message": {"text": "tmp path"},
                "locations": [],
            },
        ]

        result = reporter._summarize_findings(findings)
        # Should consolidate the two B101 findings into one summarized entry
        assert len(result) == 2
        b101_finding = next(f for f in result if f["rule"]["id"] == "B101")
        assert b101_finding["properties"]["summarized"] is True
        assert b101_finding["properties"]["original_count"] == 2

    @patch("boto3.Session")
    def test_returns_unchanged_when_disabled(self, mock_session_cls, mock_context):
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.summarize_findings = False

        findings = [{"rule": {"id": "A"}, "level": "error"}]
        result = reporter._summarize_findings(findings)
        assert result == findings

    @patch("boto3.Session")
    def test_handles_empty_list(self, mock_session_cls, mock_context):
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.summarize_findings = True
        assert reporter._summarize_findings([]) == []


# ---------------------------------------------------------------------------
# Suppression / actionable filtering tests
# ---------------------------------------------------------------------------


class TestActionableFiltering:
    """Test that suppressed and below-threshold findings are excluded."""

    @patch("boto3.client")
    @patch("boto3.Session")
    def test_suppressed_findings_excluded(
        self,
        mock_session_cls,
        mock_boto3_client,
        mock_context,
        bedrock_client_ok,
        bedrock_runtime_ok,
    ):
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import (
            SarifReport,
            Run,
            Tool,
            ToolComponent,
            Result,
            Message,
            ReportingDescriptorReference,
            Suppression,
        )

        AshAggregatedResults.model_rebuild()

        suppressed_result = Result(
            ruleId="B101",
            rule=ReportingDescriptorReference(id="B101"),
            level="error",
            message=Message(text="Suppressed finding"),
            suppressions=[Suppression(kind="inSource")],
        )
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", version="1.0.0")),
            results=[suppressed_result],
        )
        model = AshAggregatedResults()
        model.sarif = SarifReport(version="2.1.0", runs=[run])
        model.scanner_results = {}

        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.actionable_only = True
        result = reporter.report(model)
        assert "No actionable findings" in result


# ---------------------------------------------------------------------------
# Config options tests
# ---------------------------------------------------------------------------


class TestConfigOptions:
    """Tests for BedrockSummaryReporterConfigOptions defaults."""

    def test_default_model_id(self):
        opts = BedrockSummaryReporterConfigOptions()
        assert "claude" in opts.model_id or "nova" in opts.model_id or opts.model_id

    def test_default_temperature(self):
        opts = BedrockSummaryReporterConfigOptions()
        assert 0.0 <= opts.temperature <= 1.0

    def test_default_max_tokens(self):
        opts = BedrockSummaryReporterConfigOptions()
        assert opts.max_tokens > 0

    def test_default_sections(self):
        opts = BedrockSummaryReporterConfigOptions()
        assert "executive_summary" in opts.include_sections
        assert "risk_assessment" in opts.include_sections

    def test_secret_excluded_by_default(self):
        opts = BedrockSummaryReporterConfigOptions()
        assert "SECRET" in opts.exclude_scanner_types


# ---------------------------------------------------------------------------
# Fallback model tests
# ---------------------------------------------------------------------------


class TestTryFallbackModels:
    """Tests for _try_fallback_models logic."""

    @patch("boto3.Session")
    def test_returns_error_when_no_fallback_available(
        self, mock_session_cls, mock_context
    ):
        reporter = BedrockSummaryReporter(context=mock_context)

        # get_fallback_model returns a model, but we patch to return None
        with patch(
            "automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter.get_fallback_model",
            return_value=None,
        ):
            result = reporter._try_fallback_models(
                MagicMock(),
                MagicMock(),
                "bad-model",
                [],
                [],
                {},
            )
        assert "*Error" in result
        assert "No suitable fallback" in result

    @patch("boto3.Session")
    def test_returns_error_when_fallback_same_as_failed(
        self, mock_session_cls, mock_context
    ):
        reporter = BedrockSummaryReporter(context=mock_context)

        with patch(
            "automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter.get_fallback_model",
            return_value="bad-model",
        ):
            result = reporter._try_fallback_models(
                MagicMock(),
                MagicMock(),
                "bad-model",
                [],
                [],
                {},
            )
        assert "*Error" in result


# ---------------------------------------------------------------------------
# Executive summary generation tests
# ---------------------------------------------------------------------------


class TestGenerateExecutiveSummary:
    """Tests for _generate_executive_summary prompt construction."""

    @patch("boto3.client")
    @patch("boto3.Session")
    def test_includes_severity_counts_in_prompt(
        self,
        mock_session_cls,
        mock_boto3_client,
        mock_context,
        bedrock_client_ok,
        bedrock_runtime_ok,
    ):
        mock_boto3_client.return_value = bedrock_client_ok
        reporter = BedrockSummaryReporter(context=mock_context)

        model = MagicMock()
        model.scanner_results = {"bandit": MagicMock()}

        findings = [
            {"level": "error", "message": {"text": "bad"}},
            {"level": "error", "message": {"text": "worse"}},
            {"level": "warning", "message": {"text": "meh"}},
        ]

        result = reporter._generate_executive_summary(
            bedrock_runtime_ok, model, findings, []
        )
        assert result == "Generated summary from Bedrock."

        # Verify the prompt sent to converse contains severity info
        call_args = bedrock_runtime_ok.converse.call_args
        messages = call_args[1]["messages"]
        user_text = messages[0]["content"][0]["text"]
        assert "error" in user_text
        assert "3" in user_text  # total findings


# ---------------------------------------------------------------------------
# Batch processing tests
# ---------------------------------------------------------------------------


class TestBatchProcessing:
    """Tests for _process_findings_by_batch."""

    @patch("boto3.client")
    @patch("boto3.Session")
    def test_falls_back_to_standard_when_disabled(
        self,
        mock_session_cls,
        mock_boto3_client,
        mock_context,
        bedrock_client_ok,
        bedrock_runtime_ok,
    ):
        mock_boto3_client.return_value = bedrock_client_ok
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.batch_processing = False

        model = MagicMock()
        model.scanner_results = {}
        findings = [{"level": "error", "message": {"text": f"f{i}"}} for i in range(20)]

        result = reporter._process_findings_by_batch(
            bedrock_runtime_ok, model, findings
        )
        assert isinstance(result, str)

    @patch("boto3.client")
    @patch("boto3.Session")
    def test_processes_in_batches_when_enabled(
        self,
        mock_session_cls,
        mock_boto3_client,
        mock_context,
        bedrock_client_ok,
        bedrock_runtime_ok,
    ):
        mock_boto3_client.return_value = bedrock_client_ok
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.batch_processing = True
        reporter.config.options.max_findings_to_analyze = 5

        model = MagicMock()
        model.scanner_results = {}
        # 12 findings should create 3 batches of 5, 5, 2
        findings = [
            {"level": "error", "message": {"text": f"f{i}"}} for i in range(12)
        ]

        result = reporter._process_findings_by_batch(
            bedrock_runtime_ok, model, findings
        )
        # The final synthesis call plus batch calls
        assert bedrock_runtime_ok.converse.call_count >= 3
        assert isinstance(result, str)
