"""
Tests for the BedrockSummaryReporter class.
"""

from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
)

# Rebuild models to ensure they're properly defined for testing
from automated_security_helper.config.ash_config import AshConfig

AshConfig.model_rebuild()
BedrockSummaryReporterConfig.model_rebuild()
BedrockSummaryReporter.model_rebuild()


class TestBedrockSummaryReporter:
    """Tests for the BedrockSummaryReporter class."""

    @pytest.fixture
    def mock_context(self, temp_project_dir, temp_output_dir):
        """Create a mock context for the reporter."""
        from automated_security_helper.base.plugin_context import PluginContext

        # Create a proper PluginContext instance instead of a MagicMock
        context = PluginContext(output_dir=temp_output_dir, source_dir=temp_project_dir)
        return context

    @pytest.fixture
    def mock_bedrock_client(self):
        """Create a mock Bedrock client."""
        mock_client = MagicMock()
        # Mock list_foundation_models response
        mock_client.list_foundation_models.return_value = {
            "modelSummaries": [
                {
                    "modelId": "us.amazon.nova-pro-v1:0",
                    "modelName": "Amazon Nova Pro",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-pro-v1",
                    "providerName": "Amazon",
                    "inputModalities": ["TEXT"],
                    "outputModalities": ["TEXT"],
                    "inferenceTypesSupported": ["ON_DEMAND"],
                    "modelLifecycle": {"status": "ACTIVE"},
                }
            ]
        }
        # Mock list_inference_profiles response
        mock_client.list_inference_profiles.return_value = {
            "inferenceProfileSummaries": []
        }
        return mock_client

    @pytest.fixture
    def mock_bedrock_runtime(self):
        """Create a mock Bedrock runtime client."""
        mock_runtime = MagicMock()
        # Mock converse response
        mock_runtime.converse.return_value = {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "This is a test response from Bedrock"}],
                }
            }
        }
        return mock_runtime

    @pytest.fixture
    def mock_sts_client(self):
        """Create a mock STS client."""
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        return mock_sts

    @pytest.fixture
    def mock_boto3_session(
        self, mock_bedrock_client, mock_bedrock_runtime, mock_sts_client
    ):
        """Create a mock boto3 session."""
        mock_session = MagicMock()
        mock_session.client.side_effect = lambda service, **kwargs: {
            "bedrock": mock_bedrock_client,
            "bedrock-runtime": mock_bedrock_runtime,
            "sts": mock_sts_client,
        }[service]
        return mock_session

    @patch("boto3.Session")
    def test_validate_success(
        self, mock_session_class, mock_boto3_session, mock_context
    ):
        """Test successful validation."""
        mock_session_class.return_value = mock_boto3_session

        reporter = BedrockSummaryReporter(context=mock_context)

        result = reporter.validate_plugin_dependencies()

        assert result is False
        assert reporter.dependencies_satisfied is False
        mock_boto3_session.client.assert_any_call("bedrock")
        mock_boto3_session.client.assert_any_call("sts")

    @patch("boto3.Session")
    def test_validate_no_region(self, mock_session_class, mock_context):
        """Test validation with no AWS region."""
        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.aws_region = None

        result = reporter.validate_plugin_dependencies()

        assert result is False
        assert reporter.dependencies_satisfied is False

    @patch("boto3.Session")
    def test_validate_invalid_credentials(self, mock_session_class, mock_context):
        """Test validation with invalid AWS credentials."""
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {}  # Missing Account
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        reporter = BedrockSummaryReporter(context=mock_context)

        result = reporter.validate_plugin_dependencies()

        assert result is False
        assert reporter.dependencies_satisfied is False

    @patch("boto3.Session")
    def test_validate_bedrock_error(self, mock_session_class, mock_context):
        """Test validation with Bedrock service error."""
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        mock_bedrock = MagicMock()
        error_response = {
            "Error": {
                "Code": "ServiceUnavailable",
                "Message": "Bedrock service is unavailable",
            }
        }
        mock_bedrock.list_foundation_models.side_effect = (
            botocore.exceptions.ClientError(error_response, "list_foundation_models")
        )

        mock_session.client.side_effect = lambda service, **kwargs: {
            "bedrock": mock_bedrock,
            "sts": mock_sts,
        }[service]

        mock_session_class.return_value = mock_session

        reporter = BedrockSummaryReporter(context=mock_context)

        result = reporter.validate_plugin_dependencies()

        assert result is False
        assert reporter.dependencies_satisfied is False

    @patch("boto3.Session")
    def test_validate_invalid_model(
        self, mock_session_class, mock_boto3_session, mock_context, mock_bedrock_client
    ):
        """Test validation with invalid model ID."""
        mock_session_class.return_value = mock_boto3_session

        # Set up the mock to return empty model list
        mock_bedrock_client.list_foundation_models.return_value = {"modelSummaries": []}

        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.model_id = "invalid-model-id"
        reporter.config.options.enable_fallback_models = False

        result = reporter.validate_plugin_dependencies()

        assert result is False
        assert reporter.dependencies_satisfied is False

    @patch("boto3.Session")
    def test_validate_with_fallback(
        self, mock_session_class, mock_boto3_session, mock_context, mock_bedrock_client
    ):
        """Test validation with fallback model."""
        mock_session_class.return_value = mock_boto3_session

        # Make sure the session returns our mock bedrock client
        mock_boto3_session.client.return_value = mock_bedrock_client

        # Primary model not available, but fallback is
        mock_bedrock_client.list_foundation_models.return_value = {
            "modelSummaries": [
                {
                    "modelId": "us.amazon.nova-lite-v1:0",
                    "modelName": "Amazon Nova Lite",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1",
                    "providerName": "Amazon",
                    "inputModalities": ["TEXT"],
                    "outputModalities": ["TEXT"],
                    "inferenceTypesSupported": ["ON_DEMAND"],
                    "modelLifecycle": {"status": "ACTIVE"},
                }
            ]
        }

        # Mock list_inference_profiles as well
        mock_bedrock_client.list_inference_profiles.return_value = {
            "inferenceProfileSummaries": []
        }

        reporter = BedrockSummaryReporter(context=mock_context)
        reporter.config.options.model_id = "us.amazon.nova-pro-v1:0"  # Not in the list
        reporter.config.options.enable_fallback_models = True

        result = reporter.validate_plugin_dependencies()

        assert result is True
        assert reporter.dependencies_satisfied is True

    @patch("boto3.Session")
    def test_call_bedrock_success(
        self, mock_session_class, mock_boto3_session, mock_context, mock_bedrock_runtime
    ):
        """Test successful call to Bedrock."""
        mock_session_class.return_value = mock_boto3_session

        reporter = BedrockSummaryReporter(context=mock_context)

        result = reporter._call_bedrock(
            mock_bedrock_runtime, "Test user message", "Test system prompt"
        )

        assert result == "This is a test response from Bedrock"
        mock_bedrock_runtime.converse.assert_called_once()

    @patch("boto3.Session")
    def test_try_model_call_success(
        self, mock_session_class, mock_boto3_session, mock_context, mock_bedrock_runtime
    ):
        """Test successful model call."""
        mock_session_class.return_value = mock_boto3_session

        reporter = BedrockSummaryReporter(context=mock_context)

        result = reporter._try_model_call(
            mock_bedrock_runtime,
            "us.amazon.nova-pro-v1:0",
            [{"role": "user", "content": [{"text": "Test message"}]}],
            [{"text": "Test system prompt"}],
            {"temperature": 0.5, "maxTokens": 4000, "topP": 0.9},
        )

        assert result == "This is a test response from Bedrock"
        mock_bedrock_runtime.converse.assert_called_once()

    @patch("boto3.Session")
    def test_try_model_call_client_error(
        self, mock_session_class, mock_boto3_session, mock_context, mock_bedrock_runtime
    ):
        """Test model call with client error."""
        mock_session_class.return_value = mock_boto3_session

        mock_bedrock_runtime.converse.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
            "converse",
        )

        reporter = BedrockSummaryReporter(context=mock_context)

        result = reporter._try_model_call(
            mock_bedrock_runtime,
            "us.amazon.nova-pro-v1:0",
            [{"role": "user", "content": [{"text": "Test message"}]}],
            [{"text": "Test system prompt"}],
            {"temperature": 0.5, "maxTokens": 4000, "topP": 0.9},
        )

        assert "Error: Access denied" in result
        mock_bedrock_runtime.converse.assert_called_once()

    @patch("boto3.Session")
    def test_try_model_call_general_exception(
        self, mock_session_class, mock_boto3_session, mock_context, mock_bedrock_runtime
    ):
        """Test model call with general exception."""
        mock_session_class.return_value = mock_boto3_session

        mock_bedrock_runtime.converse.side_effect = Exception("Unexpected error")

        reporter = BedrockSummaryReporter(context=mock_context)

        result = reporter._try_model_call(
            mock_bedrock_runtime,
            "us.amazon.nova-pro-v1:0",
            [{"role": "user", "content": [{"text": "Test message"}]}],
            [{"text": "Test system prompt"}],
            {"temperature": 0.5, "maxTokens": 4000, "topP": 0.9},
        )

        assert "Error generating content" in result
        assert "Unexpected error" in result
        mock_bedrock_runtime.converse.assert_called_once()
