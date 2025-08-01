"""
Tests for the AWS utils module.
"""

from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    get_available_models,
    get_fallback_model,
    retry_with_backoff,
    validate_bedrock_model,
)


class TestRetryWithBackoff:
    """Tests for the retry_with_backoff decorator."""

    def test_retry_success_first_attempt(self):
        """Test successful function call on first attempt."""
        mock_func = MagicMock(return_value="success")
        decorated_func = retry_with_backoff()(mock_func)

        result = decorated_func("arg1", kwarg1="value1")

        assert result == "success"
        mock_func.assert_called_once_with("arg1", kwarg1="value1")

    def test_retry_success_after_retries(self):
        """Test successful function call after retries."""
        # Function fails twice then succeeds
        mock_func = MagicMock(
            side_effect=[
                botocore.exceptions.ClientError(
                    {
                        "Error": {
                            "Code": "ThrottlingException",
                            "Message": "Rate exceeded",
                        }
                    },
                    "operation",
                ),
                botocore.exceptions.ClientError(
                    {
                        "Error": {
                            "Code": "ThrottlingException",
                            "Message": "Rate exceeded",
                        }
                    },
                    "operation",
                ),
                "success",
            ]
        )

        # Use a very short delay for testing
        decorated_func = retry_with_backoff(
            max_retries=3, base_delay=0.01, max_delay=0.1
        )(mock_func)

        result = decorated_func("arg1", kwarg1="value1")

        assert result == "success"
        assert mock_func.call_count == 3
        mock_func.assert_called_with("arg1", kwarg1="value1")

    def test_retry_max_retries_exceeded(self):
        """Test when max retries are exceeded."""
        # Function always fails with retryable error
        error = botocore.exceptions.ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            "operation",
        )
        mock_func = MagicMock(side_effect=error)

        # Use a very short delay for testing
        decorated_func = retry_with_backoff(
            max_retries=2, base_delay=0.01, max_delay=0.1
        )(mock_func)

        with pytest.raises(botocore.exceptions.ClientError) as excinfo:
            decorated_func("arg1", kwarg1="value1")

        assert mock_func.call_count == 3  # Initial call + 2 retries
        assert "ThrottlingException" in str(excinfo.value)

    def test_retry_non_retryable_error(self):
        """Test when a non-retryable error occurs."""
        # Function fails with non-retryable error
        error = botocore.exceptions.ClientError(
            {"Error": {"Code": "ValidationError", "Message": "Invalid parameter"}},
            "operation",
        )
        mock_func = MagicMock(side_effect=error)

        decorated_func = retry_with_backoff()(mock_func)

        with pytest.raises(botocore.exceptions.ClientError) as excinfo:
            decorated_func("arg1", kwarg1="value1")

        mock_func.assert_called_once_with("arg1", kwarg1="value1")
        assert "ValidationError" in str(excinfo.value)


class TestGetAvailableModels:
    """Tests for the get_available_models function."""

    def test_get_available_models_success(self):
        """Test successful retrieval of available models."""
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
                },
                {
                    "modelId": "us.amazon.nova-lite-v1:0",
                    "modelName": "Amazon Nova Lite",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1",
                    "providerName": "Amazon",
                    "inputModalities": ["TEXT"],
                    "outputModalities": ["TEXT"],
                    "inferenceTypesSupported": ["ON_DEMAND"],
                    "modelLifecycle": {"status": "ACTIVE"},
                },
                {
                    "modelId": "us.anthropic.claude-3-5-sonnet-20240620-v1:0",
                    "modelName": "Claude 3.5 Sonnet",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20240620-v1",
                    "providerName": "Anthropic",
                    "inputModalities": ["TEXT"],
                    "outputModalities": ["TEXT"],
                    "inferenceTypesSupported": ["ON_DEMAND"],
                    "modelLifecycle": {"status": "ACTIVE"},
                },
                {
                    "modelId": "inactive-model",
                    "modelName": "Inactive Model",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/inactive-model",
                    "providerName": "Test",
                    "inputModalities": ["TEXT"],
                    "outputModalities": ["TEXT"],
                    "inferenceTypesSupported": ["ON_DEMAND"],
                    "modelLifecycle": {"status": "INACTIVE"},
                },
                {
                    "modelId": "image-model",
                    "modelName": "Image Model",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/image-model",
                    "providerName": "Test",
                    "inputModalities": ["IMAGE"],
                    "outputModalities": ["TEXT"],
                    "inferenceTypesSupported": ["ON_DEMAND"],
                    "modelLifecycle": {"status": "ACTIVE"},
                },
            ]
        }

        # Mock list_inference_profiles response
        mock_client.list_inference_profiles.return_value = {
            "inferenceProfileSummaries": [
                {
                    "inferenceProfileId": "profile-1",
                    "inferenceProfileName": "Test Profile",
                    "models": [
                        {
                            "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/profile-model",
                        }
                    ],
                }
            ]
        }

        result = get_available_models(mock_client)

        # Should return 3 models (2 Nova models and Claude, excluding inactive and image models)
        assert len(result) == 3

        # Check that the models are correctly filtered and transformed
        model_ids = [model["modelId"] for model in result]
        assert "us.amazon.nova-pro-v1:0" in model_ids
        assert "us.amazon.nova-lite-v1:0" in model_ids
        assert "us.anthropic.claude-3-5-sonnet-20240620-v1:0" in model_ids
        assert "inactive-model" not in model_ids
        assert "image-model" not in model_ids

    def test_get_available_models_client_error(self):
        """Test handling of client error when getting available models."""
        mock_client = MagicMock()

        # Mock client error
        mock_client.list_foundation_models.side_effect = (
            botocore.exceptions.ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": "Access denied",
                    }
                },
                "list_foundation_models",
            )
        )

        result = get_available_models(mock_client)

        # Should return empty list on error
        assert result == []

    def test_get_available_models_general_exception(self):
        """Test handling of general exception when getting available models."""
        mock_client = MagicMock()

        # Mock general exception
        mock_client.list_foundation_models.side_effect = Exception("Unexpected error")

        result = get_available_models(mock_client)

        # Should return empty list on error
        assert result == []


class TestGetFallbackModel:
    """Tests for the get_fallback_model function."""

    def test_get_fallback_model_same_family(self):
        """Test getting fallback model from the same family."""
        # Test with a model that's in the fallback chain
        result = get_fallback_model("us.amazon.nova-pro-v1:0")
        assert result == "us.amazon.nova-lite-v1:0"

        # Test with the last model in a chain
        result = get_fallback_model("us.amazon.nova-micro-v1:0")
        assert result is None or result != "us.amazon.nova-micro-v1:0"

    def test_get_fallback_model_not_in_chain(self):
        """Test getting fallback model for a model not in the chain."""
        # Test with a model that matches a prefix but isn't in the chain
        result = get_fallback_model("us.amazon.nova-unknown-v1:0")
        assert result == "us.amazon.nova-pro-v1:0"  # Should return first in chain

    def test_get_fallback_model_unknown_family(self):
        """Test getting fallback model for an unknown model family."""
        # Test with a completely unknown model
        result = get_fallback_model("unknown-model-family")
        assert result == "us.amazon.nova-pro-v1:0"  # Should return default


class TestValidateBedrockModel:
    """Tests for the validate_bedrock_model function."""

    def test_validate_model_success(self):
        """Test successful model validation."""
        mock_client = MagicMock()

        # Mock get_available_models to return a list with our test model
        with patch(
            "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.get_available_models"
        ) as mock_get_models:
            mock_get_models.return_value = [
                {
                    "modelId": "us.amazon.nova-pro-v1:0",
                    "modelName": "Amazon Nova Pro",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-pro-v1",
                    "providerName": "Amazon",
                    "inferenceType": "ON_DEMAND",
                }
            ]

            is_valid, error_message = validate_bedrock_model(
                mock_client, "us.amazon.nova-pro-v1:0"
            )

        assert is_valid is True
        assert error_message is None

    def test_validate_model_case_insensitive(self):
        """Test model validation with case-insensitive matching."""
        mock_client = MagicMock()

        # Mock get_available_models to return a list with our test model
        with patch(
            "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.get_available_models"
        ) as mock_get_models:
            mock_get_models.return_value = [
                {
                    "modelId": "us.amazon.nova-pro-v1:0",
                    "modelName": "Amazon Nova Pro",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-pro-v1",
                    "providerName": "Amazon",
                    "inferenceType": "ON_DEMAND",
                }
            ]

            is_valid, error_message = validate_bedrock_model(
                mock_client, "US.AMAZON.NOVA-PRO-V1:0"
            )

        assert is_valid is True
        assert error_message is None

    def test_validate_model_inference_profile(self):
        """Test validation of an inference profile model."""
        mock_client = MagicMock()

        # Mock get_available_models to return a list with an inference profile model
        with patch(
            "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.get_available_models"
        ) as mock_get_models:
            mock_get_models.return_value = [
                {
                    "modelId": "profile-1",
                    "modelName": "Profile Model",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/profile-model",
                    "providerName": "Amazon",
                    "inferenceType": "INFERENCE_PROFILE",
                }
            ]

            is_valid, error_message = validate_bedrock_model(mock_client, "profile-1")

        assert is_valid is True
        assert error_message is None

    def test_validate_model_not_found(self):
        """Test validation of a model that doesn't exist."""
        mock_client = MagicMock()

        # Mock get_available_models to return a list without our test model
        with patch(
            "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.get_available_models"
        ) as mock_get_models:
            mock_get_models.return_value = [
                {
                    "modelId": "us.amazon.nova-lite-v1:0",
                    "modelName": "Amazon Nova Lite",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1",
                    "providerName": "Amazon",
                    "inferenceType": "ON_DEMAND",
                }
            ]

            is_valid, error_message = validate_bedrock_model(
                mock_client, "us.amazon.nova-pro-v1:0"
            )

        assert is_valid is False
        assert "not found" in error_message

    def test_validate_model_no_models_available(self):
        """Test validation when no models are available."""
        mock_client = MagicMock()

        # Mock get_available_models to return an empty list
        with patch(
            "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.get_available_models"
        ) as mock_get_models:
            mock_get_models.return_value = []

            is_valid, error_message = validate_bedrock_model(
                mock_client, "us.amazon.nova-pro-v1:0"
            )

        assert is_valid is False
        assert "No available models" in error_message

    def test_validate_model_client_error(self):
        """Test validation with client error."""
        mock_client = MagicMock()

        # Mock get_available_models to raise a client error
        with patch(
            "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.get_available_models"
        ) as mock_get_models:
            mock_get_models.side_effect = botocore.exceptions.ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": "Access denied",
                    }
                },
                "list_foundation_models",
            )

            is_valid, error_message = validate_bedrock_model(
                mock_client, "us.amazon.nova-pro-v1:0"
            )

        assert is_valid is False
        assert "Access denied" in error_message

    def test_validate_model_general_exception(self):
        """Test validation with general exception."""
        mock_client = MagicMock()

        # Mock get_available_models to raise a general exception
        with patch(
            "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.get_available_models"
        ) as mock_get_models:
            mock_get_models.side_effect = Exception("Unexpected error")

            is_valid, error_message = validate_bedrock_model(
                mock_client, "us.amazon.nova-pro-v1:0"
            )

        assert is_valid is False
        assert "Unexpected error" in error_message
