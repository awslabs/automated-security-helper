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


class TestRetryIntervals:
    """The interval is the one thing the tests above never observe.

    They pass ``base_delay=0.01`` to stay fast and then assert only the call
    count, so replacing the exponential with a constant -- or with zero -- would
    leave every one of them green while the decorator hammered a throttled API
    back-to-back. So these assert what ``time.sleep`` is handed.

    No wall-clock bound is used: an elapsed-time assertion flakes low on a fast
    machine and high on a loaded one, and would not distinguish a broken
    schedule from a busy host.
    """

    @staticmethod
    def _throttling_error():
        return botocore.exceptions.ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            "operation",
        )

    def _sleeps_while_always_failing(self, **retry_kwargs):
        mock_func = MagicMock(side_effect=self._throttling_error())
        decorated_func = retry_with_backoff(**retry_kwargs)(mock_func)

        sleeps = []
        with (
            patch(
                "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.time.sleep",
                side_effect=sleeps.append,
            ),
            pytest.raises(botocore.exceptions.ClientError),
        ):
            decorated_func()
        return sleeps, mock_func

    def test_the_interval_grows_between_retries(self):
        sleeps, mock_func = self._sleeps_while_always_failing(
            max_retries=3, base_delay=10.0, max_delay=600.0
        )

        assert mock_func.call_count == 4
        assert len(sleeps) == 3, "one wait between each pair of attempts, no more"
        assert sleeps == sorted(sleeps), sleeps
        # Jitter adds at most 1.0s and each step doubles a >=10s base, so the
        # per-attempt envelopes cannot overlap and exact bounds are safe here.
        assert 10.0 <= sleeps[0] < 11.0, sleeps
        assert 20.0 <= sleeps[1] < 21.0, sleeps
        assert 40.0 <= sleeps[2] < 41.0, sleeps

    def test_the_interval_is_capped_at_max_delay(self):
        sleeps, _ = self._sleeps_while_always_failing(
            max_retries=4, base_delay=10.0, max_delay=25.0
        )
        assert all(interval <= 25.0 for interval in sleeps), sleeps
        assert sleeps[-1] == 25.0, sleeps

    def test_a_negative_max_delay_never_reaches_sleep(self):
        """Reachable from reporter config, and it used to raise inside the retry.

        CloudWatchLogsReporter and S3Reporter both declare ``base_delay`` and
        ``max_delay`` as bare ``float`` fields with no lower bound and hand them
        straight to this decorator. ``time.sleep`` raises ValueError on a negative
        argument, and the broad ``except Exception`` in
        ``_create_log_stream_with_retry`` swallows it -- so the retry silently
        became zero retries and the warning blamed the log stream.
        """
        sleeps, mock_func = self._sleeps_while_always_failing(
            max_retries=2, base_delay=1.0, max_delay=-30.0
        )

        assert all(interval >= 0.0 for interval in sleeps), sleeps
        assert mock_func.call_count == 3, "the retries themselves must still happen"

    def test_a_negative_base_delay_never_reaches_sleep(self):
        sleeps, _ = self._sleeps_while_always_failing(
            max_retries=2, base_delay=-5.0, max_delay=60.0
        )
        assert all(interval >= 0.0 for interval in sleeps), sleeps


class TestASleepFailureIsNotAbsorbedHere:
    """Where a ValueError out of ``time.sleep`` ends up, pinned at both levels.

    Unlike the clamp tests above, neither of these fails on the unmodified
    decorator -- they are characterization, not regression. They are here because
    the clamp's value depends entirely on this pair of facts, and nothing else in
    the suite states either one. The decorator raises the sleep failure; the
    CloudWatch caller then buries it under a message naming the wrong subsystem.
    Together they explain why a negative interval was survivable enough to ship:
    the only symptom was a warning about a log stream.

    If a later change wraps the sleep in a ``try``, the first test fails and says
    so, rather than the retry quietly degrading to zero retries again.
    """

    @staticmethod
    def _throttling_error():
        return botocore.exceptions.ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            "operation",
        )

    def test_the_decorator_lets_a_sleep_failure_out(self):
        """time.sleep is called from inside the ``except`` block, so it escapes.

        An exception raised in a handler is not caught by that same handler, which
        is what keeps a bad interval from being mistaken for a retryable API
        error and looped on.
        """
        mock_func = MagicMock(side_effect=self._throttling_error())
        decorated_func = retry_with_backoff(max_retries=3, base_delay=1.0)(mock_func)

        with (
            patch(
                "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.time.sleep",
                side_effect=ValueError("sleep length must be non-negative"),
            ),
            pytest.raises(ValueError, match="non-negative"),
        ):
            decorated_func()

        assert mock_func.call_count == 1, (
            "the sleep failure must stop the loop, not be retried around"
        )

    def test_the_cloudwatch_caller_is_what_hides_it(self):
        """The broad ``except Exception`` one level up is the actual concealment.

        Asserting this is what makes the clamp's necessity legible: the reporter
        does not crash on a negative interval, it reports success-shaped failure
        with a message about the log stream. Grepping the logs for a backoff
        problem would never have found it.
        """
        from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
            CloudWatchLogsReporter,
        )

        reporter = CloudWatchLogsReporter.model_construct()
        reporter.config = MagicMock()
        reporter.config.options.max_retries = 3
        reporter.config.options.base_delay = 1.0
        reporter.config.options.max_delay = 60.0
        reporter.config.options.log_group_name = "group"
        reporter.config.options.log_stream_name = "stream"

        logged = []
        reporter._plugin_log = lambda message, **kwargs: logged.append(message)

        client = MagicMock()
        client.create_log_stream.side_effect = self._throttling_error()

        with patch(
            "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.time.sleep",
            side_effect=ValueError("sleep length must be non-negative"),
        ):
            # No pytest.raises: swallowing it is precisely the behavior recorded.
            reporter._create_log_stream_with_retry(client)

        assert len(logged) == 1, logged
        assert "Error when creating log stream" in logged[0], logged[0]
        assert "non-negative" in logged[0], (
            "the sleep failure is reported under a log-stream heading -- "
            "the misattribution that let a negative interval go unnoticed"
        )


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
