# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import random
import time
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar

import botocore.exceptions

from automated_security_helper.utils.log import ASH_LOGGER

# Type variable for the return type of the function
T = TypeVar("T")

# List of retryable exceptions
RETRYABLE_EXCEPTIONS = [
    "ThrottlingException",
    "Throttling",
    "ThrottledException",
    "RequestThrottledException",
    "TooManyRequestsException",
    "ProvisionedThroughputExceededException",
    "TransactionInProgressException",
    "RequestLimitExceeded",
    "BandwidthLimitExceeded",
    "LimitExceededException",
    "RequestThrottled",
    "SlowDown",
    "ServiceUnavailable",
    "InternalServerError",
    "InternalFailure",
    "ServiceFailure",
    "ConnectionError",
    "HTTPClientError",
]


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    retryable_exceptions: Optional[List[str]] = None,
    logger: Optional[Any] = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator for AWS API calls that implements exponential backoff with jitter.

    Args:
        max_retries: Maximum number of retries before giving up
        base_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries in seconds
        retryable_exceptions: List of exception names that should trigger a retry
        logger: Logger to use for logging retry attempts

    Returns:
        Decorated function with retry logic
    """
    if retryable_exceptions is None:
        retryable_exceptions = RETRYABLE_EXCEPTIONS

    if logger is None:
        logger = ASH_LOGGER

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            retries = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    # Get the exception name
                    exception_name = e.__class__.__name__
                    error_code = None

                    # Extract error code based on exception type
                    if isinstance(e, botocore.exceptions.ClientError):
                        error_code = e.response.get("Error", {}).get("Code")
                    else:
                        error_code = getattr(e, "code", None)

                    # Check if we should retry based on the exception
                    should_retry = retries < max_retries and (
                        exception_name in retryable_exceptions
                        or (error_code and error_code in retryable_exceptions)
                    )

                    if not should_retry:
                        # If we shouldn't retry, re-raise the exception
                        raise

                    # Calculate delay with exponential backoff and jitter
                    delay = min(
                        base_delay * (2**retries) + random.uniform(0, 1), max_delay
                    )

                    # Log the retry
                    logger.warning(
                        f"Retrying due to {exception_name} ({error_code}). "
                        f"Attempt {retries + 1}/{max_retries} after {delay:.2f}s delay"
                    )

                    # Sleep before retrying
                    time.sleep(delay)
                    retries += 1

        return wrapper

    return decorator


def get_available_models(bedrock_client: Any) -> List[Dict[str, Any]]:
    """Get available foundation models in the current region

    Returns:
        List of available models with their details, including inference profile ARNs for models
        that only support inference profiles
    """
    try:
        final_model_list = []
        inference_profiles = bedrock_client.list_inference_profiles()
        model_profile_map = {}
        for profile in inference_profiles.get("inferenceProfileSummaries", []):
            for model in [
                item
                for item in profile.get("models", [])
                if item.get("modelArn", None) is not None
            ]:
                model_profile_map[model["modelArn"]] = profile
        ASH_LOGGER.debug("Fetching available foundation models...")
        # Get foundation models
        response = bedrock_client.list_foundation_models()
        active_models = [
            item
            for item in response.get("modelSummaries", [])
            if item.get("modelLifecycle", {}).get("status", "NA") == "ACTIVE"
            and "TEXT" in item.get("inputModalities", [])
            and "TEXT" in item.get("outputModalities", [])
        ]
        ASH_LOGGER.debug(f"Found {len(active_models)} active foundation models")
        for model in active_models:
            if "ON_DEMAND" in model.get("inferenceTypesSupported", []):
                final_model_list.append(
                    {
                        "modelId": model.get("modelId", "unknown"),
                        "modelName": model.get("modelName", "unknown"),
                        "modelArn": model.get("modelArn", "unknown"),
                        "providerName": model.get("providerName", "unknown"),
                        "inferenceType": "ON_DEMAND",
                    }
                )
            if "INFERENCE_PROFILE" in model.get("inferenceTypesSupported", []):
                if model.get("modelArn", "unknown") not in model_profile_map:
                    # Unable to find the inference profile ID!
                    continue
                final_model_list.append(
                    {
                        "modelId": model_profile_map[model.get("modelArn", "unknown")][
                            "inferenceProfileId"
                        ],
                        "modelName": model.get("modelName", "unknown"),
                        "modelArn": model.get("modelArn", "unknown"),
                        "providerName": model.get("providerName", "unknown"),
                        "inferenceType": "INFERENCE_PROFILE",
                    }
                )

        available_models = final_model_list
        return available_models
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        error_message = e.response.get("Error", {}).get("Message")
        ASH_LOGGER.warning(
            f"Bedrock API error when getting available models ({error_code}): {error_message}"
        )
        return []
    except Exception as e:
        ASH_LOGGER.warning(f"Unexpected error getting available models: {str(e)}")
        return []


def get_fallback_model(current_model_id: str) -> Optional[str]:
    """
    Get a fallback model ID if the current model is unavailable.

    Args:
        current_model_id: The current model ID that failed

    Returns:
        A fallback model ID or None if no suitable fallback is available
    """
    # Define fallback chains for different model families
    fallback_chains = {
        "anthropic.claude-": [
            "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "anthropic.claude-3-5-haiku-20241022-v1:0",
        ],
        "us.anthropic.claude-": [
            "us.anthropic.claude-sonnet-4-20250514-v1:0",
            # "us.anthropic.claude-opus-4-20250514-v1:0",
            "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
            "us.anthropic.claude-3-5-sonnet-20240620-v1:0",
        ],
        "amazon.titan-": [
            "amazon.titan-text-express-v1",
            "amazon.titan-text-lite-v1",
        ],
        "us.amazon.nova-": [
            "us.amazon.nova-pro-v1:0",
            "us.amazon.nova-lite-v1:0",
            "us.amazon.nova-micro-v1:0",
        ],
        "us.meta.llama3-": [
            "us.meta.llama3-3-70b-instruct-v1:0",
            "us.meta.llama3-2-1b-instruct-v1:0",
            "us.meta.llama3-2-3b-instruct-v1:0",
            "us.meta.llama3-2-11b-instruct-v1:0",
            "us.meta.llama3-1-8b-instruct-v1:0",
        ],
        "us.meta.llama4-": [
            "us.meta.llama4-scout-17b-instruct-v1:0",
            "us.meta.llama4-maverick-17b-instruct-v1:0",
        ],
    }

    # Find the appropriate fallback chain
    for prefix, models in fallback_chains.items():
        if current_model_id.startswith(prefix):
            # Find the current model in the chain
            try:
                current_index = models.index(current_model_id)
                # Return the next model in the chain if available
                if current_index < len(models) - 1:
                    return models[current_index + 1]
            except ValueError:
                # If the current model isn't in our predefined list,
                # return the first model in the chain
                return models[0]

    # If no specific fallback chain is found, return a default model
    return "us.amazon.nova-pro-v1:0"


def validate_bedrock_model(
    bedrock_client: Any, model_id: str
) -> tuple[bool, Optional[str]]:
    """
    Validate that a Bedrock model is available and accessible.

    Args:
        bedrock_client: Boto3 Bedrock client
        model_id: The model ID to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Get all available models
        available_models = get_available_models(bedrock_client)
        if not available_models:
            ASH_LOGGER.warning("No available models found in the current region")
            return False, "No available models found in the current region"

        # Extract model IDs from the available models
        available_model_ids = [model.get("modelId") for model in available_models]

        # Check if the requested model is in the available models
        if model_id in available_model_ids:
            ASH_LOGGER.debug(f"Model {model_id} is available")
            return True, None

        # If model not found directly, try to find a matching model ID (case insensitive)
        for available_id in available_model_ids:
            if available_id and model_id and available_id.lower() == model_id.lower():
                ASH_LOGGER.debug(
                    f"Found model {available_id} matching {model_id} (case insensitive)"
                )
                return True, None

        # If still not found, check if it's an inference profile model
        for model in available_models:
            if (
                model.get("inferenceType") == "INFERENCE_PROFILE"
                and model.get("modelId") == model_id
            ):
                ASH_LOGGER.debug(
                    f"Model {model_id} is available as an inference profile"
                )
                return True, None

        # Model not found in available models
        ASH_LOGGER.warning(
            f"Model {model_id} not found in available models: {available_model_ids}"
        )
        return False, f"Model {model_id} not found in available models"

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        error_message = e.response.get("Error", {}).get("Message")

        ASH_LOGGER.warning(f"Bedrock API error ({error_code}): {error_message}")

        if error_code == "AccessDeniedException":
            return False, f"Access denied to model {model_id}: {error_message}"
        elif error_code == "ResourceNotFoundException":
            return False, f"Model {model_id} not found: {error_message}"
        else:
            return False, f"Error validating model {model_id}: {error_message}"
    except Exception as e:
        ASH_LOGGER.warning(f"Unexpected error validating model {model_id}: {str(e)}")
        return False, f"Unexpected error validating model {model_id}: {str(e)}"
