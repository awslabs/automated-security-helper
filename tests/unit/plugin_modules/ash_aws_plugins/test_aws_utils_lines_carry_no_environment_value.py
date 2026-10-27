# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""aws_utils' model lines carry no value the config read from the environment.

The Bedrock model id is a configured value, which can come from the
environment (``${VAR}``). ``validate_bedrock_model`` and
``get_available_models`` are module functions with no config in scope, so the
values to redact arrive as a parameter (``values``), the way ``error_text``
takes them: the caller passes what its config read from the environment, and
every line these functions log, and every error string they return (the
caller records those), is redacted with them.
"""

import logging
from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    get_available_models,
    validate_bedrock_model,
)
from automated_security_helper.utils.log import ASH_LOGGER

_MOD = "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils"

#: Long and dotted like a real model id, so redaction replaces it anywhere.
MODEL_CANARY = "us.envcanary.fi77-model-v1:0"


@pytest.fixture
def logged():
    lines = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(logging.Formatter("%(message)s").format(record))

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _client_offering(model_id):
    client = MagicMock()
    client.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    client.list_foundation_models.return_value = {
        "modelSummaries": [
            {
                "modelId": model_id,
                "modelName": "canary",
                "modelArn": f"arn:aws:bedrock:::{model_id}",
                "providerName": "canary",
                "modelLifecycle": {"status": "ACTIVE"},
                "inputModalities": ["TEXT"],
                "outputModalities": ["TEXT"],
                "inferenceTypesSupported": ["ON_DEMAND"],
            }
        ]
    }
    return client


def test_an_available_model_line_carries_no_environment_value(logged):
    client = _client_offering(MODEL_CANARY)

    is_valid, error_message = validate_bedrock_model(
        client, MODEL_CANARY, values=[MODEL_CANARY]
    )

    assert is_valid is True and error_message is None
    line = next(line for line in logged if "is available" in line)
    assert "envcanary" not in line.lower(), line


def test_a_model_not_found_line_carries_no_environment_value(logged):
    client = _client_offering("us.other.model-v1:0")

    is_valid, error_message = validate_bedrock_model(
        client, MODEL_CANARY, values=[MODEL_CANARY]
    )

    assert is_valid is False
    assert "not found" in error_message, error_message
    assert "envcanary" not in error_message.lower(), error_message
    line = next(line for line in logged if "not found in available models" in line)
    assert "envcanary" not in line.lower(), line


def test_a_validation_error_carries_no_environment_value(logged):
    client = MagicMock()

    with patch(
        f"{_MOD}.get_available_models",
        side_effect=RuntimeError(f"could not load {MODEL_CANARY}"),
    ):
        is_valid, error_message = validate_bedrock_model(
            client, MODEL_CANARY, values=[MODEL_CANARY]
        )

    assert is_valid is False
    assert "Unexpected error" in error_message, error_message
    assert "envcanary" not in error_message.lower(), error_message
    line = next(line for line in logged if "Unexpected error validating" in line)
    assert "envcanary" not in line.lower(), line


def test_an_access_denied_error_carries_no_environment_value(logged):
    client = MagicMock()
    denied = botocore.exceptions.ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": f"no access to {MODEL_CANARY}",
            }
        },
        "ListFoundationModels",
    )

    with patch(f"{_MOD}.get_available_models", side_effect=denied):
        is_valid, error_message = validate_bedrock_model(
            client, MODEL_CANARY, values=[MODEL_CANARY]
        )

    assert is_valid is False
    assert "Access denied" in error_message, error_message
    assert "envcanary" not in error_message.lower(), error_message
    line = next(line for line in logged if "Bedrock API error" in line)
    assert "envcanary" not in line.lower(), line


def test_an_available_models_error_line_carries_no_environment_value(logged):
    client = MagicMock()
    client.list_inference_profiles.side_effect = RuntimeError(
        f"no credentials for {MODEL_CANARY}"
    )

    models = get_available_models(client, values=[MODEL_CANARY])

    assert models == []
    line = next(
        line for line in logged if "Unexpected error getting available models" in line
    )
    assert "envcanary" not in line.lower(), line


# The sinks no cell above reached.


def _refused(message):
    return botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": message}},
        "ListInferenceProfiles",
    )


def test_a_case_insensitive_match_line_carries_no_environment_value(logged):
    """The region offers the configured model under another case."""
    client = _client_offering(MODEL_CANARY.upper())

    is_valid, error_message = validate_bedrock_model(
        client, MODEL_CANARY, values=[MODEL_CANARY]
    )

    assert is_valid is True and error_message is None
    line = next(line for line in logged if "(case insensitive)" in line)
    assert "envcanary" not in line.lower(), line


def test_an_available_models_api_error_line_carries_no_environment_value(logged):
    """get_available_models' ClientError WARNING, called directly."""
    client = MagicMock()
    client.list_inference_profiles.side_effect = _refused(
        f"no access to {MODEL_CANARY}"
    )

    assert get_available_models(client, values=[MODEL_CANARY]) == []
    line = next(
        line for line in logged if "Bedrock API error when getting available" in line
    )
    assert "no access to" in line, line
    assert "envcanary" not in line.lower(), line


def test_validation_hands_its_values_to_the_model_listing(logged):
    """validate_bedrock_model passes the values on: the listing's own WARNING."""
    client = MagicMock()
    client.list_inference_profiles.side_effect = _refused(
        f"no access to {MODEL_CANARY}"
    )

    is_valid, _ = validate_bedrock_model(client, MODEL_CANARY, values=[MODEL_CANARY])

    assert is_valid is False
    line = next(
        line for line in logged if "Bedrock API error when getting available" in line
    )
    assert "envcanary" not in line.lower(), line
