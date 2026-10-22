# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unexpected ValidationError is logged with its type and its model's title.

For a chain holding a ValidationError, log_unexpected_error logs the error as
error_text describes it, and no traceback messages: those would quote the
refused input. The description alone named a field and a problem, with nothing
to say what had failed: not the exception's type, nor the model that refused
the field. Neither is input. The model's title is pydantic's ``title``, the
name its own text gives in "1 validation error for <title>".
"""

from typing import Dict
from unittest.mock import MagicMock

from pydantic import BaseModel, ValidationError

from automated_security_helper.utils.error_text import (
    error_text,
    log_unexpected_error,
    traceback_text,
)

CANARY = "ash-canary-7f3e"


class _Unhidden(BaseModel):
    flag: bool


class _Keyed(BaseModel):
    limits: Dict[str, int]


def _refused() -> ValidationError:
    try:
        _Unhidden.model_validate({"flag": CANARY})
    except ValidationError as error:
        assert CANARY in str(error), "the control: this model quotes its input"
        return error
    raise AssertionError("the canary was accepted")


def _logged(error: BaseException, context=None) -> str:
    logger = MagicMock()
    log_unexpected_error(logger, error, context)
    (message,), _ = logger.error.call_args
    return str(message)


def test_a_validation_error_names_its_type_and_model():
    message = _logged(_refused())
    assert message.startswith("ValidationError for _Unhidden: "), message
    assert "Invalid value at 'flag'" in message, message
    assert CANARY not in message, message


def test_the_context_comes_first():
    message = _logged(_refused(), "Error in get_config")
    assert message.startswith("Error in get_config: ValidationError for _Unhidden: ")
    assert CANARY not in message, message


def test_an_error_raised_from_one_names_both():
    refused = _refused()
    try:
        raise RuntimeError(f"could not build the plugin: {refused}") from refused
    except RuntimeError as error:
        message = _logged(error)
    assert message.startswith(
        "RuntimeError (from a ValidationError for _Unhidden): "
    ), message
    assert "could not build the plugin: Invalid value at 'flag'" in message, message
    assert CANARY not in message, message


def test_any_other_error_is_logged_with_its_traceback():
    """With its traceback, which already names its type."""
    logger = MagicMock()
    error = KeyError("missing")
    log_unexpected_error(logger, error)
    (message,), kwargs = logger.error.call_args
    assert message is error
    assert kwargs["exc_info"] is error


def _refused_at_a_key() -> ValidationError:
    """A refusal whose location is a key: the canary is the key, as when the
    config file read the key from the environment."""
    try:
        _Keyed.model_validate({"limits": {CANARY: "many"}})
    except ValidationError as error:
        return error
    raise AssertionError("the value was accepted")


def test_the_values_are_redacted_from_a_location():
    refused = _refused_at_a_key()
    # The control: the description names the key, which is the canary.
    assert CANARY in error_text(refused)
    described = error_text(refused, [CANARY])
    assert "Invalid value at 'limits." in described, described
    assert CANARY not in described, described


def test_the_values_are_redacted_from_a_traceback():
    refused = _refused_at_a_key()
    try:
        raise RuntimeError(f"could not build the plugin: {refused}") from refused
    except RuntimeError as error:
        assert CANARY in traceback_text(error), "the control"
        text = traceback_text(error, [CANARY])
    assert "could not build the plugin" in text, text
    assert CANARY not in text, text


def test_the_values_are_redacted_when_logged():
    logger = MagicMock()
    log_unexpected_error(logger, _refused_at_a_key(), "Error in x", [CANARY])
    logged = " ".join(str(call) for call in logger.mock_calls)
    assert "Error in x: ValidationError for _Keyed: " in logged, logged
    assert CANARY not in logged, logged


def test_any_other_error_is_logged_redacted_with_its_traceback():
    """Its own traceback would print the message as it is, so it is logged as
    traceback_text gives it."""
    logger = MagicMock()
    try:
        raise KeyError(CANARY)
    except KeyError as error:
        log_unexpected_error(logger, error, None, [CANARY])
    (message,), kwargs = logger.error.call_args
    assert "exc_info" not in kwargs, kwargs
    assert "Traceback (most recent call last)" in message, message
    assert "KeyError" in message, message
    assert CANARY not in message, message
