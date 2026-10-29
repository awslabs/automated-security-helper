# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which refusals of a config name a key the model does not declare, and nothing else.

The pre-run gate of a container scan whose image may hold another schema
applies ``--config-overrides`` to this tree's model. A refusal whose every
error names a key this tree does not declare is the image's to judge, since
another revision may declare it; a refusal with any other error (a value of the
wrong kind, a section given a scalar) is refused by every revision, so the host
refuses it before anything is built or started.

``error_names_an_undeclared_key`` reads one entry of pydantic's ``errors()``.
The cells compare it with the words the module itself writes for such a key, so
a change to that wording fails here instead of turning the waiver off, and with
what the real model reports for the three shapes the gate meets.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.unknown_keys import (
    error_names_an_undeclared_key,
    internal_field_message,
    misplaced_key_problems,
    unknown_keys_message,
)

pytestmark = pytest.mark.unit


def _value_error(text: str) -> dict:
    """The entry pydantic reports for a ``ValueError`` a validator raised."""
    return {"type": "value_error", "msg": f"Value error, {text}"}


def _errors_of(data: dict) -> list:
    with pytest.raises(ValidationError) as refused:
        AshConfig.model_validate(data)
    return refused.value.errors()


def test_a_key_a_section_forbids_is_recognized():
    assert error_names_an_undeclared_key(
        {"type": "extra_forbidden", "msg": "Extra inputs are not permitted"}
    )


@pytest.mark.parametrize(
    "text",
    [
        unknown_keys_message(["zz_option"], ["depth", "level"], "these plugin options"),
        unknown_keys_message(["zz_one", "zz_two"], [], "these plugin options"),
        *misplaced_key_problems(
            ["zz_key"], ["enabled", "options"], {"depth"}, "scanners.bandit"
        ),
        *misplaced_key_problems(
            ["depth"], ["enabled", "options"], {"depth"}, "scanners.bandit"
        ),
        *misplaced_key_problems(
            ["tool_version"],
            ["enabled", "options"],
            {"tool_version"},
            "scanners.bandit",
        ),
        internal_field_message("scanners", "bandit", "tool_version"),
    ],
)
def test_the_words_the_module_gives_an_undeclared_key_are_recognized(text):
    assert error_names_an_undeclared_key(_value_error(text)), text


@pytest.mark.parametrize(
    "error",
    [
        {
            "type": "bool_parsing",
            "msg": "Input should be a valid boolean, unable to interpret input",
        },
        {
            "type": "model_type",
            "msg": "Input should be a valid dictionary or instance of a section",
        },
        {"type": "literal_error", "msg": "Input should be 'a' or 'b'"},
        {"type": "missing", "msg": "Field required"},
        _value_error("a different reason, with no key named"),
        {"type": "value_error"},
        {},
    ],
    ids=[
        "wrong-kind",
        "not-a-section",
        "outside-the-literal",
        "missing",
        "another-value-error",
        "value-error-without-a-message",
        "empty",
    ],
)
def test_an_error_about_a_value_or_the_documents_shape_is_not(error):
    assert not error_names_an_undeclared_key(error), error


def test_a_key_a_real_section_forbids_is_recognized_through_the_model():
    errors = _errors_of({"global_settings": {"zz_option_a_later_schema_declares": 1}})

    assert errors and all(error_names_an_undeclared_key(e) for e in errors), errors


def test_an_unknown_plugin_option_is_recognized_through_the_model():
    errors = _errors_of(
        {"scanners": {"bandit": {"options": {"zz_option_a_later_schema_declares": 1}}}}
    )

    assert errors and all(error_names_an_undeclared_key(e) for e in errors), errors


@pytest.mark.parametrize(
    "data",
    [{"fail_on_findings": "maybe"}, {"global_settings": 7}],
    ids=["wrong-kind-of-value", "a-section-given-a-scalar"],
)
def test_a_value_the_real_model_refuses_is_not_recognized(data):
    errors = _errors_of(data)

    assert errors and not any(error_names_an_undeclared_key(e) for e in errors), errors
