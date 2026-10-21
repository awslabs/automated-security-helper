# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A model error shows no refused value, in any form its validator wrote it.

``ConfigValidator.format_model_error`` replaces each refused input in the
message by ``<value>``, matching the input as given and as repr() and JSON
escape it. A validator that quotes a changed form of its input, upper-cased or
with its separators taken out, would get past that match alone. Such a message
has the changed form replaced too, or is not shown at all.

pydantic's own messages never quote the input, and some list the values a
field accepts ("Input should be 'LOW', 'MEDIUM' ..."), so only a message a
validator wrote is matched this way.
"""

from __future__ import annotations

import re

import pytest
from pydantic import BaseModel, ValidationError, ValidationInfo, field_validator

from automated_security_helper.config.config_validator import (
    ConfigValidator,
    describe_validation_error,
)

CANARY = "ash-canary-7f3e-0123456789"

#: How a validator might write its input back.
CHANGES = {
    "as-given": lambda value: value,
    "upper": str.upper,
    "title": str.title,
    "swapcase": str.swapcase,
    "without-separators": lambda value: value.replace("-", ""),
    "spaced-out": lambda value: " ".join(value),
    "underscored": lambda value: value.replace("-", "_").upper(),
}


class _Checked(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def _refuse(cls, value: str, info: ValidationInfo) -> str:
        change = (info.context or {})["change"]
        raise ValueError(f"not a known name: {change(value)}")


class _Severity(BaseModel):
    severity: str

    @field_validator("severity")
    @classmethod
    def _refuse(cls, value: str) -> str:
        raise ValueError("severity must be one of LOW, MEDIUM or CRITICAL")


def _squeezed(text: str) -> str:
    return re.sub(r"[\W_]", "", text).casefold()


def _shows_the_value(text: str) -> bool:
    return _squeezed(CANARY) in _squeezed(text)


def _error(change) -> dict:
    with pytest.raises(ValidationError) as caught:
        _Checked.model_validate({"name": CANARY}, context={"change": change})
    return caught.value.errors()[0]


@pytest.mark.parametrize("change", sorted(CHANGES))
def test_the_message_shows_no_form_of_the_value(change):
    message = ConfigValidator.format_model_error(_error(CHANGES[change]))
    # The control: the message is the one for this field.
    assert message.startswith("Invalid value at 'name': "), message.split(":")[0]
    assert not _shows_the_value(message), f"a {change} form of the value is shown"


@pytest.mark.parametrize("change", ["as-given", "upper", "title"])
def test_a_quoted_value_is_replaced_in_place(change):
    """Where the changed form can be replaced, the validator's own words stay."""
    message = ConfigValidator.format_model_error(_error(CHANGES[change]))
    assert "not a known name: <value>" in message, "not replaced in place"


def test_the_one_description_shows_no_form_of_the_value():
    with pytest.raises(ValidationError) as caught:
        _Checked.model_validate({"name": CANARY}, context={"change": str.upper})
    text = describe_validation_error(caught.value)
    assert "Invalid value at 'name'" in text
    assert not _shows_the_value(text)


def test_a_validator_naming_what_is_accepted_keeps_it_for_an_unrelated_value():
    """The values a message lists are the schema's words, not the input's: an
    input that is none of them leaves them readable."""
    with pytest.raises(ValidationError) as caught:
        _Severity.model_validate({"severity": "urgent-please"})
    message = ConfigValidator.format_model_error(caught.value.errors()[0])
    assert "LOW, MEDIUM or CRITICAL" in message, message


def test_pydantic_s_own_list_of_accepted_values_stays_readable():
    """A literal's error lists what it accepts, and pydantic never quotes the
    input in it: an input that differs from an accepted value only in case
    leaves the list as it is."""
    from typing import Literal

    class _Literal(BaseModel):
        level: Literal["CRITICAL", "MEDIUM"]

    with pytest.raises(ValidationError) as caught:
        _Literal.model_validate({"level": "critical"})
    message = ConfigValidator.format_model_error(caught.value.errors()[0])
    assert "'CRITICAL'" in message and "'MEDIUM'" in message, message
