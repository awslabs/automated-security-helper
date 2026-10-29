# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""In a union, a container-shaped arm speaks for a value's markers only when
pydantic would accept the value at that arm.

The typed walk admitted a union as soon as one arm that could hold the value
kept every marker as text, even when that arm would fail validation for
another reason: a fixed tuple of another length, a model given a key it does
not declare (a marker under it is never read) or missing a field it requires.
pydantic refuses such an arm and its smart-mode union hands the value to a
sibling, so the sibling converted the env-read text and printed it in clear
while the walk had read it as kept.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple, Union

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_ARM_CANARY"


def _refusal_text(model_type, payload) -> str:
    with pytest.raises(ValidationError) as refused:
        model_type.model_validate(payload)
    return " ".join(
        f"{error['loc']}: {error['msg']}" for error in refused.value.errors()
    )


def _assert_named_not_echoed(text: str, field: str) -> None:
    assert VARIABLE in text, text
    assert field in text, text
    assert CANARY not in text.replace(field, ""), text


class _Closed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    count: int = 0


class _Needs(BaseModel):
    count: int


class _Named(BaseModel):
    name: str = ""


class _Open(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str = ""


def test_a_model_arm_given_an_undeclared_marker_key_does_not_mask_a_sibling():
    class Section(RedactedSection):
        value: Optional[Union[_Closed, Dict[str, int]]] = None

    text = _refusal_text(
        Section, {"value": {"other": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "value")


def test_a_model_arm_missing_a_required_field_does_not_mask_a_sibling():
    class Section(RedactedSection):
        value: Optional[Union[_Needs, Dict[str, int]]] = None

    text = _refusal_text(
        Section, {"value": {"other": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "value")


def test_a_fixed_tuple_arm_of_another_length_does_not_mask_a_sibling():
    class Section(RedactedSection):
        value: Optional[Union[Tuple[str, str], List[int]]] = None

    text = _refusal_text(Section, {"value": [env_resolved_scalar(CANARY, VARIABLE)]})
    _assert_named_not_echoed(text, "value")


def test_a_model_arm_that_takes_the_value_still_admits_the_text():
    """The control: the marker sits under a declared str field, so the model
    arm holds it as text and the reference is admitted and downcast."""

    class Section(RedactedSection):
        value: Optional[Union[_Named, Dict[str, int]]] = None

    section = Section.model_validate(
        {"value": {"name": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    assert section.value == _Named(name=CANARY)
    assert type(section.value.name) is str


def test_an_undeclared_marker_key_with_no_converting_sibling_is_downcast():
    """No arm speaks for the marker, so the walk refuses nothing and the
    downcast hands pydantic plain text, which the open model keeps as an
    extra."""

    class Section(RedactedSection):
        value: Optional[Union[_Open, List[int]]] = None

    section = Section.model_validate(
        {"value": {"other": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    assert section.value.__pydantic_extra__ == {"other": CANARY}
    assert type(section.value.__pydantic_extra__["other"]) is str
