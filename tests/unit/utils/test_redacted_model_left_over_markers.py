# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No reference survives validation outside the sections of a section-reaching
field.

A value under a field that reaches another section is handed to pydantic with
its markers, so the section in the shape receives them. The slots beside the
section are downcast before that where the annotation says which slot a value
lands in, but a union of several arms keeps the value as given: which arm
describes it is pydantic's call. When pydantic then picked a sibling arm (a
``Dict[str, Any]``, a plain model with an Any field), the marker survived in
the validated model as a str subclass, which a config dump cannot write.

The field is now downcast after validation, in the containers and in the plain
models the validated value holds; a section is left to its own validator.
"""

from typing import Any, Dict, Optional, Union

import pytest
from pydantic import BaseModel, ConfigDict

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

VARIABLE = "ASH_LEFT_OVER_CANARY"


class _Closed(RedactedSection):
    """A section that refuses a key it does not declare, so a dict that holds
    one can only be taken by the sibling arm."""

    model_config = ConfigDict(extra="forbid")

    name: str = ""


class _Plain(BaseModel):
    payload: Any = None


def test_a_dict_arm_beside_a_section_arm_holds_plain_text():
    class Section(RedactedSection):
        value: Optional[Union[_Closed, Dict[str, Any]]] = None

    section = Section.model_validate(
        {"value": {"free": env_resolved_scalar("loose-text", VARIABLE)}}
    )
    assert section.value == {"free": "loose-text"}
    assert type(section.value["free"]) is str


def test_a_nested_value_in_the_dict_arm_holds_plain_text():
    class Section(RedactedSection):
        value: Optional[Union[_Closed, Dict[str, Any]]] = None

    section = Section.model_validate(
        {"value": {"free": [{"deep": env_resolved_scalar("loose-text", VARIABLE)}]}}
    )
    assert type(section.value["free"][0]["deep"]) is str


def test_a_plain_model_arm_beside_a_section_arm_holds_plain_text():
    class Section(RedactedSection):
        value: Optional[Union[_Closed, _Plain]] = None

    section = Section.model_validate(
        {"value": {"payload": env_resolved_scalar("loose-text", VARIABLE)}}
    )
    assert isinstance(section.value, _Plain)
    assert section.value.payload == "loose-text"
    assert type(section.value.payload) is str


def test_a_container_in_a_plain_model_arm_holds_plain_text():
    class Section(RedactedSection):
        value: Optional[Union[_Closed, _Plain]] = None

    section = Section.model_validate(
        {"value": {"payload": [env_resolved_scalar("loose-text", VARIABLE)]}}
    )
    assert isinstance(section.value, _Plain)
    assert type(section.value.payload[0]) is str


def test_the_section_arm_still_receives_the_text_it_takes():
    """The control: the section takes the value and downcasts its own. The
    dict arm types its values as numbers, so it cannot take this text."""

    class Section(RedactedSection):
        value: Optional[Union[_Closed, Dict[str, int]]] = None

    section = Section.model_validate(
        {"value": {"name": env_resolved_scalar("loose-text", VARIABLE)}}
    )
    assert isinstance(section.value, _Closed)
    assert section.value.name == "loose-text"
    assert type(section.value.name) is str
