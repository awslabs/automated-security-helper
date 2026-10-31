# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A union arm speaks for a value's markers only when it validates the value.

The walk admitted a union as soon as one arm that could hold the container
kept every marker as text. An arm that keeps a marker as text can still fail
on the rest of the value: ``List[str]`` fails on a number beside the marker,
``List[Literal["a"]]`` fails on any text that is no constant, and a section
arm refuses the value in its own before-validator when a field of it converts
text. pydantic then hands the whole value to a sibling arm, and the sibling
(``List[int]``, ``Dict[str, int]``) typed the env-read text and printed it in
a spelling the needle never matched.

The arm now has to validate the value, the markers downcast as the validator
hands them on (a section arm gets them as they are), before it can vouch.
"""

from typing import Dict, List, Literal, Optional, Union

import pytest
from pydantic import ValidationError

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_VALIDATES_CANARY"


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


class _Counted(RedactedSection):
    limit: int = 0


class _Named(RedactedSection):
    name: str = ""


def test_a_list_arm_that_fails_on_another_item_does_not_speak_for_the_marker():
    class Section(RedactedSection):
        value: Optional[Union[List[str], List[int]]] = None

    text = _refusal_text(Section, {"value": [env_resolved_scalar(CANARY, VARIABLE), 5]})
    _assert_named_not_echoed(text, "value")


def test_a_list_arm_that_validates_the_whole_value_still_admits_the_text():
    """The control: the list holds only strings, so the str arm takes it."""

    class Section(RedactedSection):
        value: Optional[Union[List[str], List[int]]] = None

    section = Section.model_validate(
        {"value": [env_resolved_scalar(CANARY, VARIABLE), "other"]}
    )
    assert section.value == [CANARY, "other"]
    assert all(type(item) is str for item in section.value)


def test_a_literal_item_arm_that_refuses_the_text_does_not_speak_for_the_marker():
    class Section(RedactedSection):
        value: Optional[Union[List[Literal["a"]], List[int]]] = None

    text = _refusal_text(Section, {"value": [env_resolved_scalar(CANARY, VARIABLE)]})
    _assert_named_not_echoed(text, "value")


def test_a_literal_item_arm_that_keeps_the_text_still_admits_it():
    class Section(RedactedSection):
        value: Optional[Union[List[Literal["a"]], List[int]]] = None

    section = Section.model_validate({"value": [env_resolved_scalar("a", VARIABLE)]})
    assert section.value == ["a"]
    assert type(section.value[0]) is str


def test_a_section_arm_that_refuses_the_value_does_not_speak_for_the_marker():
    """The section arm is opaque to the walk (its own validator judges its
    markers), and its own validator refuses a reference at its int field. The
    dict arm that comes first would type the text, so the union is refused."""

    class Section(RedactedSection):
        value: Optional[Union[Dict[str, int], _Counted]] = None

    text = _refusal_text(
        Section, {"value": {"limit": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "value")


def test_a_section_arm_that_takes_the_value_still_admits_the_text():
    """The control: the marker sits at the section's str field, which keeps it."""

    class Section(RedactedSection):
        value: Optional[Union[Dict[str, int], _Named]] = None

    section = Section.model_validate(
        {"value": {"name": env_resolved_scalar("text", VARIABLE)}}
    )
    assert isinstance(section.value, _Named)
    assert section.value.name == "text"
    assert type(section.value.name) is str


def test_a_value_with_no_marker_is_not_validated_by_the_walk():
    """No marker, nothing for an arm to vouch for: the union is left to
    pydantic as before."""

    class Section(RedactedSection):
        value: Optional[Union[List[str], List[int]]] = None

    section = Section.model_validate({"value": [1, 2, 3]})
    assert section.value == [1, 2, 3]
