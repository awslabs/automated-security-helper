# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The metadata behind a type alias or a NewType is read.

A ``TypeAliasType`` or a NewType is unwrapped to the type it stands for, as
pydantic expands it, but the ``Annotated`` metadata inside it was not read: the
metadata was collected from the outer layers only. So an alias over
``Annotated[str, AfterValidator(str.lower)]`` was taken for a str slot that keeps
its text, admitted a reference, and pydantic stored the lowercased text, a
spelling the redaction needle never matches; in a union the same alias counted as
an unconditional str arm. The metadata is now collected through the whole
unwrapping, so the slot is read by validating the text through it, as a
constrained str written in place is.
"""

from typing import Annotated, NewType, Optional, Union

import pytest
import typing_extensions
from pydantic import AfterValidator, Field, ValidationError

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

VARIABLE = "ASH_ALIAS_METADATA_CANARY"
MIXED = "Mixed-Case-Text"

Lower = typing_extensions.TypeAliasType(
    "Lower", Annotated[str, AfterValidator(str.lower)]
)
LowerNew = NewType("LowerNew", Annotated[str, AfterValidator(str.lower)])  # type: ignore[valid-newtype]
Described = typing_extensions.TypeAliasType(
    "Described", Annotated[str, Field(description="free text")]
)


def _refusal_text(model_type, payload) -> str:
    with pytest.raises(ValidationError) as refused:
        model_type.model_validate(payload)
    return " ".join(
        f"{error['loc']}: {error['msg']}" for error in refused.value.errors()
    )


def _assert_named_not_echoed(text: str, field: str, value: str) -> None:
    assert VARIABLE in text, text
    assert field in text, text
    assert value not in text, text


def test_an_alias_over_a_str_that_lowers_its_text_refuses_a_reference():
    class Section(RedactedSection):
        name: Optional[Lower] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"name": env_resolved_scalar(MIXED, VARIABLE)})
    _assert_named_not_echoed(text, "name", MIXED)


def test_a_new_type_over_a_str_that_lowers_its_text_refuses_a_reference():
    class Section(RedactedSection):
        name: Optional[LowerNew] = None

    text = _refusal_text(Section, {"name": env_resolved_scalar(MIXED, VARIABLE)})
    _assert_named_not_echoed(text, "name", MIXED)


def test_an_alias_arm_that_lowers_its_text_is_conditional_in_a_union():
    """Read as a bare str arm, the alias admitted every text; it keeps only
    text already in lower case, and the rest would be re-spelled, so the
    reference is refused."""

    class Section(RedactedSection):
        name: Optional[Union[int, Lower]] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"name": env_resolved_scalar(MIXED, VARIABLE)})
    _assert_named_not_echoed(text, "name", MIXED)


def test_an_alias_over_a_str_with_inert_metadata_keeps_the_text():
    """The must-not-flag control: a description adds no check and re-spells
    nothing, so the alias keeps every reference as a bare str does."""

    class Section(RedactedSection):
        name: Optional[Described] = None  # type: ignore[valid-type]

    section = Section.model_validate({"name": env_resolved_scalar(MIXED, VARIABLE)})
    assert section.name == MIXED
    assert type(section.name) is str


def test_an_alias_over_a_lowering_str_keeps_text_already_lower():
    """The other control: text the validator gives back unchanged is kept, as
    for a constrained str written in place."""

    class Section(RedactedSection):
        name: Optional[Lower] = None  # type: ignore[valid-type]

    section = Section.model_validate(
        {"name": env_resolved_scalar("lower-text", VARIABLE)}
    )
    assert section.name == "lower-text"
    assert type(section.name) is str
