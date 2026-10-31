# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A str slot whose metadata re-spells the text does not keep a reference.

The admission read the type alone: pydantic moves a field's metadata
(``Field(pattern=...)``, ``union_mode``, a validator) out of
``field.annotation``, and a nested ``Annotated`` layer was unwrapped before
the test, so a str slot that lowers, strips or converts its text was taken for
one that keeps it. The reference was downcast and then re-spelled by the
slot, and the value printed in a spelling the redaction needle never matched.

The slot is now read by validating the text through the whole annotation: a
validation that gives back something else refuses the reference by name, and
one that gives the text back (or refuses it, or cannot be run) leaves the
standing answer.
"""

from typing import Annotated, Dict, List, Optional, Union

import pytest
from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    StringConstraints,
    ValidationError,
)

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

VARIABLE = "ASH_METADATA_CANARY"
MIXED = "Mixed-Case-Text"


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


def test_a_field_that_lowers_its_text_refuses_a_reference_by_name():
    class Section(RedactedSection):
        name: Annotated[str, StringConstraints(to_lower=True)] = ""

    text = _refusal_text(Section, {"name": env_resolved_scalar(MIXED, VARIABLE)})
    _assert_named_not_echoed(text, "name", MIXED)


def test_a_field_with_a_validator_that_changes_its_text_refuses_a_reference():
    class Section(RedactedSection):
        name: Annotated[str, AfterValidator(str.upper)] = ""

    text = _refusal_text(Section, {"name": env_resolved_scalar("lower-text", VARIABLE)})
    _assert_named_not_echoed(text, "name", "lower-text")


def test_a_field_whose_union_mode_lets_a_number_arm_convert_the_text_is_refused():
    class Section(RedactedSection):
        value: Union[int, str] = Field("", union_mode="left_to_right")

    text = _refusal_text(Section, {"value": env_resolved_scalar("067", VARIABLE)})
    _assert_named_not_echoed(text, "value", "067")


def test_an_item_that_lowers_its_text_refuses_a_reference_by_name():
    class Section(RedactedSection):
        names: Optional[List[Annotated[str, StringConstraints(to_lower=True)]]] = None

    text = _refusal_text(Section, {"names": [env_resolved_scalar(MIXED, VARIABLE)]})
    _assert_named_not_echoed(text, "names", MIXED)


def test_a_value_slot_that_lowers_its_text_refuses_a_reference_by_name():
    class Section(RedactedSection):
        named: Optional[Dict[str, Annotated[str, StringConstraints(to_lower=True)]]] = (
            None
        )

    text = _refusal_text(
        Section, {"named": {"key": env_resolved_scalar(MIXED, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "named", MIXED)


def test_a_field_of_a_nested_model_that_lowers_its_text_refuses_a_reference():
    """The model's own fields are read with their metadata too, not only the
    section's: the reference sits in a dict handed to a plain model."""

    class Inner(BaseModel):
        name: Annotated[str, StringConstraints(to_lower=True)] = ""

    class Section(RedactedSection):
        inner: Optional[Inner] = None

    text = _refusal_text(
        Section, {"inner": {"name": env_resolved_scalar(MIXED, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "inner", MIXED)


def test_a_field_that_strips_a_text_with_nothing_to_strip_keeps_the_reference():
    """The control: the slot gives the text back, so it is admitted and
    downcast to plain str."""

    class Section(RedactedSection):
        name: Annotated[str, StringConstraints(strip_whitespace=True)] = ""

    section = Section.model_validate({"name": env_resolved_scalar("plain", VARIABLE)})
    assert section.name == "plain"
    assert type(section.name) is str


def test_a_field_with_a_pattern_the_text_matches_keeps_the_reference():
    class Section(RedactedSection):
        name: Annotated[str, Field(pattern=r"^[a-z]+$")] = ""

    section = Section.model_validate({"name": env_resolved_scalar("plain", VARIABLE)})
    assert section.name == "plain"
    assert type(section.name) is str


def test_a_field_with_a_pattern_the_text_fails_keeps_pydantics_own_refusal():
    """Nothing is converted, so the standing answer stands: the reference is
    admitted and the field's own validation refuses the text."""

    class Section(RedactedSection):
        name: Annotated[str, Field(pattern=r"^[a-z]+$")] = ""

    text = _refusal_text(Section, {"name": env_resolved_scalar("UPPER", VARIABLE)})
    assert "pattern" in text, text


def test_a_union_with_the_default_mode_keeps_the_reference_as_text():
    class Section(RedactedSection):
        value: Union[int, str] = ""

    section = Section.model_validate({"value": env_resolved_scalar("067", VARIABLE)})
    assert section.value == "067"
    assert type(section.value) is str
