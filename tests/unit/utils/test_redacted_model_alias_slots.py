# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The typed walk keys a TypedDict's or dataclass's fields by every alias
pydantic reads, each alias recording the field's own annotation.

Two gaps in the alias keying. First, the alias slots were built from the map
the walk was mutating: when an earlier field's alias equals a later field's
name, that entry becomes a list of slots, and the later field's own alias then
recorded the list as its annotation, so a valid reference at that alias key
was refused against the earlier field's type. Second, a standard-library
dataclass had no alias keys at all (only a pydantic dataclass's
``__pydantic_fields__`` were read), although pydantic honors a ``Field(alias=)``
in its ``Annotated`` metadata and the holder's ``alias_generator``; a reference
under such a key escaped the typed-slot refusal and was typed silently.
"""

from __future__ import annotations

import dataclasses
from typing import Annotated, Optional

import pydantic.dataclasses
import pytest
from pydantic import ConfigDict, Field, ValidationError
from typing_extensions import TypedDict

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_ALIAS_SLOT_CANARY"


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


class _Chained(TypedDict, total=False):
    """Field ``first`` is read under the key ``second``, the name of the next
    field, which is itself read under ``third``."""

    first: Annotated[int, Field(alias="second")]
    second: Annotated[str, Field(alias="third")]


def test_a_typed_dict_alias_records_its_own_fields_annotation():
    class Section(RedactedSection):
        entries: Optional[_Chained] = None

    section = Section.model_validate(
        {"entries": {"third": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    assert section.entries == {"second": CANARY}
    assert type(section.entries["second"]) is str


@pydantic.dataclasses.dataclass
class _ChainedDataclass:
    first: Annotated[int, Field(alias="second")] = 0
    second: Annotated[str, Field(alias="third")] = ""


def test_a_pydantic_dataclass_alias_records_its_own_fields_annotation():
    class Section(RedactedSection):
        entries: Optional[_ChainedDataclass] = None

    section = Section.model_validate(
        {"entries": {"third": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    assert section.entries.second == CANARY
    assert type(section.entries.second) is str


@dataclasses.dataclass
class _Limits:
    limit: Annotated[int, Field(alias="max")] = 0


def test_a_stdlib_dataclass_annotated_alias_is_a_typed_slot():
    class Section(RedactedSection):
        limits: Optional[_Limits] = None

    text = _refusal_text(
        Section, {"limits": {"max": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "limits")


@dataclasses.dataclass
class _Plain:
    limit: int = 0


def test_a_stdlib_dataclass_generated_alias_is_a_typed_slot():
    """The holder's alias_generator names the dataclass's keys, as pydantic
    applies it to a stdlib dataclass used as a field."""

    class Section(RedactedSection):
        model_config = ConfigDict(alias_generator=str.upper)

        limits: Optional[_Plain] = None

    text = _refusal_text(
        Section, {"LIMITS": {"LIMIT": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "limits")


def test_a_stdlib_dataclass_field_by_its_own_name_is_still_a_typed_slot():
    """The control: the field name itself was always keyed."""

    class Section(RedactedSection):
        limits: Optional[_Plain] = None

    text = _refusal_text(
        Section, {"limits": {"limit": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "limits")
