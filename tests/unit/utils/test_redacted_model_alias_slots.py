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
from typing import Annotated, Dict, NamedTuple, Optional, Union

import pydantic.dataclasses
import pytest
from pydantic import ConfigDict, Field, ValidationError, with_config
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


@with_config(ConfigDict(alias_generator=str.upper))
@dataclasses.dataclass
class _OwnConfig:
    limit: int = 0


def test_a_stdlib_dataclass_own_config_generated_alias_is_a_typed_slot():
    """A stdlib dataclass can carry its own pydantic config, which names its
    alias generator; the alias keys are read from it first, as pydantic reads
    them, with no generator in force around the dataclass."""

    class Section(RedactedSection):
        limits: Optional[_OwnConfig] = None

    text = _refusal_text(
        Section, {"limits": {"LIMIT": env_resolved_scalar(CANARY, VARIABLE)}}
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


@dataclasses.dataclass
class _Defaulted:
    """The alias is given as the field's default, the other spelling pydantic
    reads (``collect_dataclass_fields`` takes a ``Field(...)`` default as the
    field's info); the Field carries a default of its own, so the field is
    optional."""

    limit: int = Field(0, alias="max")


def test_a_stdlib_dataclass_field_default_alias_is_a_typed_slot():
    """Read off the Annotated metadata only, the alias was missed: the key
    landed in the extras branch, no extras type refused it, and the reference
    was downcast and typed to int silently."""

    class Section(RedactedSection):
        limits: Optional[_Defaulted] = None

    text = _refusal_text(
        Section, {"limits": {"max": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "limits")


class _DefaultedTuple(NamedTuple):
    """The NamedTuple spelling of :class:`_Defaulted`: pydantic builds a
    NamedTuple's parameters from ``_field_defaults`` through
    ``FieldInfo.from_annotated_attribute``, so a ``Field(...)`` default names
    the key here too, and this one carries a default, so the field is
    optional."""

    limit: int = Field(0, alias="max")


class _RequiredTuple(NamedTuple):
    """A ``Field(...)`` default that carries no default of its own: pydantic
    keeps the field required although ``_field_defaults`` lists it."""

    limit: int = Field(alias="max")
    other: str = ""


def test_a_named_tuple_field_default_alias_is_a_typed_slot():
    """Read off the Annotated metadata only, the alias was missed: the key
    landed in the extras branch, no extras type refused it, and the reference
    was downcast and typed to int silently, as for the dataclass above."""

    class Section(RedactedSection):
        limits: Optional[_DefaultedTuple] = None

    text = _refusal_text(
        Section, {"limits": {"max": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "limits")


def test_a_named_tuple_field_a_field_default_leaves_required_is_counted():
    """Counted by the defaults dict alone, ``limit`` read as optional, the
    NamedTuple arm vouched for a dict pydantic refuses (no ``max``), and the
    converting sibling typed the reference silently; the arm is now read as
    pydantic reads it, so the sibling's typing is refused by name."""

    class Section(RedactedSection):
        value: Optional[Union[_RequiredTuple, Dict[str, int]]] = None

    text = _refusal_text(
        Section, {"value": {"other": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "value")


def test_pydantic_reads_the_field_default_alias_of_a_named_tuple():
    """The positive control: pydantic reads the key the walk refuses, and
    requires the field whose Field default carries none."""

    class Section(RedactedSection):
        limits: Optional[_DefaultedTuple] = None
        strict: Optional[_RequiredTuple] = None

    assert Section.model_validate({"limits": {"max": "5"}}).limits.limit == 5
    assert Section.model_validate({"strict": {"max": 3}}).strict == _RequiredTuple(3)
    with pytest.raises(ValidationError):
        Section.model_validate({"strict": {"other": "x"}})


def test_pydantic_reads_the_annotated_alias_of_a_stdlib_dataclass():
    """The positive control for the refusals above: pydantic does read the
    keys the walk refuses, so a refused key is one a value would land under.
    A pydantic release that stopped reading one would show here."""

    class Section(RedactedSection):
        limits: Optional[_Limits] = None

    assert Section.model_validate({"limits": {"max": "5"}}).limits.limit == 5


def test_pydantic_reads_the_holders_generated_alias_of_a_stdlib_dataclass():
    class Section(RedactedSection):
        model_config = ConfigDict(alias_generator=str.upper)

        limits: Optional[_Plain] = None

    assert Section.model_validate({"LIMITS": {"LIMIT": "5"}}).limits.limit == 5


def test_pydantic_reads_the_own_config_generated_alias_of_a_stdlib_dataclass():
    class Section(RedactedSection):
        limits: Optional[_OwnConfig] = None

    assert Section.model_validate({"limits": {"LIMIT": "5"}}).limits.limit == 5


def test_pydantic_reads_the_field_default_alias_of_a_stdlib_dataclass():
    class Section(RedactedSection):
        limits: Optional[_Defaulted] = None

    assert Section.model_validate({"limits": {"max": "5"}}).limits.limit == 5
