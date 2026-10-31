# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Slots whose type the annotation alone does not give: a TypeVar and a str
subclass that builds its own schema.

pydantic validates an unparameterized TypeVar as its bound, or as the union of
its constraints. The admission took every TypeVar for a shape it cannot
interpret and admitted the reference, so a TypeVar bound to int typed the text
(``"067"`` read as 67) and printed it in a spelling the needle never matched.

A str subclass with a ``__get_pydantic_core_schema__`` of its own was admitted
as any str is, though what it does with the text cannot be read from the class
(a normalizing type lowers it, say). The container walk already fails closed
on such a class; the scalar slot now validates the text through it and
refuses a reference that comes back as something else.

A TypedDict has no slot for a str, and the subclass check refuses to read it:
it stays refused by name, as the docstring of the admission says.
"""

from typing import Optional, TypeVar

import pytest
from pydantic import GetCoreSchemaHandler, ValidationError
from pydantic_core import core_schema
from typing_extensions import TypedDict

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

VARIABLE = "ASH_SLOT_CANARY"

_BOUND_INT = TypeVar("_BOUND_INT", bound=int)
_NUMBER = TypeVar("_NUMBER", int, float)
_NUMBER_OR_STR = TypeVar("_NUMBER_OR_STR", int, str)
_UNBOUND = TypeVar("_UNBOUND")


class _Slug(str):
    """A str that lowers what it is given, through a schema of its own."""

    __slots__ = ()

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: type, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_after_validator_function(
            lambda value: cls(value.lower()), core_schema.str_schema()
        )


class _Shape(TypedDict):
    count: int


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


def test_a_typevar_bound_to_a_number_refuses_a_reference_by_name():
    class Section(RedactedSection):
        limit: _BOUND_INT = 0  # type: ignore[valid-type]

    text = _refusal_text(Section, {"limit": env_resolved_scalar("067", VARIABLE)})
    _assert_named_not_echoed(text, "limit", "067")


def test_a_typevar_constrained_to_numbers_refuses_a_reference_by_name():
    class Section(RedactedSection):
        limit: _NUMBER = 0  # type: ignore[valid-type]

    text = _refusal_text(Section, {"limit": env_resolved_scalar("067", VARIABLE)})
    _assert_named_not_echoed(text, "limit", "067")


def test_a_typevar_constrained_to_a_number_or_a_str_keeps_the_reference():
    """The control: one constraint is a str, which keeps the text."""

    class Section(RedactedSection):
        limit: _NUMBER_OR_STR = 0  # type: ignore[valid-type]

    section = Section.model_validate({"limit": env_resolved_scalar("067", VARIABLE)})
    assert section.limit == "067"
    assert type(section.limit) is str


def test_an_unbound_typevar_keeps_the_reference():
    class Section(RedactedSection):
        value: _UNBOUND = None  # type: ignore[valid-type]

    section = Section.model_validate({"value": env_resolved_scalar("067", VARIABLE)})
    assert section.value == "067"
    assert type(section.value) is str


def test_a_str_subclass_with_a_schema_of_its_own_refuses_text_it_would_change():
    class Section(RedactedSection):
        slug: Optional[_Slug] = None

    text = _refusal_text(Section, {"slug": env_resolved_scalar("Upper-Slug", VARIABLE)})
    _assert_named_not_echoed(text, "slug", "Upper-Slug")


def test_a_str_subclass_with_a_schema_of_its_own_keeps_text_it_gives_back():
    """The control: the schema returns this text as it went in."""

    class Section(RedactedSection):
        slug: Optional[_Slug] = None

    section = Section.model_validate(
        {"slug": env_resolved_scalar("lower-slug", VARIABLE)}
    )
    assert section.slug == "lower-slug"


def test_a_typed_dict_slot_refuses_a_reference_by_name():
    """A TypedDict is read as a mapping and no str lands in it; the subclass
    check raises on it, and the slot refuses."""

    class Section(RedactedSection):
        shape: Optional[_Shape] = None

    text = _refusal_text(Section, {"shape": env_resolved_scalar("067", VARIABLE)})
    _assert_named_not_echoed(text, "shape", "067")
