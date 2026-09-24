# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every enum-typed default in the SARIF model must be spelled as a plain string.

``use_enum_values=True`` converts at validation time, and pydantic does not
validate an unprovided field default. A default written as an enum member
therefore survives on the model as the member, so ``result.level`` is a plain
``str`` when the scanner supplied the key and a ``Level`` member when it omitted
it. ``Level`` and ``Kind`` are ``(str, Enum)`` mixins rather than ``StrEnum``,
so ``Enum.__str__`` wins over ``str.__str__`` and ``str(Level.error)`` renders
``"Level.error"`` -- a value that matches no SARIF level and no lookup table.

These tests assert the resolved runtime type, not equality. ``Level.error ==
"error"`` is True for a str mixin, so an equality assertion passes against both
shapes and cannot fail.
"""

import enum
import inspect

import pytest
from pydantic import BaseModel

from automated_security_helper.schemas import sarif_schema_model
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    ReportingConfiguration,
    Result,
)


def _models():
    """Every pydantic model declared in the SARIF schema module."""
    for name, obj in vars(sarif_schema_model).items():
        if inspect.isclass(obj) and issubclass(obj, BaseModel):
            yield name, obj


def test_no_sarif_model_declares_an_enum_member_as_a_field_default():
    """The census guard.

    ``sarif_schema_model.py`` is datamodel-codegen output, so regenerating it
    would reintroduce enum-member defaults wholesale. This walks every model in
    the module instead of naming the three fields, so a regeneration fails here
    rather than silently downgrading findings in four consumers.
    """
    offenders = [
        f"{model_name}.{field_name} = {default!r}"
        for model_name, model in _models()
        for field_name, field in model.model_fields.items()
        if isinstance((default := field.default), enum.Enum)
    ]

    assert offenders == [], (
        "enum-member defaults are not validated, so they survive as members and "
        "str() renders them as 'EnumName.member'; spell them as plain strings: "
        + "; ".join(offenders)
    )


@pytest.mark.parametrize(
    ("field_name", "expected"),
    [("level", "error"), ("kind", "fail")],
)
def test_result_default_is_a_plain_string_when_the_key_is_absent(field_name, expected):
    """A scanner may legally omit level and kind; SARIF says so."""
    result = Result.model_validate({"message": {"text": "hardcoded credential"}})
    value = getattr(result, field_name)

    assert type(value) is str, f"expected str, got {type(value).__name__}: {value!r}"
    assert value == expected
    assert str(value) == expected


@pytest.mark.parametrize(
    ("field_name", "expected"),
    [("level", "error"), ("kind", "fail")],
)
def test_result_default_is_a_plain_string_under_direct_construction(
    field_name, expected
):
    """Defaults are unvalidated on the constructor path too, not only model_validate."""
    result = Result(message=Message(text="hardcoded credential"))
    value = getattr(result, field_name)

    assert type(value) is str, f"expected str, got {type(value).__name__}: {value!r}"
    assert str(value) == expected


def test_reporting_configuration_level_default_is_a_plain_string():
    """The rule-side default feeds the GHAS reporter's security-severity lookup."""
    level = ReportingConfiguration.model_validate({}).level

    assert type(level) is str, f"expected str, got {type(level).__name__}: {level!r}"
    assert str(level) == "warning"


@pytest.mark.parametrize(
    "value",
    [
        Result.model_validate({"message": {"text": "x"}}).level,
        Result.model_validate({"message": {"text": "x"}}).kind,
        ReportingConfiguration.model_validate({}).level,
    ],
)
def test_no_defaulted_enum_value_stringifies_with_a_dot(value):
    """'Level.error' is the fingerprint; a bare SARIF value never contains a dot."""
    assert "." not in str(value), (
        f"str() rendered the enum member rather than its value: {str(value)!r}"
    )
