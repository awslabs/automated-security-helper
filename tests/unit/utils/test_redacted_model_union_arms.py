# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""In a union, an arm that keeps only SOME text (a str Enum's members, a
constrained str's pattern) admits an environment reference only when the text
is known to match it, or when no sibling arm converts a str.

A str-valued Enum arm with the stock ``_missing_`` admitted every text, as a
plain str arm does, although pydantic's smart-mode union hands text that is no
member to the next arm: ``Union[int, StrEnum]`` typed the env-read "424242" to
424242 through the int arm, and the number printed wherever the section was
shown, in a spelling the redaction needle never matches. A constrained str arm
(``Annotated[str, Field(pattern=...)]``) was read as a bare str and admitted
the same way. The Literal arm already had the sibling check; the Enum and the
constrained str now get it too.
"""

from __future__ import annotations

import decimal
import enum
from pathlib import Path
from typing import Annotated, List, Optional, Union

import pytest
from pydantic import Field, ValidationError

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_UNION_CANARY"
MEMBER = "zz-red-choice"


class Choice(str, enum.Enum):
    RED = MEMBER
    BLUE = "zz-blue-choice"


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


@pytest.mark.parametrize(
    "sibling",
    [int, float, decimal.Decimal, Path],
    ids=["int", "float", "decimal", "path"],
)
def test_a_str_enum_arm_beside_a_converting_arm_refuses_non_member_text(sibling):
    class Section(RedactedSection):
        level: Optional[Union[sibling, Choice]] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"level": env_resolved_scalar(CANARY, VARIABLE)})
    _assert_named_not_echoed(text, "level")


def test_a_str_enum_arm_beside_a_converting_arm_keeps_exact_member_text():
    """The must-not-flag control: text that equals a member value is found
    before any sibling converts it, and the member spells the text."""

    class Section(RedactedSection):
        level: Optional[Union[int, Choice]] = None

    section = Section.model_validate({"level": env_resolved_scalar(MEMBER, VARIABLE)})
    assert section.level == Choice.RED


def test_a_str_enum_arm_beside_a_container_arm_still_admits_the_text():
    """A sibling that holds a container takes no scalar text, so the Enum arm
    keeps its standing admission; pydantic then applies the Enum itself."""

    class Section(RedactedSection):
        level: Optional[Union[List[int], Choice]] = None

    section = Section.model_validate({"level": env_resolved_scalar(MEMBER, VARIABLE)})
    assert section.level == Choice.RED


def test_a_constrained_str_arm_beside_a_converting_arm_is_refused():
    class Section(RedactedSection):
        level: Optional[Union[int, Annotated[str, Field(pattern=r"^[a-z-]+$")]]] = None

    text = _refusal_text(Section, {"level": env_resolved_scalar(CANARY, VARIABLE)})
    _assert_named_not_echoed(text, "level")


def test_a_constrained_str_arm_keeps_text_that_passes_its_constraint():
    """The constraint is read: text the pattern accepts is an exact match in
    pydantic's strict pass, ahead of any lax conversion by a sibling, so the
    reference is admitted and the text kept whole."""

    class Section(RedactedSection):
        timeout: Optional[Union[int, Annotated[str, Field(pattern=r"^\d+[smh]$")]]] = (
            None
        )

    section = Section.model_validate({"timeout": env_resolved_scalar("30s", VARIABLE)})
    assert section.timeout == "30s"
    assert type(section.timeout) is str


class _Port(str, enum.Enum):
    DEFAULT = "0080"


def test_an_enum_member_text_an_earlier_converting_arm_takes_is_refused():
    """A str-to-Enum read is as lax as a str-to-int read, and the earlier arm
    wins the tie, so "0080" at Union[int, Port] would reach the int arm and
    print as 80, a spelling the redaction needle never matches."""

    class Section(RedactedSection):
        port: Optional[Union[int, _Port]] = None

    text = _refusal_text(Section, {"port": env_resolved_scalar("0080", VARIABLE)})
    assert VARIABLE in text, text
    assert "0080" not in text.replace("port", ""), text


def test_an_enum_member_text_with_no_earlier_converting_arm_is_admitted():
    """The must-not-flag control for the order rule: the Enum arm comes first,
    so no converting arm takes the text ahead of it, and the member spells the
    text. A check that read every sibling instead of the earlier ones would
    refuse this."""

    class Section(RedactedSection):
        port: Optional[Union[_Port, int]] = None

    section = Section.model_validate({"port": env_resolved_scalar("0080", VARIABLE)})
    assert section.port is _Port.DEFAULT


def test_a_constrained_str_match_wins_over_a_converting_arm_before_it():
    """The must-not-flag control for the other half of the rule: a constrained
    str's match is exact and wins whatever the order, so text the int arm
    before it would also take is admitted and kept whole. The order check
    applied to a constrained str would refuse this."""

    class Section(RedactedSection):
        port: Optional[Union[int, Annotated[str, Field(pattern=r"^\d+$")]]] = None

    section = Section.model_validate({"port": env_resolved_scalar("0080", VARIABLE)})
    assert section.port == "0080"
    assert type(section.port) is str


def test_an_unconstrained_annotated_str_arm_beside_a_converting_arm_admits():
    """A Field with no constraint of its own (a description) refuses no text,
    so the str arm keeps every reference, as a bare str arm does."""

    class Section(RedactedSection):
        level: Optional[Union[int, Annotated[str, Field(description="a level")]]] = None

    section = Section.model_validate({"level": env_resolved_scalar(CANARY, VARIABLE)})
    assert section.level == CANARY
    assert type(section.level) is str
