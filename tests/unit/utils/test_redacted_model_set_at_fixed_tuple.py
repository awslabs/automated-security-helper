# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A set at a fixed-length tuple slot is read against every positional slot.

The typed walk paired a fixed tuple's slots by position for a list or a tuple
value only; a set or frozenset fell to the homogeneous-sequence branch, which
read every member against the FIRST slot's type alone. At ``Tuple[str, int]``
a set holding a reference was therefore admitted (the first slot keeps a str),
downcast and handed to pydantic, which lands a set's members in iteration
order, so the env-read text could reach the int slot and be typed silently. No
config file parser produces a set; a Python caller's value can.
"""

from __future__ import annotations

from typing import Optional, Tuple

import pytest
from pydantic import ValidationError

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_SET_TUPLE_CANARY"


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


@pytest.mark.parametrize("kind", [set, frozenset], ids=["set", "frozenset"])
def test_a_set_at_a_fixed_tuple_with_a_converting_slot_is_refused_by_name(kind):
    class Section(RedactedSection):
        pair: Optional[Tuple[str, int]] = None

    text = _refusal_text(
        Section, {"pair": kind({env_resolved_scalar(CANARY, VARIABLE)})}
    )
    _assert_named_not_echoed(text, "pair")


def test_a_set_at_a_fixed_tuple_of_strings_still_takes_the_downcast():
    """The must-not-flag control: every slot keeps a str, so the reference is
    admitted and downcast whichever slot pydantic lands it in."""

    class Section(RedactedSection):
        pair: Optional[Tuple[str, str]] = None

    section = Section.model_validate(
        {"pair": {env_resolved_scalar(CANARY, VARIABLE), "other"}}
    )
    assert sorted(section.pair) == sorted((CANARY, "other"))
    assert all(type(item) is str for item in section.pair)


def test_a_list_at_a_fixed_tuple_still_pairs_by_position():
    """The control for the positional branch: a list's marker in the str slot
    is admitted, a list's marker in the int slot is refused."""

    class Section(RedactedSection):
        pair: Optional[Tuple[str, int]] = None

    section = Section.model_validate(
        {"pair": [env_resolved_scalar(CANARY, VARIABLE), 7]}
    )
    assert section.pair == (CANARY, 7)
    text = _refusal_text(
        Section, {"pair": ["name", env_resolved_scalar(CANARY, VARIABLE)]}
    )
    _assert_named_not_echoed(text, "pair")
