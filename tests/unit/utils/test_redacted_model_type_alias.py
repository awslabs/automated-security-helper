# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``type X = ...`` alias (typing.TypeAliasType) is unwrapped like a
typing_extensions.TypeAliasType, so the slot behind it is read.

On Python 3.12 and 3.13 typing_extensions defines a TypeAliasType class of its
own instead of re-exporting typing's, so an alias the ``type`` statement makes
matched the unwrapper's isinstance check on neither version. Unread, an alias
over a number admitted a reference that pydantic then typed silently, an alias
over a container hid its item slots, and an alias over a section was not seen
to reach one, so the section was handed a downcast copy and its own validator
never saw the marker. Python 3.14 re-exports typing's class, so these tests
pass there on the old bytes; 3.10 and 3.11 have no typing.TypeAliasType and
skip.
"""

from __future__ import annotations

import sys
from typing import List, Optional

import pytest
import typing_extensions
from pydantic import ValidationError

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.version_info < (3, 12), reason="typing.TypeAliasType is 3.12+"
    ),
]

CANARY = "424242"
VARIABLE = "ASH_ALIAS_CANARY"


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


def _typing_alias(name, value):
    import typing

    return typing.TypeAliasType(name, value)


def test_a_typing_alias_over_a_number_refuses_a_reference():
    count = _typing_alias("Count", int)

    class Section(RedactedSection):
        limit: Optional[count] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"limit": env_resolved_scalar(CANARY, VARIABLE)})
    _assert_named_not_echoed(text, "limit")


def test_a_typing_alias_over_a_container_reads_its_item_slot():
    counts = _typing_alias("Counts", List[int])

    class Section(RedactedSection):
        ids: Optional[counts] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"ids": [env_resolved_scalar(CANARY, VARIABLE)]})
    _assert_named_not_echoed(text, "ids")


def test_a_typing_alias_over_a_section_hands_the_section_its_markers():
    """Behind an unread alias the inner section received a downcast copy, so
    its typed field got plain text and pydantic typed it silently; read, the
    marker at the typed slot is refused by name, never echoed."""

    class Inner(RedactedSection):
        limit: Optional[int] = None

    inner_alias = _typing_alias("InnerAlias", Inner)

    class Outer(RedactedSection):
        inner: Optional[inner_alias] = None  # type: ignore[valid-type]

    text = _refusal_text(
        Outer, {"inner": {"limit": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "inner")


def test_a_typing_extensions_alias_is_read_the_same_way():
    """The control: the spelling the module already read keeps refusing."""
    count = typing_extensions.TypeAliasType("Count", int)

    class Section(RedactedSection):
        limit: Optional[count] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"limit": env_resolved_scalar(CANARY, VARIABLE)})
    _assert_named_not_echoed(text, "limit")
