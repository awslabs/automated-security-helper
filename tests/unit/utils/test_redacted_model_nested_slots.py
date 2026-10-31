# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A container holding a reference at an inner slot that cannot hold a
container is refused by name, as the same container at the field itself is.

At the top level a list or mapping at a scalar field is refused in words that
name the variable. One level down the typed walk had no such rule: a list at
the int value slot of ``Dict[str, int]`` was admitted (the slot's annotation
has no item argument to walk), the value was downcast and handed to pydantic,
and pydantic's own error named no variable and echoed the downcast copy, with
the resolved environment text in it, as the input.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest
from pydantic import ValidationError

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_NESTED_CANARY"


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


def test_a_list_at_an_int_value_slot_is_refused_by_name():
    class Section(RedactedSection):
        counts: Optional[Dict[str, int]] = None

    text = _refusal_text(
        Section, {"counts": {"a": [env_resolved_scalar(CANARY, VARIABLE)]}}
    )
    _assert_named_not_echoed(text, "counts")


def test_a_list_at_a_str_item_slot_is_refused_by_name():
    class Section(RedactedSection):
        names: Optional[List[str]] = None

    text = _refusal_text(Section, {"names": [[env_resolved_scalar(CANARY, VARIABLE)]]})
    _assert_named_not_echoed(text, "names")


def test_a_mapping_at_a_sequence_item_slot_is_refused_by_name():
    class Section(RedactedSection):
        rows: Optional[List[List[int]]] = None

    text = _refusal_text(
        Section, {"rows": [{"k": env_resolved_scalar(CANARY, VARIABLE)}]}
    )
    _assert_named_not_echoed(text, "rows")


def test_a_container_at_a_path_item_slot_gets_the_container_wording():
    """The refusal speaks of the container, not the reference: it names what
    the slot expects and what the field holds, and gives no idiom advice,
    since a list at a `Path | str` slot would be refused by this rule again."""
    from pathlib import Path

    class Section(RedactedSection):
        roots: Optional[Dict[str, Path]] = None

    text = _refusal_text(
        Section, {"roots": {"a": [env_resolved_scalar(CANARY, VARIABLE)]}}
    )
    _assert_named_not_echoed(text, "roots")
    assert "holds a list" in text, text
    assert "Plugin authors" not in text, text
    assert "Write the value in the file" not in text, text


def test_a_container_at_a_slot_that_holds_it_is_still_walked():
    """The control: the inner slot takes a list, so its item slot is read and
    the reference there is refused by name as before."""

    class Section(RedactedSection):
        nested: Optional[Dict[str, List[int]]] = None

    text = _refusal_text(
        Section, {"nested": {"a": [env_resolved_scalar(CANARY, VARIABLE)]}}
    )
    _assert_named_not_echoed(text, "nested")


def test_a_container_at_an_untyped_inner_slot_still_takes_the_downcast():
    class Section(RedactedSection):
        nested: Optional[Dict[str, Any]] = None

    section = Section.model_validate(
        {"nested": {"a": [env_resolved_scalar(CANARY, VARIABLE)]}}
    )
    assert section.nested == {"a": [CANARY]}
    assert type(section.nested["a"][0]) is str
