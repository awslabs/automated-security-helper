# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A section slot behind ``Annotated`` or a RootModel is the section's own to
judge, as a bare section slot is.

When a field's shape reaches a section, the outer validator walks the shape
with section-typed slots opaque and hands the value on whole, so the section's
own validator sees its markers and honors its ``_env_scalar_typed_fields``
opt-in. The opaque test read the slot's annotation as it was written, so a
section behind ``Annotated[...]`` or wrapped in a RootModel was not exempt:
the outer walk read it through to the section's fields and refused a
reference at an opted typed field that the section itself would have taken.
"""

from __future__ import annotations

from typing import Annotated, ClassVar, FrozenSet, List, Optional, Tuple

import pytest
from pydantic import Field, RootModel, ValidationError

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_OPAQUE_CANARY"


class _Inner(RedactedSection):
    """A section whose one typed field is opted in: its text is handed to the
    field's own validation, which types it (the measured-printer shape)."""

    _env_scalar_typed_fields: ClassVar[FrozenSet[str]] = frozenset({"limit"})

    limit: Optional[int] = None


class _Wrapped(RootModel[_Inner]):
    pass


def test_an_annotated_section_slot_hands_the_section_its_markers():
    class Outer(RedactedSection):
        inner: Optional[Annotated[_Inner, Field(description="an inner")]] = None

    outer = Outer.model_validate(
        {"inner": {"limit": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    assert outer.inner.limit == int(CANARY)


def test_an_annotated_section_item_slot_hands_the_section_its_markers():
    class Outer(RedactedSection):
        inners: Optional[List[Annotated[_Inner, Field(description="an inner")]]] = None

    outer = Outer.model_validate(
        {"inners": [{"limit": env_resolved_scalar(CANARY, VARIABLE)}]}
    )
    assert [inner.limit for inner in outer.inners] == [int(CANARY)]


def test_a_root_nested_section_slot_hands_the_section_its_markers():
    class Outer(RedactedSection):
        inner: Optional[_Wrapped] = None

    outer = Outer.model_validate(
        {"inner": {"limit": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    assert outer.inner.root.limit == int(CANARY)


def test_a_typed_slot_beside_an_annotated_section_still_refuses():
    """The control: the slot beside the section is not the section's, so the
    outer walk still refuses a reference there by name."""

    class Outer(RedactedSection):
        pair: Optional[Tuple[Annotated[_Inner, Field(description="x")], int]] = None

    with pytest.raises(ValidationError) as refused:
        Outer.model_validate(
            {"pair": [{"limit": 1}, env_resolved_scalar(CANARY, VARIABLE)]}
        )
    text = " ".join(error["msg"] for error in refused.value.errors())
    assert VARIABLE in text, text
    assert "pair" in text, text
    assert CANARY not in text, text
