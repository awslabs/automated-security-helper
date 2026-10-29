# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A RootModel slot is read through what it wraps, in the union and the walk.

``_shape_can_hold`` decides which union arms can describe a container value,
and ``_marker_a_slot_would_type`` walks the arms that can. Both read a
RootModel through its root annotation, nested RootModels included. Without
the read in ``_shape_can_hold`` a RootModel over a scalar counts as holding a
mapping (it is a BaseModel) and its walk finds no slot, so the mapping arm
that converts the text is never reached and the reference is admitted. A bare
reference at a RootModel itself keeps the refusal whatever the model wraps.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Union

import pytest
from pydantic import RootModel

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

VARIABLE = "ASH_ROOT_SLOT_CANARY"
TEXT = "067"


class _Count(RootModel[int]):
    pass


class _Ids(RootModel[List[int]]):
    pass


class _NestedIds(RootModel[_Ids]):
    pass


def _refusal_text(model_type, payload) -> str:
    with pytest.raises(Exception) as refused:
        model_type.model_validate(payload)
    errors = refused.value.errors()  # type: ignore[attr-defined]
    return " ".join(f"{error['loc']}: {error['msg']}" for error in errors)


def test_a_root_model_over_a_scalar_does_not_hold_a_mapping_for_its_siblings():
    """The mapping arm that converts the item is the one that describes the
    value, so the reference in it is refused."""

    class Section(RedactedSection):
        value: Optional[Union[_Count, Dict[str, int]]] = None

    marker = env_resolved_scalar(TEXT, VARIABLE)
    text = _refusal_text(Section, {"value": {"a": marker}})

    assert VARIABLE in text and "value" in text, text
    assert TEXT not in text, text


def test_the_same_mapping_of_strings_beside_it_takes_the_downcast():
    """The must-not-flag control: the mapping arm that keeps the text admits."""

    class Section(RedactedSection):
        value: Optional[Union[_Count, Dict[str, str]]] = None

    section = Section.model_validate(
        {"value": {"a": env_resolved_scalar(TEXT, VARIABLE)}}
    )

    assert section.value == {"a": TEXT}
    assert type(section.value["a"]) is str  # type: ignore[index]


def test_a_nested_root_model_is_read_through_every_level():
    class Section(RedactedSection):
        ids: Optional[_NestedIds] = None

    text = _refusal_text(Section, {"ids": [env_resolved_scalar(TEXT, VARIABLE)]})

    assert VARIABLE in text and "ids" in text, text
    assert TEXT not in text, text


@pytest.mark.parametrize(
    "root_model", [_Ids, _NestedIds], ids=["root-model", "nested-root-model"]
)
def test_a_bare_reference_at_a_root_model_is_refused(root_model):
    class Section(RedactedSection):
        ids: Optional[root_model] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"ids": env_resolved_scalar(TEXT, VARIABLE)})

    assert VARIABLE in text and "ids" in text, text
    assert TEXT not in text, text
