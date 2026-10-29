# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""At a field whose shape reaches a section, a slot beside the section that
admits text as it is gets a plain str, and the section still gets its markers.

The section-reaching route of the section base's validator hands the value on
whole so each section's own validator sees its markers. A slot beside a section
that converts text (an int) is refused by the opaque walk; a slot that admits
the text as it is (``Any``) refused nothing and was handed on whole too, so the
marker class (``EnvResolvedScalar``) survived validation there, into a config
dump with no representer for it. The route now downcasts the slots that reach
no section (``_downcast_outside_sections``) and leaves the section slots' values
as given.

Red at the base: the Any slot held the marker class after validation.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, FrozenSet, List, Optional, Tuple, Union

import pytest

from automated_security_helper.utils.redacted_model import (
    EnvResolvedScalar,
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_BESIDE_CANARY"


class _Inner(RedactedSection):
    _env_scalar_typed_fields: ClassVar[FrozenSet[str]] = frozenset({"limit"})

    limit: Optional[int] = None
    name: Optional[str] = None


def test_an_any_slot_beside_a_section_holds_a_plain_str() -> None:
    class Outer(RedactedSection):
        pair: Optional[Tuple[_Inner, Any]] = None

    outer = Outer.model_validate(
        {"pair": [{"limit": 1}, env_resolved_scalar(CANARY, VARIABLE)]}
    )

    assert outer.pair[1] == CANARY
    assert type(outer.pair[1]) is str
    assert outer.pair[0].limit == 1


def test_the_sections_in_the_same_shape_still_get_their_markers() -> None:
    """The control: the opted typed field of a section under a dict is typed
    from the marker's text, as the section's own validator does."""

    class Outer(RedactedSection):
        inners: Optional[Dict[str, _Inner]] = None
        pair: Optional[Tuple[_Inner, Any]] = None

    outer = Outer.model_validate(
        {
            "inners": {"a": {"limit": env_resolved_scalar(CANARY, VARIABLE)}},
            "pair": [{"limit": env_resolved_scalar(CANARY, VARIABLE)}, "plain"],
        }
    )

    assert outer.inners["a"].limit == int(CANARY)
    assert outer.pair[0].limit == int(CANARY)


def test_a_str_slot_of_a_list_beside_sections_holds_plain_strs() -> None:
    class Outer(RedactedSection):
        mixed: Optional[Tuple[List[_Inner], List[str]]] = None

    outer = Outer.model_validate(
        {"mixed": [[{"name": "n"}], [env_resolved_scalar(CANARY, VARIABLE)]]}
    )

    assert outer.mixed[1] == [CANARY]
    assert all(type(item) is str for item in outer.mixed[1])
    assert outer.mixed[0][0].name == "n"


def test_a_union_of_a_section_and_another_arm_keeps_the_value_as_given() -> None:
    """The named limit: which arm describes the value is the arm's own call,
    so the markers stay for the section that may take them."""

    class Outer(RedactedSection):
        either: Optional[Union[_Inner, List[str]]] = None

    outer = Outer.model_validate(
        {"either": {"limit": env_resolved_scalar(CANARY, VARIABLE)}}
    )

    assert isinstance(outer.either, _Inner)
    assert outer.either.limit == int(CANARY)


def test_a_field_that_reaches_no_section_is_downcast_as_before() -> None:
    """The control: the non-section route is unchanged."""

    class Outer(RedactedSection):
        names: Optional[List[str]] = None

    outer = Outer.model_validate({"names": [env_resolved_scalar(CANARY, VARIABLE)]})

    assert outer.names == [CANARY]
    assert not any(isinstance(item, EnvResolvedScalar) for item in outer.names)
