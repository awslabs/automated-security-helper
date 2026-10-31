# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A frozenset is a container the marker detector, the typed walk and the
downcast all read, like a set.

Every other container kind was walked, but the isinstance tuples named list,
tuple, set and dict only, so a frozenset handed to a section by a Python
caller passed the validator's gate untouched: a ``FrozenSet[int]`` slot typed
the env-read text silently, and an untyped slot kept the marker subclass in
the validated model. No config file parser produces a frozenset; a plugin
building its config in Python can.
"""

from __future__ import annotations

from typing import Any, FrozenSet, Optional

import pytest
from pydantic import ValidationError

from automated_security_helper.utils.redacted_model import (
    EnvResolvedScalar,
    RedactedSection,
    env_resolved_scalar,
    first_env_scalar,
    without_env_scalars,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_FROZEN_CANARY"


def test_a_frozenset_item_at_a_typed_item_slot_is_refused_by_name():
    class Section(RedactedSection):
        ids: Optional[FrozenSet[int]] = None

    with pytest.raises(ValidationError) as refused:
        Section.model_validate(
            {"ids": frozenset({env_resolved_scalar(CANARY, VARIABLE)})}
        )
    text = " ".join(error["msg"] for error in refused.value.errors())
    assert VARIABLE in text, text
    assert CANARY not in text, text


def test_a_frozenset_at_an_untyped_slot_is_downcast_to_plain_strings():
    class Section(RedactedSection):
        names: Optional[Any] = None

    section = Section.model_validate(
        {"names": frozenset({env_resolved_scalar(CANARY, VARIABLE)})}
    )
    assert isinstance(section.names, frozenset)
    (member,) = section.names
    assert member == CANARY
    assert type(member) is str


def test_first_env_scalar_reads_a_frozenset_member():
    marker = env_resolved_scalar(CANARY, VARIABLE)
    assert first_env_scalar(frozenset({marker})) is marker
    assert first_env_scalar({"outer": frozenset({"plain", marker})}) is marker


def test_without_env_scalars_rebuilds_a_frozenset_as_a_frozenset():
    marker = env_resolved_scalar(CANARY, VARIABLE)
    view = without_env_scalars({"outer": frozenset({marker, "plain"})})
    assert isinstance(view["outer"], frozenset)
    assert view["outer"] == frozenset({CANARY, "plain"})
    assert not any(isinstance(member, EnvResolvedScalar) for member in view["outer"])
