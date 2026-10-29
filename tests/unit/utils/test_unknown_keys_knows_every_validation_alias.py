# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""known_keys names every key pydantic accepts for a field.

A validation alias can be one name, an ``AliasChoices`` of several or an
``AliasPath`` into a nested value. known_keys read only a plain string, so
refuse_unknown_keys refused a key that pydantic would have accepted by one of the
choices or by a path's first segment.
"""

from __future__ import annotations

import pytest
from pydantic import AliasChoices, AliasPath, BaseModel, Field

from automated_security_helper.utils.unknown_keys import known_keys

pytestmark = pytest.mark.unit


class _Choosy(BaseModel):
    rule_id: str = Field(validation_alias=AliasChoices("rule_id", "ruleId", "rule-id"))
    reason: str = Field(validation_alias=AliasPath("details", "reason"))
    plain: str = Field(validation_alias="spelled")
    aliased: str = Field(alias="alias_name")


def test_each_choice_of_an_alias_choices_is_a_known_key():
    keys = known_keys(_Choosy)

    assert {"rule_id", "ruleId", "rule-id"} <= keys


def test_the_first_segment_of_an_alias_path_is_a_known_key():
    keys = known_keys(_Choosy)

    assert "details" in keys
    assert "reason" in keys  # the field's own name


def test_a_plain_validation_alias_and_an_alias_are_still_known():
    keys = known_keys(_Choosy)

    assert {"spelled", "plain", "alias_name", "aliased"} <= keys


def test_the_known_keys_are_what_the_model_accepts():
    accepted = _Choosy.model_validate(
        {
            "ruleId": "B101",
            "details": {"reason": "why"},
            "spelled": "x",
            "alias_name": "y",
        }
    )

    assert accepted.rule_id == "B101"
    assert accepted.reason == "why"
    assert {"ruleId", "details", "spelled", "alias_name"} <= known_keys(_Choosy)
