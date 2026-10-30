# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""known_keys names every key pydantic accepts for a field.

A validation alias can be one name, an ``AliasChoices`` of several or an
``AliasPath`` into a nested value. known_keys read only a plain string, so
refuse_unknown_keys refused a key that pydantic would have accepted by one of the
choices or by a path's first segment. An aliased field's own name is a key only
when the model populates by name: this model does not, so pydantic never reads
``reason``, ``plain`` or ``aliased`` as keys, and neither does known_keys.
"""

from __future__ import annotations

import pytest
from pydantic import AliasChoices, AliasPath, BaseModel, ConfigDict, Field

from automated_security_helper.utils.unknown_keys import known_keys, refuse_unknown_keys

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
    # The field's own name: the model does not populate by name, so pydantic
    # would not read it, and a key spelled so is an extra, not a value.
    assert "reason" not in keys


def test_a_plain_validation_alias_and_an_alias_are_still_known():
    keys = known_keys(_Choosy)

    assert {"spelled", "alias_name"} <= keys
    assert not {"plain", "aliased"} & keys


class _PathInChoices(BaseModel):
    """An ``AliasPath`` among the choices of an ``AliasChoices``, as a reporter's
    destination option declares one (tests/unit/config/
    test_reporter_trust_covers_an_alias_path.py)."""

    endpoint: str = Field(
        validation_alias=AliasChoices("url", AliasPath("connection", "endpoint"))
    )


class _PathInChoicesByName(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    endpoint: str = Field(
        validation_alias=AliasChoices("url", AliasPath("connection", "endpoint"))
    )


class _IndexedPath(BaseModel):
    first: str = Field(validation_alias=AliasPath(0, "first"))


def test_the_first_key_of_an_alias_path_among_choices_is_a_known_key():
    keys = known_keys(_PathInChoices)

    assert {"url", "connection"} <= keys
    # Not the path's second key, and not the field's name: the model does not
    # populate by name.
    assert not {"endpoint"} & keys


def test_a_key_the_model_reads_through_a_path_among_choices_is_not_refused():
    data = {"connection": {"endpoint": "https://file.invalid/"}}

    assert _PathInChoices.model_validate(data).endpoint == "https://file.invalid/"
    refuse_unknown_keys(_PathInChoices, data, None, "a reporter")


def test_the_field_name_is_also_known_when_the_model_populates_by_name():
    keys = known_keys(_PathInChoicesByName)

    assert {"endpoint", "url", "connection"} <= keys
    assert _PathInChoicesByName.model_validate({"endpoint": "x"}).endpoint == "x"
    refuse_unknown_keys(_PathInChoicesByName, {"endpoint": "x"}, None, "a reporter")


def test_a_path_that_starts_with_an_index_names_no_key():
    assert known_keys(_IndexedPath) == set()


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
