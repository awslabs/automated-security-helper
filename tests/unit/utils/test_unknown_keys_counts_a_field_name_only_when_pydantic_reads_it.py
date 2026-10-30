# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""known_keys (utils/unknown_keys.py) counts a field's name only when pydantic reads it.

An aliased field of a model that does not populate by name takes its alias
only, so a key written by the field's name is an extra the model never reads.
known_keys counted the name all the same, and refuse_unknown_keys let the dead
key through where a misspelled alias is refused with its "did you mean".
"""

from __future__ import annotations

import pytest
from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from automated_security_helper.utils.unknown_keys import known_keys, refuse_unknown_keys

pytestmark = pytest.mark.unit


class _AliasOnly(BaseModel):
    rule_id: str = Field(validation_alias=AliasChoices("ruleId", "rule-id"))
    plain: str = ""


class _ByNameToo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    rule_id: str = Field(validation_alias=AliasChoices("ruleId", "rule-id"))


def test_an_alias_only_fields_name_is_not_a_key():
    keys = known_keys(_AliasOnly)
    assert "rule_id" not in keys
    assert {"ruleId", "rule-id", "plain"} <= keys
    # The control: the model does not read the field's name either.
    with pytest.raises(Exception):
        _AliasOnly.model_validate({"rule_id": "B101"})


def test_the_name_is_a_key_when_the_model_populates_by_name():
    assert {"rule_id", "ruleId", "rule-id"} <= known_keys(_ByNameToo)
    assert _ByNameToo.model_validate({"rule_id": "B101"}).rule_id == "B101"


def test_a_dead_key_written_by_field_name_is_refused():
    with pytest.raises(ValueError) as raised:
        refuse_unknown_keys(_AliasOnly, {"rule_id": "B101"}, None, "a suppression")
    message = str(raised.value)
    assert "'rule_id'" in message
    # Both aliases fold to the dead name; closest_key suggests the first in
    # sorted order, and "-" sorts before "I".
    assert "did you mean 'rule-id'" in message, message
