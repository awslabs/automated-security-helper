# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A RecordModel puts its extra fields' NAMES in the record form, not only the values.

A property bag's key is a name a tool or a repository chose, and a dump in JSON mode
UTF-8-encodes the keys, so an extra field whose name holds a lone surrogate failed
the dump as a value would. RecordModel put only the extra VALUES in the record form,
and the lone-surrogate tree check behind recorded() read only the values, so such a
dump was re-raised instead of repaired. The names are built with chr(), so this file
holds no lone surrogate itself.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ConfigDict

from automated_security_helper.utils.undecodable_text import (
    RecordModel,
    recorded,
    text_of_undecodable,
)

pytestmark = pytest.mark.unit

#: The lone surrogate a surrogateescape decode of a latin-1 0xE9 byte produces.
SURROGATE = chr(0xDCE9)
RAW_NAME = "caf" + SURROGATE
RECORDED_NAME = text_of_undecodable(RAW_NAME)


class _Bag(RecordModel):
    model_config = ConfigDict(extra="allow")

    name: str = "x"


def test_a_validated_model_records_the_extra_fields_names():
    bag = _Bag.model_validate({"name": "x", RAW_NAME: 1})

    assert RECORDED_NAME in (bag.__pydantic_extra__ or {})
    assert RAW_NAME not in (bag.__pydantic_extra__ or {})
    assert bag.model_dump(mode="json") == {"name": "x", RECORDED_NAME: 1}
    assert json.loads(bag.model_dump_json()) == {"name": "x", RECORDED_NAME: 1}


def test_a_constructed_model_with_such_a_name_still_dumps():
    # model_construct runs no validator, so the name reaches the dump as given,
    # the shape of a field filled in after the model was built.
    bag = _Bag.model_construct(name="x", **{RAW_NAME: 1})

    assert bag.model_dump(mode="json") == {"name": "x", RECORDED_NAME: 1}
    assert json.loads(bag.model_dump_json()) == {"name": "x", RECORDED_NAME: 1}
    copy = recorded(bag)
    assert copy is not bag
    assert RECORDED_NAME in (copy.__pydantic_extra__ or {})
    # The model itself is left as it was.
    assert RAW_NAME in (bag.__pydantic_extra__ or {})


def test_a_model_whose_extra_names_are_text_is_left_alone():
    bag = _Bag.model_construct(name="x", plain=1)

    assert recorded(bag) is bag
    assert bag.model_dump(mode="json") == {"name": "x", "plain": 1}
