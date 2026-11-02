# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A RecordModel puts its extra fields' NAMES in the record form, not only the values.

A property bag's key is a name a tool or a repository chose, and a dump in JSON mode
UTF-8-encodes the keys, so an extra field whose name holds a lone surrogate failed
the dump as a value would. RecordModel put only the extra VALUES in the record form,
and the lone-surrogate tree check behind recorded() read only the values, so such a
dump was re-raised instead of repaired. A validated model never carries such a name:
pydantic-core refuses it as the extra field's name is validated, so the record form
matters for a constructed model and a field filled in after the build. The names are
built with chr(), so this file holds no lone surrogate itself.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ConfigDict, ValidationError

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


def test_a_validated_model_refuses_such_a_name_before_the_record_form():
    """pydantic-core validates an extra field's NAME as a str and refuses one that
    is not valid unicode (``string_unicode``), so a lone surrogate never reaches a
    validated model's property bag and the record form has nothing to do there:
    the refusal is loud, not a later dump failure. The record form is reached
    through model_construct (test_a_constructed_model_with_such_a_name_still_dumps)
    and a field filled in after the build
    (test_a_field_filled_in_after_the_build_dumps_in_the_record_form)."""
    with pytest.raises(ValidationError) as caught:
        _Bag.model_validate({"name": "x", RAW_NAME: 1})

    assert caught.value.error_count() == 1
    assert caught.value.errors()[0]["type"] == "string_unicode"


def test_a_validated_model_records_a_text_name_as_given():
    bag = _Bag.model_validate({"name": "x", "plain": 1})

    assert bag.model_dump(mode="json") == {"name": "x", "plain": 1}
    assert json.loads(bag.model_dump_json()) == {"name": "x", "plain": 1}


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


def test_a_field_filled_in_after_the_build_dumps_in_the_record_form():
    """The path the module docstring names: a validated model, then an extra field
    set by name, which pydantic does not validate."""
    bag = _Bag.model_validate({"name": "x"})

    setattr(bag, RAW_NAME, 1)

    assert RAW_NAME in (bag.__pydantic_extra__ or {})
    assert bag.model_dump(mode="json") == {"name": "x", RECORDED_NAME: 1}
    assert json.loads(bag.model_dump_json()) == {"name": "x", RECORDED_NAME: 1}


def test_two_names_with_one_record_form_keep_the_later_value():
    """A property bag cannot hold two equal keys, so a name that is already the
    record form of another collides with it. The record form is applied in the
    order the names were set and the later value stays; nothing is raised. The
    rule is pinned so a change to it is a decision: the earlier value is lost."""
    bag = _Bag.model_construct(name="x", **{RAW_NAME: 1, RECORDED_NAME: 2})

    assert bag.model_dump(mode="json") == {"name": "x", RECORDED_NAME: 2}
    copy = recorded(bag)
    assert (copy.__pydantic_extra__ or {}) == {RECORDED_NAME: 2}

    reversed_order = _Bag.model_construct(name="x", **{RECORDED_NAME: 2, RAW_NAME: 1})
    assert reversed_order.model_dump(mode="json") == {"name": "x", RECORDED_NAME: 1}


def test_a_model_whose_extra_names_are_text_is_left_alone():
    bag = _Bag.model_construct(name="x", plain=1)

    assert recorded(bag) is bag
    assert bag.model_dump(mode="json") == {"name": "x", "plain": 1}
