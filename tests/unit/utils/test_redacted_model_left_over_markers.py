# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No reference survives validation outside the sections of a section-reaching
field.

A value under a field that reaches another section is handed to pydantic with
its markers, so the section in the shape receives them. The slots beside the
section are downcast before that where the annotation says which slot a value
lands in, but a union of several arms keeps the value as given: which arm
describes it is pydantic's call. When pydantic then picked a sibling arm (a
``Dict[str, Any]``, a plain model with an Any field), the marker survived in
the validated model as a str subclass, which a config dump cannot write.

The field is now downcast after validation, in the containers and in the plain
models the validated value holds; a section is left to its own validator.

The downcast keeps each container as the instance pydantic built. Rebuilt as
base types, a validated ``OrderedDict`` came back a plain dict and a NamedTuple
a plain tuple whose fields no longer answered by name; a deque and a dataclass
instance were not walked at all and kept the marker class.

It writes into nothing it was given: an Any slot returns its input by
identity, so a container in the validated value can be the caller's own payload
object, and a rewrite in place stripped the markers out of the payload; a
sub-object shared with a second field then reached that field's typed slot as
plain text and was typed silently.
"""

import collections
import dataclasses
from typing import Any, Deque, Dict, List, NamedTuple, Optional, Union

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    _downcast_what_validation_kept,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

VARIABLE = "ASH_LEFT_OVER_CANARY"


class _Closed(RedactedSection):
    """A section that refuses a key it does not declare, so a dict that holds
    one can only be taken by the sibling arm."""

    model_config = ConfigDict(extra="forbid")

    name: str = ""


class _Plain(BaseModel):
    payload: Any = None


def test_a_dict_arm_beside_a_section_arm_holds_plain_text():
    class Section(RedactedSection):
        value: Optional[Union[_Closed, Dict[str, Any]]] = None

    section = Section.model_validate(
        {"value": {"free": env_resolved_scalar("loose-text", VARIABLE)}}
    )
    assert section.value == {"free": "loose-text"}
    assert type(section.value["free"]) is str


def test_a_nested_value_in_the_dict_arm_holds_plain_text():
    class Section(RedactedSection):
        value: Optional[Union[_Closed, Dict[str, Any]]] = None

    section = Section.model_validate(
        {"value": {"free": [{"deep": env_resolved_scalar("loose-text", VARIABLE)}]}}
    )
    assert type(section.value["free"][0]["deep"]) is str


def test_a_plain_model_arm_beside_a_section_arm_holds_plain_text():
    class Section(RedactedSection):
        value: Optional[Union[_Closed, _Plain]] = None

    section = Section.model_validate(
        {"value": {"payload": env_resolved_scalar("loose-text", VARIABLE)}}
    )
    assert isinstance(section.value, _Plain)
    assert section.value.payload == "loose-text"
    assert type(section.value.payload) is str


def test_a_container_in_a_plain_model_arm_holds_plain_text():
    class Section(RedactedSection):
        value: Optional[Union[_Closed, _Plain]] = None

    section = Section.model_validate(
        {"value": {"payload": [env_resolved_scalar("loose-text", VARIABLE)]}}
    )
    assert isinstance(section.value, _Plain)
    assert type(section.value.payload[0]) is str


def test_the_section_arm_still_receives_the_text_it_takes():
    """The control: the section takes the value and downcasts its own. The
    dict arm types its values as numbers, so it cannot take this text."""

    class Section(RedactedSection):
        value: Optional[Union[_Closed, Dict[str, int]]] = None

    section = Section.model_validate(
        {"value": {"name": env_resolved_scalar("loose-text", VARIABLE)}}
    )
    assert isinstance(section.value, _Closed)
    assert section.value.name == "loose-text"
    assert type(section.value.name) is str


def test_an_ordered_dict_beside_a_section_arm_keeps_its_class():
    """pydantic builds the field an OrderedDict; the downcast of the marker it
    kept must not hand back a plain dict."""

    class Section(RedactedSection):
        value: Optional[collections.OrderedDict[str, Union[_Closed, Any]]] = None

    section = Section.model_validate(
        {"value": {"free": env_resolved_scalar("loose-text", VARIABLE)}}
    )
    assert isinstance(section.value, collections.OrderedDict)
    assert section.value == {"free": "loose-text"}
    assert type(section.value["free"]) is str


class _Point(NamedTuple):
    x: Any


def test_a_named_tuple_beside_a_section_arm_keeps_its_class():
    """A NamedTuple built by pydantic answers by field name; rebuilt as a plain
    tuple it no longer did."""

    class Section(RedactedSection):
        value: Optional[List[Union[_Closed, _Point]]] = None

    section = Section.model_validate(
        {"value": [[env_resolved_scalar("loose-text", VARIABLE)]]}
    )
    assert isinstance(section.value[0], _Point)
    assert section.value[0].x == "loose-text"
    assert type(section.value[0].x) is str


def test_a_deque_beside_a_section_arm_holds_plain_text():
    class Section(RedactedSection):
        value: Optional[Deque[Union[_Closed, Any]]] = None

    section = Section.model_validate(
        {"value": [env_resolved_scalar("loose-text", VARIABLE)]}
    )
    assert isinstance(section.value, collections.deque)
    assert type(section.value[0]) is str


@dataclasses.dataclass
class _Bag:
    payload: Any = None


def test_a_dataclass_instance_beside_a_section_arm_holds_plain_text():
    class Section(RedactedSection):
        value: Optional[Union[_Closed, _Bag]] = None

    section = Section.model_validate(
        {"value": {"payload": env_resolved_scalar("loose-text", VARIABLE)}}
    )
    assert isinstance(section.value, _Bag)
    assert section.value.payload == "loose-text"
    assert type(section.value.payload) is str


def test_the_payload_given_is_left_as_given():
    """The list under the dict arm's Any slot is the caller's own object
    (pydantic hands an Any slot's input back by identity); the downcast
    rebuilds a copy and leaves the payload's marker where the caller put it."""

    class Section(RedactedSection):
        value: Optional[Union[_Closed, Dict[str, Any]]] = None

    marker = env_resolved_scalar("loose-text", VARIABLE)
    inner = {"deep": marker}
    payload = {"value": {"free": [inner]}}
    section = Section.model_validate(payload)
    assert type(section.value["free"][0]["deep"]) is str
    assert inner["deep"] is marker
    assert payload["value"]["free"][0] is inner


def test_a_sub_object_shared_with_a_typed_field_is_still_refused_there():
    """The same dict sits under an Any slot of the first field and at the typed
    dict of the second. With the first field's downcast written into the
    shared object, the second field saw plain text and typed the env-read
    value silently; the markers now survive to the second field, whose int
    slot refuses the reference by name."""

    class Section(RedactedSection):
        first: Optional[Union[_Closed, Dict[str, Any]]] = None
        second: Optional[Union[_Closed, Dict[str, int]]] = None

    shared = {"count": env_resolved_scalar("424242", VARIABLE)}
    with pytest.raises(ValidationError) as refused:
        Section.model_validate({"first": {"free": [shared]}, "second": shared})
    text = " ".join(
        f"{error['loc']}: {error['msg']}" for error in refused.value.errors()
    )
    assert VARIABLE in text, text
    assert "second" in text, text
    assert "424242" not in text, text


def test_a_counter_keeps_its_counts_and_its_class():
    """A Counter's ``update`` counts an iterable's elements, so rebuilding it
    from pairs produced counts of 1 for each pair; each key is set one at a
    time, and the input Counter is left as given."""
    marker = env_resolved_scalar("loose-text", VARIABLE)
    given = collections.Counter({marker: 2, "other": 1})
    out = _downcast_what_validation_kept(given)
    assert isinstance(out, collections.Counter)
    assert out["loose-text"] == 2 and out["other"] == 1
    assert all(type(key) is str for key in out)
    assert out is not given
    assert any(key is marker for key in given)


class _Loose(tuple):
    """A tuple subclass with a ``__dict__``, so an instance can carry an
    attribute named like a NamedTuple's ``_fields`` without being one."""

    __slots__ = ("__dict__",)


def test_a_tuple_subclass_with_an_instance_fields_attribute_is_rebuilt_as_itself():
    """Whether a tuple is a NamedTuple is read on its class: an instance that
    merely carries a ``_fields`` attribute has no ``_make``, and reading the
    instance sent it there and raised."""
    marker = env_resolved_scalar("loose-text", VARIABLE)
    given = _Loose([marker, "kept"])
    given._fields = ("not", "a", "namedtuple")
    out = _downcast_what_validation_kept(given)
    assert type(out) is _Loose
    assert type(out[0]) is str and out[0] == "loose-text"
    assert out[1] == "kept"


class _Clinging(dict):
    """A dict subclass whose copy protocol answers with the object itself."""

    def __copy__(self):
        return self


def test_a_container_whose_copy_is_itself_is_rebuilt_as_its_base_and_left_as_given():
    """The rebuild copies a container before it writes, and a copy protocol
    that hands back the very object would turn that write into a write on the
    caller's payload (cleared and refilled with plain text); such a container
    is rebuilt as its base class and the one given is left as given."""

    class Section(RedactedSection):
        value: Optional[Dict[str, Union[_Closed, Any]]] = None

    marker = env_resolved_scalar("loose-text", VARIABLE)
    clinging = _Clinging({"deep": marker})
    section = Section.model_validate({"value": {"free": clinging}})
    assert clinging["deep"] is marker
    rebuilt = section.value["free"]
    assert type(rebuilt) is dict
    assert type(rebuilt["deep"]) is str
    assert rebuilt["deep"] == "loose-text"
