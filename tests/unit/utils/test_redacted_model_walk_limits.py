# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Four readings of the typed walk that were wrong at their edges.

- A value nested past the interpreter's recursion limit, at a recursive
  annotation, raised RecursionError out of the section's validator. It is
  refused by name now, with the variable of the first reference it holds.
- ``Counter[str]`` names its keys only, and pydantic validates the values as
  int; the walk read them as anything.
- The members of a set were read in hash order, so the reference a refusal
  named changed from run to run.
- An Enum with no members worded a container refusal with empty phrases.
"""

import enum
import re
import sys
from collections import Counter
from typing import Dict, Optional, Set

import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_LIMITS_CANARY"


def _refusal_text(model_type, payload) -> str:
    with pytest.raises(ValidationError) as refused:
        model_type.model_validate(payload)
    return " ".join(
        f"{error['loc']}: {error['msg']}" for error in refused.value.errors()
    )


class _Node(BaseModel):
    """A model that holds nodes of its own kind: a recursive annotation."""

    name: str = ""
    children: Dict[str, "_Node"] = {}


_Node.model_rebuild()


def _nested(depth: int, leaf):
    """A value *depth* levels deep with *leaf* at its name, built without
    recursion."""
    value = {"name": leaf}
    for _ in range(depth):
        value = {"children": {"key": value}}
    return value


def test_a_value_nested_past_the_recursion_limit_is_refused_by_name():
    class Section(RedactedSection):
        tree: Optional[_Node] = None

    depth = sys.getrecursionlimit() * 2
    text = _refusal_text(
        Section, {"tree": _nested(depth, env_resolved_scalar(CANARY, VARIABLE))}
    )
    assert VARIABLE in text, text
    assert "tree" in text, text
    assert "nested too deeply" in text, text
    assert CANARY not in text, text


def test_a_shallow_value_at_the_recursive_annotation_keeps_the_text():
    """The control: the same shape within the limit is walked and downcast."""

    class Section(RedactedSection):
        tree: Optional[_Node] = None

    section = Section.model_validate(
        {"tree": _nested(2, env_resolved_scalar(CANARY, VARIABLE))}
    )
    node = section.tree
    for _ in range(2):
        node = node.children["key"]
    assert node.name == CANARY
    assert type(node.name) is str


def test_a_counters_values_are_read_as_numbers():
    class Section(RedactedSection):
        counts: Optional[Counter[str]] = None

    text = _refusal_text(
        Section, {"counts": {"key": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    assert VARIABLE in text, text
    assert "counts" in text, text
    assert CANARY not in text, text


def test_a_counters_key_is_read_as_a_str():
    """The control: a reference used as a key lands in the str key slot."""

    class Section(RedactedSection):
        counts: Optional[Counter[str]] = None

    section = Section.model_validate(
        {"counts": {env_resolved_scalar("key-text", VARIABLE): 3}}
    )
    assert section.counts == Counter({"key-text": 3})


def test_a_set_of_references_is_refused_naming_the_same_variable_every_time():
    """Sixteen references, one variable each: the refusal names the one whose
    variable sorts first, whatever order the set iterates in. On the old bytes
    the set's own order decided, and the first member came out the one that
    sorts first in one run of sixteen."""

    class Section(RedactedSection):
        ids: Optional[Set[int]] = None

    markers = {
        env_resolved_scalar(str(100 + index), f"ASH_ORDER_{index:02d}")
        for index in range(16)
    }
    text = _refusal_text(Section, {"ids": markers})
    assert set(re.findall(r"ASH_ORDER_\d\d", text)) == {"ASH_ORDER_00"}, text


class _Mode(enum.Enum):
    pass


def test_a_container_at_an_enum_with_no_members_is_worded_by_the_enum_name():
    class Section(RedactedSection):
        kind: Optional[_Mode] = None

    text = _refusal_text(Section, {"kind": [env_resolved_scalar(CANARY, VARIABLE)]})
    assert VARIABLE in text, text
    assert "Input should be a valid _mode" in text, text
    assert "where a _mode is expected" in text, text
    assert "should be :" not in text, text
