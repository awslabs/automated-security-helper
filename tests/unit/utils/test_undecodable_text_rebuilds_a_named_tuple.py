# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""texts_of_undecodable (utils/undecodable_text.py) rebuilds a NamedTuple as one.

A changed tuple subclass was rebuilt with type(value)(items), which hands a
NamedTuple one list where it wants its fields and raises TypeError; a result
whose property bag held one with a name that is not UTF-8 failed its dump.
"""

from __future__ import annotations

from typing import NamedTuple

import pytest

from automated_security_helper.utils.undecodable_text import texts_of_undecodable

pytestmark = pytest.mark.unit


class _Span(NamedTuple):
    file: str
    start: int
    end: int


def test_a_named_tuple_with_a_name_that_is_not_utf8_is_rebuilt_as_itself():
    span = _Span("b" + chr(0xDCE9) + ".tar", 1, 2)

    recorded = texts_of_undecodable(span)

    assert isinstance(recorded, _Span)
    assert recorded == _Span("b\\udce9.tar", 1, 2)


def test_a_named_tuple_that_needs_no_change_is_returned_itself():
    span = _Span("plain.py", 1, 2)
    assert texts_of_undecodable(span) is span


def test_a_plain_tuple_and_a_set_are_still_rebuilt_as_their_types():
    assert texts_of_undecodable(("a" + chr(0xDCE9), 1)) == ("a\\udce9", 1)
    assert texts_of_undecodable({"a" + chr(0xDCE9)}) == {"a\\udce9"}
