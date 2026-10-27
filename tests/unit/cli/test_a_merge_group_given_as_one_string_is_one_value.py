# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A merge value group given as one string is one value.

``value_tuple`` is the rule: a str is an iterable of its characters, and a
character is shorter than any band the redaction replaces, so a value split
that way prints whole.
"""

from __future__ import annotations

_VALUE = "one-value-not-fourteen"


def test_a_merge_group_given_as_one_string_is_one_value():
    """A merge value group that is a bare string joins as one value, never one
    per character."""
    from automated_security_helper.cli.merge import _each_value_once

    joined = _each_value_once(_VALUE, (f"{_VALUE}-2",))

    assert joined == [_VALUE, f"{_VALUE}-2"], joined


def test_merge_groups_given_as_tuples_are_unchanged():
    """The control: tuple groups join as they are, each value once."""
    from automated_security_helper.cli.merge import _each_value_once

    joined = _each_value_once((_VALUE,), (f"{_VALUE}-2", _VALUE))

    assert joined == [_VALUE, f"{_VALUE}-2"], joined
