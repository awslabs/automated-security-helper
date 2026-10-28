# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge`` hides a shard's values in its refusals as config validation does.

A copy of config_validator.redact_values that replaced the values one
alternation at a time would, with two values that overlap, have the first match
win and leave part of the other in the message, and mark a marker already in the
text again. merge goes through redact_values itself, adding the forms pydantic
stores a value in once it is stripped.
"""

from __future__ import annotations

from automated_security_helper.cli import merge
from automated_security_helper.config.config_validator import redact_values


def test_overlapping_values_leave_no_part_behind():
    text = "x foo/bar/baz-long y"
    values = ["foo/bar", "bar/baz-long"]

    assert merge._redact_values(text, values) == "x <value> y"
    assert merge._redact_values(text, values) == redact_values(text, values)


def test_a_marker_already_in_the_text_is_left_as_it_is():
    assert merge._redact_values("x <value> y", ["value"]) == "x <value> y"


def test_the_validator_leaves_an_environment_marker_as_it_is():
    """The ``<from ${VAR}>`` an environment record writes is left whole by
    redact_values's default, the variable's name inside it included; only a
    caller whose text holds no such record, as merge's, passes REDACTED_MARKERS."""
    text = "<from ${ASH_TOKEN_NAME}>"
    assert redact_values(text, ["ASH_TOKEN_NAME"]) == text


def test_a_shard_value_shaped_like_an_environment_marker_is_hidden():
    """A shard's value is the shard's, whatever it looks like: the
    ``<from ${VAR}>`` a config's refusal leaves as it is is no marker merge
    wrote, so a value shaped like one, or inside one, is hidden too."""
    assert (
        merge._redact_values("got '<from abcdSECRET>'", ["<from abcdSECRET>"])
        == "got '<value>'"
    )
    assert (
        merge._redact_values("got '<from abcdSECRET>'", ["abcdSECRET"])
        == "got '<from <value>>'"
    )


def test_control_a_value_stored_stripped_is_hidden_too():
    """What the copy did on top of the validator, kept: a value pydantic strips
    before an error quotes it is found in its stripped form."""
    assert merge._redact_values("got 'abcd'", ["  abcd\t"]) == "got '<value>'"


def test_control_a_short_shard_value_is_left_even_quoted():
    """A shard's values are its results file's inputs, not the environment's, and
    are replaced as a model error's input is (``whole_words``): one under four
    characters is left, quoted or not, so a message's own quoted choices stay."""
    assert merge._redact_values("got 'abc'", ["abc"]) == "got 'abc'"
