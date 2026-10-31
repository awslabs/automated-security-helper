# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The release-tag validator refuses a long non-tag in linear time.

``options.release_tag`` validates a version a plugin downloads by, with one
regular expression. Its two repeated groups both matched a ``.1`` part, so a
long value that is not a tag backtracked through every split of the two before
failing, quadratic in the value's length, during config validation. One
repeated group matches the same language and fails in one pass.

The cases run through the validator a plugin's option uses, so what is pinned is
what a config sees: a tag is kept, anything else reads as the option's default.
The language of the one-group pattern is also checked against the two-group
pattern it replaced, over every short string.
"""

from __future__ import annotations

import itertools
import re
import time
from typing import Annotated

import pytest
from pydantic import BaseModel

from automated_security_helper.base.options import _RELEASE_TAG, release_tag

pytestmark = pytest.mark.unit

DEFAULT = "v9.9.9"


class _Probe(BaseModel):
    version: Annotated[str, release_tag("scanners.probe.options.version")] = DEFAULT


def _kept(value: str) -> bool:
    """Whether the validator keeps ``value`` rather than reading the default."""
    return _Probe(version=value).version == value


@pytest.mark.parametrize(
    "tag",
    ["v1.15.1", "1.2.0-rc1", "1.2.0-rc1.beta", "1", "v1", "1.a", "1-a", "1.2-rc.1"],
)
def test_a_release_tag_still_matches(tag):
    assert _kept(tag), tag


# "1.2-rc_1" is refused by the original pattern too: its part class is
# [0-9A-Za-z], with no underscore, and the one-group pattern keeps that class.
@pytest.mark.parametrize(
    "value",
    ["1..2", "1.2/x", "1.2-", "a1", "", "v", "1.2 ", "1.2-rc_1", "1.2\n", "\n1.2"],
)
def test_a_non_tag_is_still_refused(value):
    assert not _kept(value), repr(value)
    assert _Probe(version=value).version == DEFAULT


def test_a_long_non_tag_is_refused_quickly():
    """At the base the two overlapping groups took seconds on this input
    (about 8 s for 20,000 parts on the host that measured it); one group
    answers in milliseconds. The bound is loose so a loaded runner passes."""
    value = "1" + ".1" * 20000 + "!"

    started = time.perf_counter()
    version = _Probe(version=value).version
    elapsed = time.perf_counter() - started

    assert version == DEFAULT
    assert elapsed < 2.0, elapsed


def test_the_one_group_pattern_matches_the_language_of_the_two_group_pattern():
    """The pattern the quadratic one was replaced by, kept here as the oracle:
    every string of up to five characters from the alphabet the pattern cares
    about is accepted by both or refused by both."""
    two_groups = re.compile(r"v?[0-9]+(\.[0-9]+)*([-.][0-9A-Za-z]+)*")
    alphabet = "1av.-_\n"
    checked = 0
    for length in range(0, 6):
        for chars in itertools.product(alphabet, repeat=length):
            text = "".join(chars)
            assert bool(_RELEASE_TAG.fullmatch(text)) == bool(
                two_groups.fullmatch(text)
            ), repr(text)
            checked += 1

    # A control for the oracle itself: it accepts and refuses something.
    assert two_groups.fullmatch("v1.2.3-rc1")
    assert not two_groups.fullmatch("1..2")
    assert checked == sum(len(alphabet) ** n for n in range(0, 6))
