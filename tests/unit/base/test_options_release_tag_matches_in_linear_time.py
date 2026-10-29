# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The release-tag pattern refuses a long non-tag in linear time.

``options.release_tag`` validates a version a plugin downloads by, with one
regular expression. Its two repeated groups both matched a ``.1`` part, so a
long value that is not a tag backtracked through every split of the two before
failing, quadratic in the value's length, during config validation. One
repeated group matches the same language and fails in one pass.
"""

from __future__ import annotations

import time

import pytest

from automated_security_helper.base.options import _RELEASE_TAG

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "tag",
    ["v1.15.1", "1.2.0-rc1", "1.2.0-rc1.beta", "1", "v1", "1.a", "1-a", "1.2-rc_1"],
)
def test_a_release_tag_still_matches(tag):
    assert _RELEASE_TAG.fullmatch(tag) is not None, tag


@pytest.mark.parametrize("value", ["1..2", "1.2/x", "1.2-", "a1", "", "v", "1.2 "])
def test_a_non_tag_is_still_refused(value):
    assert _RELEASE_TAG.fullmatch(value) is None, repr(value)


def test_a_long_non_tag_is_refused_quickly():
    """At the base the two overlapping groups took seconds on this input
    (about 8 s for 20,000 parts on the host that measured it); one group
    answers in milliseconds. The bound is loose so a loaded runner passes."""
    value = "1" + ".1" * 20000 + "!"

    started = time.perf_counter()
    matched = _RELEASE_TAG.fullmatch(value)
    elapsed = time.perf_counter() - started

    assert matched is None
    assert elapsed < 2.0, elapsed
