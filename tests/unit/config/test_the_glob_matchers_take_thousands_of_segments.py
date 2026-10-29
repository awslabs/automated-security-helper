# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pointer glob matchers take a path of thousands of segments.

``_match_segments`` and ``_pattern_reaches_into`` recursed once per segment, so
a JSON pointer with a few thousand segments, well inside the 64 KiB a client
may send, raised RecursionError out of the matchers and escaped the
``RuntimePatchDeniedError`` contract. Both now run as one forward pass over the
pattern.

Red at the base: each matcher raised RecursionError on the long path.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.runtime_patch import (
    _match_segments,
    _path_matches,
    _pattern_reaches_into,
)

pytestmark = pytest.mark.unit

LONG = ["a"] * 5000


def test_match_segments_takes_a_long_path() -> None:
    assert _match_segments(["**", "leaf"], [*LONG, "leaf"]) is True
    assert _match_segments(["**", "other"], [*LONG, "leaf"]) is False
    assert _match_segments(["*"] * len(LONG), LONG) is True


def test_pattern_reaches_into_takes_a_long_path() -> None:
    assert _pattern_reaches_into(["**"], LONG) is True
    assert _pattern_reaches_into(["b", "**"], LONG) is False
    assert _pattern_reaches_into([*LONG, "**", "leaf"], LONG) is True


def test_path_matches_takes_a_long_pointer() -> None:
    pointer = "/" + "/".join(LONG) + "/leaf"

    assert _path_matches("/**/leaf", pointer) is True
    assert _path_matches("/**/other", pointer) is False


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        (["a", "b"], ["a", "b"], True),
        (["a", "*"], ["a", "b"], True),
        (["a", "*"], ["a"], False),
        (["**"], [], True),
        (["a", "**", "c"], ["a", "c"], True),
        (["a", "**", "c"], ["a", "x", "y", "c"], True),
        (["a", "**", "c"], ["a", "x", "y"], False),
        (["aws_*"], ["aws_region"], True),
        (["aws_*"], ["region"], False),
    ],
)
def test_short_patterns_match_as_before(
    pattern: list, path: list, expected: bool
) -> None:
    """The control: the matcher's answers on short paths are unchanged."""
    assert _match_segments(pattern, path) is expected


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        (["a"], ["a", "b"], False),
        (["a", "b", "c"], ["a", "b"], True),
        (["**"], ["a", "b"], True),
        (["a", "*", "c"], ["a", "b"], True),
        (["x", "**"], ["a", "b"], False),
    ],
)
def test_short_subtree_reaches_as_before(
    pattern: list, path: list, expected: bool
) -> None:
    """The control for the subtree matcher."""
    assert _pattern_reaches_into(pattern, path) is expected
