# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ignore_path_pattern``: a directory pattern covers what is inside it, and a
spelling of the current directory covers nothing, however many separators end it.

``./`` and ``.\\`` were already returned as they are. ``.//`` and ``.\\\\`` were
not: the names-no-path check ran before the trailing separators came off, so
those spellings became ``./*/**``, which covers every ``./``-prefixed path, the
whole tree.
"""

import pytest

from automated_security_helper.utils.path_matching import ignore_path_pattern

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("pattern", ["", ".", "./", ".\\", ".//", "./\\", ".\\\\", "/"])
def test_a_spelling_of_no_path_is_left_as_it_is(pattern):
    assert ignore_path_pattern(pattern) == pattern


@pytest.mark.parametrize(
    "pattern, expected",
    [
        ("vendor/", "vendor/*/**"),
        ("vendor//", "vendor/*/**"),
        ("vendor\\", "vendor/*/**"),
        ("**/vendor/", "**/vendor/*/**"),
        ("vendor", "vendor"),
    ],
)
def test_a_directory_pattern_covers_what_is_inside_it(pattern, expected):
    assert ignore_path_pattern(pattern) == expected
