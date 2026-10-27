# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A test that needs a file named with a character the host refuses is skipped there.

Windows file names cannot hold ``< > : " / \\ | ? *`` or the characters 1 to 31.
The tests that make a directory or a file under a hostile name (``a*?b``, a tab, a
double quote, a line break, an ESC) stop with ``WinError 123`` ("The filename,
directory name, or volume label syntax is incorrect") or ``Errno 22`` before the
code under test runs, and a backslash is a separator there, so ``back\\slash`` is two
components. No such directory can exist on Windows, so there is nothing to refuse,
contain or log; the test says so and is skipped, and only on the hosts and for the
names where that is true.
"""

import pytest

from tests.utils.host_file_names import (
    refused_by_the_host,
    skip_unless_the_host_can_name,
)

#: Names the tests use that Windows can hold.
HOLDABLE = [
    "plain",
    "with space",
    "dollar$HOME",
    "semi;colon&amp",
    "quote'single",
    "uniéü",
    "eq=sign",
    "-leading-dash",
    "a,b",
    "glob[ab]",
]

#: Names the tests use that Windows cannot, and the characters it refuses in each.
REFUSED = [
    pytest.param("glob*?[ab]", ["*", "?"], id="glob"),
    pytest.param("back\\slash", ["\\"], id="backslash"),
    pytest.param("tab\there", ["\t"], id="tab"),
    pytest.param('x"y', ['"'], id="double-quote"),
    pytest.param("x\ny", ["\n"], id="line-feed"),
    pytest.param("x\ry", ["\r"], id="carriage-return"),
    pytest.param("\x1b[32mgreen.zip", ["\x1b"], id="escape"),
    pytest.param("a<b>c|d:e", [":", "<", ">", "|"], id="angle-pipe-colon"),
]


@pytest.mark.parametrize("name", HOLDABLE)
def test_windows_holds_these_names(name):
    assert refused_by_the_host(name, windows=True) == []


@pytest.mark.parametrize("name, refused", REFUSED)
def test_windows_refuses_exactly_these_characters(name, refused):
    assert refused_by_the_host(name, windows=True) == refused


@pytest.mark.parametrize("name", [*HOLDABLE, *(p.values[0] for p in REFUSED)])
def test_a_host_that_is_not_windows_refuses_none_of_them(name):
    assert refused_by_the_host(name, windows=False) == []


def test_a_name_the_host_cannot_hold_skips_and_names_the_characters():
    with pytest.raises(pytest.skip.Exception) as skipped:
        skip_unless_the_host_can_name("glob*?[ab]", windows=True)

    reason = str(skipped.value)
    assert "Windows file names cannot hold" in reason
    assert "'*'" in reason and "'?'" in reason
    assert "glob*?[ab]" in reason


@pytest.mark.parametrize("name", HOLDABLE)
def test_a_name_the_host_can_hold_does_not_skip(name):
    skip_unless_the_host_can_name(name, windows=True)


def test_nothing_is_skipped_on_a_host_that_is_not_windows():
    skip_unless_the_host_can_name('x"y*\x1b', windows=False)
