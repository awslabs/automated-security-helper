# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""File names the host's file system cannot hold, for tests that make one.

A test about a hostile name (``a*?b``, a tab, a double quote, a line break, an ESC)
makes a directory or a file under it. Windows refuses ``< > : " / \\ | ? *`` and the
characters 0 to 31 in a name, and reads a backslash as a separator. Creating one
there fails (``WinError 123``, ``Errno 22``) before the code under test runs, and no
such directory can exist for that code to refuse, contain or log. The test is
skipped, naming the characters, and only for a name and a host where that is true;
a name Windows can hold still runs there.
"""

import sys

import pytest

_WINDOWS = sys.platform == "win32"

#: What a Windows file name cannot hold: ``< > : " / \\ | ? *`` and the characters 0 to
#: 31. The measured instances are the CI errors for ``*?``, a tab, a double quote,
#: a line feed, a carriage return (``WinError 123``), an ESC (``Errno 22``) and a
#: backslash (``WinError 3``, a separator).
WINDOWS_REFUSES = frozenset('<>:"/\\|?*') | frozenset(map(chr, range(32)))


def refused_by_the_host(name: str, *, windows: bool = _WINDOWS) -> list[str]:
    """The characters of ``name`` the host's file system cannot hold, in order.

    Empty off Windows, where the names the tests use are legal.
    """
    return sorted(set(name) & WINDOWS_REFUSES) if windows else []


def skip_unless_the_host_can_name(name: str, *, windows: bool = _WINDOWS) -> None:
    """Skip the test that is running when ``name`` cannot be a file name on this host."""
    refused = refused_by_the_host(name, windows=windows)
    if refused:
        pytest.skip(
            "Windows file names cannot hold "
            + ", ".join(repr(character) for character in refused)
            + f", so nothing named {name!r} can exist there"
        )
