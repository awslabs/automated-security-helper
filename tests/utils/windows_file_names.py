# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Test names that a Windows file system cannot hold.

POSIX accepts every byte but ``/`` and NUL in a file name. Windows refuses ``<``,
``>``, ``:``, ``"``, ``|``, ``?``, ``*`` and every control character in one, and
reads ``\\`` as a separator, so a test that creates a directory named
``x"y`` or ``back\\slash`` fails at ``mkdir`` there before it reaches the code
under test. :func:`created_on_disk` marks those parameters skipped on Windows and
leaves every other parameter, and every other platform, as it was.
"""

from __future__ import annotations

import sys
from typing import Iterable, List

import pytest

#: Characters a Windows file name cannot carry (a backslash is a separator there).
WINDOWS_REFUSED_CHARACTERS = frozenset('<>:"/\\|?*') | frozenset(
    chr(code) for code in range(32)
)


def cannot_be_a_windows_file_name(name: str) -> bool:
    """Whether *name* holds a character a Windows file name cannot carry."""
    return any(character in WINDOWS_REFUSED_CHARACTERS for character in name)


def created_on_disk(names: Iterable) -> List:
    """The ``pytest.param`` names, for a test that creates each one as a file name.

    Each parameter whose name Windows cannot hold is skipped on Windows with the
    reason; the others are returned unchanged.
    """
    marked = []
    for param in names:
        (name,) = param.values
        marked.append(
            pytest.param(
                name,
                id=param.id,
                marks=[
                    *param.marks,
                    pytest.mark.skipif(
                        sys.platform == "win32" and cannot_be_a_windows_file_name(name),
                        reason=(
                            "a Windows file system cannot hold a file name with this "
                            "character, so the directory the test needs cannot exist"
                        ),
                    ),
                ],
            )
        )
    return marked
