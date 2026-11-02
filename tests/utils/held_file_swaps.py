# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one place the swap tests tell a held file from any other refusal.

The MCP config tests change what a name leads to from inside a call the server is
making. On Windows the server's own open handle on the checked file refuses that
change, and the test then has nothing to pin and skips. A ``PermissionError`` has
other causes there (a read-only attribute, an ACL, an indexer or antivirus
handle), and a skip for those would hide a server that stopped holding the file.
So only the two codes a held file gives are recorded; any other error is raised.
"""

from __future__ import annotations

import sys
from typing import Callable, List

import pytest

#: ``ERROR_ACCESS_DENIED``, what replacing or removing a file another handle holds
#: open without ``FILE_SHARE_DELETE`` can give.
ERROR_ACCESS_DENIED = 5
#: ``ERROR_SHARING_VIOLATION``, the other code of the same refusal.
ERROR_SHARING_VIOLATION = 32
HELD_FILE_WINERRORS = (ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION)


def swap_or_record(action: Callable[[], None], refused: List[BaseException]) -> bool:
    """Run ``action``, a replacement or a removal of the checked file.

    True when it ran. On Windows an ``OSError`` whose ``winerror`` is one of
    HELD_FILE_WINERRORS is the server's own handle refusing it: it is appended to
    ``refused`` for :func:`skip_if_refused` and the result is False. It is
    recorded and not raised because the action runs inside the server's call,
    which could turn an exception from it into an answer. Any other error, and
    every error elsewhere, is raised.
    """
    try:
        action()
    except PermissionError as error:
        if sys.platform != "win32":
            raise
        if getattr(error, "winerror", None) not in HELD_FILE_WINERRORS:
            raise
        refused.append(error)
        return False
    return True


def skip_if_refused(refused: List[BaseException]) -> None:
    """Skip the test when the operating system refused its swap (the module doc)."""
    if refused:
        pytest.skip(
            "Windows does not let a file the server holds open be replaced or "
            f"removed, so the swap this test pins cannot be made ({refused[0]})"
        )
