# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The deprecation warning for a command spelling that moved.

A command renamed in 3.9 keeps its old spelling through the 3.x line and is
removed in 4.0. The old spelling runs the same command and prints one warning
to stderr first, so a script that parses stdout is handed nothing new.
"""

from __future__ import annotations

import functools
from typing import Any, Callable

from automated_security_helper.utils.console import echo

#: The release that removes every spelling deprecated in 3.9.
REMOVED_IN = "4.0"

_warned: set[str] = set()


def deprecated_command_message(old: str, new: str) -> str:
    """The warning text for the command spelled *old* that moved to *new*."""
    return (
        f"Deprecated: 'ash {old}' is deprecated and will be removed in "
        f"{REMOVED_IN}; use 'ash {new}' instead."
    )


def warn_deprecated_command(old: str, new: str) -> None:
    """Print the warning for *old* to stderr, once per process."""
    if old in _warned:
        return
    _warned.add(old)
    echo(deprecated_command_message(old, new), err=True)


def deprecated_alias(callback: Callable[..., Any], old: str, new: str):
    """*callback* run under its old spelling *old*: the same command, one warning.

    The wrapper keeps the callback's signature, so the options, their help and
    their defaults are the new command's, and the two spellings cannot drift.
    """

    @functools.wraps(callback)
    def run(*args: Any, **kwargs: Any) -> Any:
        warn_deprecated_command(old, new)
        return callback(*args, **kwargs)

    return run
