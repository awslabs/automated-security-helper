# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The deprecation warning for a command spelling that moved.

A command renamed in 3.9 keeps its old spelling through 4.0 and is removed in
4.1. The old spelling runs the same command and prints one warning to stderr
first on every invocation, so a script that parses stdout is handed nothing new.
The root group prints it (``AshRootTyperGroup``), for every spelling in
``DEPRECATED_SPELLINGS``, so the wording lives here once. The warning names the
command as ``CANONICAL_CLI_NAME``, as every message that names the command does.
"""

from __future__ import annotations

from automated_security_helper.cli.deprecations import CANONICAL_CLI_NAME

#: The release that removes every spelling deprecated in 3.9. 4.0 still runs
#: each of them, with the warning below.
REMOVED_IN = "4.1"


def deprecated_command_message(old: str, new: str) -> str:
    """The warning text for the command spelled *old* that moved to *new*."""
    cli = CANONICAL_CLI_NAME
    return (
        f"DeprecationWarning: '{cli} {old}' is deprecated and is removed in "
        f"{REMOVED_IN}. Use '{cli} {new}' instead; '{cli} {old}' keeps its current "
        "behavior until then."
    )
