# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The deprecation warning for a command spelling that moved.

A command renamed in 3.9 keeps its old spelling through the 3.x line and is
removed in 4.0. The old spelling runs the same command and prints one warning
to stderr first on every invocation, so a script that parses stdout is handed
nothing new. The root group prints it (``AshRootTyperGroup``), for every spelling
in ``DEPRECATED_SPELLINGS``, so the wording lives here once.
"""

from __future__ import annotations

#: The release that removes every spelling deprecated in 3.9.
REMOVED_IN = "4.0"


def deprecated_command_message(old: str, new: str) -> str:
    """The warning text for the command spelled *old* that moved to *new*."""
    return (
        f"DeprecationWarning: 'ash {old}' is deprecated and is removed in "
        f"{REMOVED_IN}. Use 'ash {new}' instead; 'ash {old}' keeps its current "
        "behavior until then."
    )
