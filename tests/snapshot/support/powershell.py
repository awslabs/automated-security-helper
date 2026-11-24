# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reading what PowerShell printed, for the snapshot tests that run ``Invoke-ASH``."""

from __future__ import annotations

import re


def error_message(text: str) -> str:
    """The message of the error PowerShell printed, without its location or excerpt.

    For an error thrown in a script, PowerShell's ConciseView prints
    ``<category>: <script>:<line>``, ``Line |``, the source line, and a ``~~~``
    underline, then the message on ``|`` lines wrapped to the console width. The
    location and the excerpt change with every edit to the wrapper and the wrapping
    with the console, so only the message is kept, unwrapped. An error printed without
    an excerpt is one ``<category>: <message>`` line, kept as it is.
    """
    lines = [
        line
        for line in re.sub(r"\x1b\[[0-9;]*m", "", text).splitlines()
        if line.strip()
    ]
    for index, line in enumerate(lines):
        if set(line.replace("|", "").strip()) == {"~"}:
            return " ".join(
                rest.split("|", 1)[1].strip()
                for rest in lines[index + 1 :]
                if "|" in rest
            )
    return lines[0] if lines else ""
