# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cut a tool's output down for an error message without losing its last words.

A tool that fails usually says why at the end. trivy, for one, prints its database
download progress first and the error that stopped it last, so an excerpt of the first
2000 characters of its stderr was all progress bar and no reason (seen in a podman CI
leg, where the message ended inside the download's progress output). An excerpt here
keeps the start, for context such as which config file was loaded, and the end, where
the error is, and says how much it left out between them.
"""

from __future__ import annotations

import re

#: Share of the limit given to the start of the text; the rest goes to the end.
_HEAD_SHARE = 4


def head_and_tail(text: str, limit: int) -> str:
    """``text`` cut to about ``limit`` characters, keeping its start and its end.

    Text within the limit is returned unchanged. Otherwise the first quarter of the
    limit and the last three quarters are kept, joined by a marker naming how many
    characters were left out. The marker itself is not counted against ``limit``.
    """
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    head = limit // _HEAD_SHARE
    tail = limit - head
    omitted = len(text) - head - tail
    return f"{text[:head]} ...[{omitted} characters omitted]... {text[-tail:]}"


#: ANSI escape sequences: CSI (colors, cursor moves) and OSC (titles, links).
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")

#: Control characters other than newline and tab, C0 and C1.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def tool_output_excerpt(text: str, limit: int) -> str:
    """A tool's output for an error message: escapes removed, then ``head_and_tail``.

    A tool's stderr can carry terminal escape sequences and other control
    characters, from its own coloring or from a file it echoes back, and an error
    message is shown in terminals, logs and reports. Escape sequences are removed
    and every other control character but newline and tab is written as ``\\xNN``,
    so nothing in the message can move a cursor, clear a screen or rewrite a line.
    """
    cleaned = _ANSI.sub("", text)
    cleaned = _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", cleaned)
    return head_and_tail(cleaned, limit)
