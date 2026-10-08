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
