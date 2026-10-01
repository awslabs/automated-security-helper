# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Replace a file's contents so a concurrent reader never sees a partial write.

``ash_aggregated_results.json`` is both the scan's result and its completion signal:
``check_scan_completion`` treats the file's existence as "the scan is done", and
``get_scan_progress`` builds its per-scanner section by parsing it. A plain
``open(path, "w")`` truncates the file to zero bytes before writing, so a reader that
lands in that window finds a file that exists but does not parse. Progress then reports
``status: completed`` with an empty ``scanners`` map, which is how a scan that ran every
scanner can look like one that ran none.

Writing to a sibling file and renaming it over the target closes that window, because
a rename within one directory is atomic: a reader opens either the old complete file or
the new complete one.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path

# Windows refuses to replace a file another process or thread has open, and a progress
# poll holds the aggregated file open for the length of one JSON parse. Retrying for a
# bounded time lets that read finish rather than failing the scan over it. POSIX never
# raises here, so the loop runs once.
_REPLACE_ATTEMPTS = 40
_REPLACE_BACKOFF_SECONDS = 0.05


def write_text_atomically(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Write ``content`` to ``path`` so that readers see the old file or the new one.

    The staging file is created in the target's own directory, because ``os.replace``
    is only atomic within one filesystem. It is created with ``open(..., "x")`` rather
    than ``tempfile.mkstemp`` so it gets the same umask-derived mode a plain write
    would: ``mkstemp`` creates 0600, which would stop a host user reading results a
    container wrote.
    """
    path = Path(path)
    staging = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with open(staging, mode="x", encoding=encoding) as handle:
            handle.write(content)
        _replace(staging, path)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise


def _replace(staging: Path, target: Path) -> None:
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            os.replace(staging, target)
            return
        except PermissionError:
            if sys.platform != "win32" or attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(_REPLACE_BACKOFF_SECONDS)
