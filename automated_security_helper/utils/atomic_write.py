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
from typing import Optional

# Windows refuses to replace a file another process or thread has open, and a progress
# poll holds the aggregated file open for the length of one JSON parse. Retrying for a
# bounded time lets that read finish rather than failing the scan over it. POSIX never
# raises here, so the loop runs once.
_REPLACE_ATTEMPTS = 40
_REPLACE_BACKOFF_SECONDS = 0.05


def write_text_atomically(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Write ``content`` to ``path`` so that readers see the old file or the new one.

    The staging file is created in the target's own directory, because ``os.replace``
    is only atomic within one filesystem. It is created exclusively rather than with
    ``tempfile.mkstemp`` so it gets the same umask-derived mode a plain write would:
    ``mkstemp`` creates 0600, which would stop a host user reading results a
    container wrote.

    Below a registered output directory (``fs_guard``), the directory is opened
    without following a link at any component, and the staging file is created and
    renamed relative to that descriptor: a link on the way to ``path``, or at
    ``path`` itself, raises ``OutputLinkRefused``, and a file at ``path`` that
    another name refers to raises ``OutputHardLinkRefused``.
    """
    from automated_security_helper.utils.sandbox.fs_guard import open_parent_beneath

    path = Path(path)
    guarded = open_parent_beneath(path)
    if guarded is not None:
        _write_beneath(*guarded, content=content, encoding=encoding, target=path)
        return
    staging = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with open(staging, mode="x", encoding=encoding) as handle:
            handle.write(content)
        _replace(staging, path)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise


def _write_beneath(
    dir_fd: int,
    name: str,
    *,
    content: str,
    encoding: str,
    target: Optional[Path] = None,
) -> None:
    """Write ``name`` in ``dir_fd`` through a staging file renamed over it.

    The name is checked again just before the rename, as open_parent_beneath checked
    it when it opened the directory: a link there, or a file another name refers to,
    raises rather than being replaced, and the staging file is removed. ``target``
    is the path to name in the error.
    """
    # Not at the top: fs_guard imports the sandbox package. Do not hoist.
    from automated_security_helper.utils.sandbox.fs_guard import _refuse_link_at

    shown = target if target is not None else Path(name)
    staging = f".{name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(staging, flags, 0o666, dir_fd=dir_fd)
        try:
            with os.fdopen(fd, "w", encoding=encoding) as handle:
                handle.write(content)
            _refuse_link_at(name, dir_fd, shown)
            os.replace(staging, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except BaseException:
            try:
                os.unlink(staging, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
            raise
    finally:
        os.close(dir_fd)


def read_text_of_replaced_file(path: Path, encoding: str = "utf-8") -> str:
    """Read a file that ``write_text_atomically`` may be replacing at this moment.

    The rename is atomic for readers on POSIX, but not on Windows. There ``os.replace``
    holds the file open without read sharing while it swaps it, so a reader whose open
    lands in that window gets a sharing violation, which Python raises as
    ``PermissionError``. The file is not unreadable: a moment later it is the new
    complete file. Treating that error as a read failure is how a progress poll
    reported a finished scan as ``failed`` with no scanners on Windows CI.

    So on Windows a ``PermissionError`` is retried for the same bounded time the writer
    allows itself. A file that is still unreadable after that raises the error, so a
    real permission problem is reported, only later. POSIX never retries.
    """
    path = Path(path)
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            with open(path, encoding=encoding) as handle:
                return handle.read()
        except PermissionError:
            if sys.platform != "win32" or attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(_REPLACE_BACKOFF_SECONDS)
    raise AssertionError("unreachable: the last attempt returns or raises")


def _replace(staging: Path, target: Path) -> None:
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            os.replace(staging, target)
            return
        except PermissionError:
            if sys.platform != "win32" or attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(_REPLACE_BACKOFF_SECONDS)
