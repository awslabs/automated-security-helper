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
import secrets
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional, TextIO, cast

# Windows refuses to replace a file another process or thread has open, and a progress
# poll holds the aggregated file open for the length of one JSON parse. Retrying for a
# bounded time lets that read finish rather than failing the scan over it. POSIX never
# raises here, so the loop runs once.
_REPLACE_ATTEMPTS = 40
_REPLACE_BACKOFF_SECONDS = 0.05


def _staging_path(path: Path) -> Path:
    """A file beside *path*, named for this process and a random token.

    The token comes from :mod:`secrets`, not ``uuid.uuid4``: the snapshot tests pin
    ``uuid.uuid4`` to a counter that report ids are built from, and a staging name
    that drew from it shifted the id of every report made after the write.
    """
    return path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp")


def write_text_atomically(
    path: Path, content: str, encoding: str = "utf-8", *, root: Optional[Path] = None
) -> None:
    """Write ``content`` to ``path`` so that readers see the old file or the new one.

    fs_guard.open_for_atomic_write does the writing: a staging file created
    exclusively in the target's own directory, because ``os.replace`` is only atomic
    within one filesystem, then renamed over ``path``. Created exclusively rather
    than with ``tempfile.mkstemp`` so it gets the same umask-derived mode a plain
    write would: ``mkstemp`` creates 0600, which would stop a host user reading
    results a container wrote.

    Below a registered output directory (``fs_guard``), or below ``root`` when the
    caller names the directory it writes in, the directory is opened without
    following a link at any component, and the staging file is created and renamed
    relative to that descriptor: a link on the way to ``path``, or at ``path``
    itself, raises ``OutputLinkRefused``, and a file at ``path`` that another name
    refers to raises ``OutputHardLinkRefused``. ``root`` is for a writer that knows
    its output directory but may run where nothing registered it (the scan-set
    lists); it guards this write only and registers nothing.
    """
    # Not at the top: fs_guard imports the sandbox package. Do not hoist.
    from automated_security_helper.utils.sandbox.fs_guard import open_for_atomic_write

    with open_for_atomic_write(path, encoding=encoding, root=root) as handle:
        handle.write(content)


@contextmanager
def open_atomically(path: Path, encoding: str = "utf-8") -> Iterator[TextIO]:
    """A text handle whose contents replace ``path`` when the block ends.

    :func:`write_text_atomically` for a writer that streams its content rather than
    holding it whole, such as the workspace's unified results file, assembled one
    project's SARIF at a time. Written to a staging file beside ``path`` and renamed
    over it when the block completes; if the block raises, the staging file is
    removed and ``path`` is left as it was.

    The staging file is created through ``fs_guard.open_for_write``, exclusively,
    so below a registered output directory no link is followed on the way to it.
    Elsewhere that is the plain exclusive ``open`` it always was.
    """
    # Not at the top: fs_guard imports the sandbox package. Do not hoist.
    from automated_security_helper.utils.sandbox.fs_guard import open_for_write

    path = Path(path)
    staging = _staging_path(path)
    try:
        with open_for_write(staging, encoding=encoding, exclusive=True) as handle:
            yield cast(TextIO, handle)
        _replace(staging, path)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise


def write_bytes_atomically(
    path: Path, data: bytes, *, root: Optional[Path] = None
) -> None:
    """Write ``data`` to ``path`` as :func:`write_text_atomically` writes text.

    The bytes reach the file as given: nothing is encoded and no newline is
    translated, so a caller that records a digest of the file can take it of
    ``data`` rather than read the file back, which another writer may have replaced
    by then.

    Guarded as :func:`write_text_atomically` is, through
    ``fs_guard.open_for_atomic_write`` in binary: below a registered output
    directory, or below ``root``, a link at ``path`` or on the way to it is refused
    with ``OutputLinkRefused`` before the staging file is created, and the rename is
    made relative to the directory's descriptor rather than by name. Staging the
    write through ``open_for_write`` alone guarded only the staging file's own
    name, so outside a registered root a link at ``path`` was replaced by the
    rename, never refused.
    """
    # Not at the top: fs_guard imports the sandbox package. Do not hoist.
    from automated_security_helper.utils.sandbox.fs_guard import open_for_atomic_write

    with open_for_atomic_write(Path(path), binary=True, root=root) as handle:
        handle.write(data)


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
    """Rename ``staging`` over ``target`` by name; fs_guard's rename without a dir_fd.

    On Windows a ``PermissionError`` from a reader holding ``target`` open is
    retried for the bounded time above.
    """
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            os.replace(staging, target)
            return
        except PermissionError:
            if sys.platform != "win32" or attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(_REPLACE_BACKOFF_SECONDS)
