# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An exclusive lock on a file, held across threads and processes.

Why this exists
---------------
Two scanners can share a tool's cache in one scan (trivy and trivy-repo share trivy's
database), and two ASH processes can share it across scans. An update written by one
while the other reads it fails in ways that look unrelated to the cause; see
``TrivyScannerBase._shared_update_flags``. ``exclusive_lock`` serializes that update.

How it locks
------------
A ``threading.Lock`` per lock path covers the threads of one process, which is where
the scanners of one scan run. ``fcntl.flock`` on the lock file also covers other
processes on POSIX. On Windows only the thread lock is taken: ``msvcrt.locking``
gives up after about ten seconds, shorter than a database download, and failing a
scan for that would be worse than the cross-process race it guards against. The lock
file is created if missing and never removed: removing it while another process
waits on it would let a third process lock a new file of the same name.

Failure modes
-------------
* A filesystem that does not support the OS lock (some network mounts) raises
  ``OSError`` from the OS call. That propagates, rather than running unlocked.
* The lock is advisory: only code that takes it is serialized.
"""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, Union

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

_registry_lock = threading.Lock()
_thread_locks: Dict[str, threading.Lock] = {}


def _thread_lock_for(path: Path) -> threading.Lock:
    key = os.path.abspath(path)
    with _registry_lock:
        return _thread_locks.setdefault(key, threading.Lock())


@contextmanager
def exclusive_lock(path: Union[str, Path]) -> Iterator[None]:
    """Hold an exclusive lock on ``path`` (created if missing) for the block."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _thread_lock_for(path):
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
