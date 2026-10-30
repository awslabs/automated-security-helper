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
the scanners of one scan run. The path is keyed by its real path, every link
resolved and the case folded where the platform folds it, so two spellings of one
lock file (a cache directory given through a link, or in another case on Windows)
share one thread lock; keyed by the spelling, they did not, and on Windows, where no
OS lock is taken, two threads then updated one database at once. ``fcntl.flock`` on
the lock file also covers other processes on POSIX. On Windows only the thread lock
is taken: ``msvcrt.locking`` gives up after about ten seconds, shorter than a
database download, and failing a scan for that would be worse than the
cross-process race it guards against. The lock file is created if missing and never
removed: removing it while another process waits on it would let a third process
lock a new file of the same name. It is opened read-only: ``flock`` needs no write
access, and a lock file another user created (a shared tool cache) is readable
where it is not writable, so the second user's update is serialized rather than
failing with ``PermissionError``. It is opened without following a link at its
name, where the platform can refuse one (``O_NOFOLLOW``): a lock file lives in a
shared cache or a shared temporary directory, and a link planted at its name would
make the lock be taken on whatever the link points at.

The wait for the OS lock is bounded. A holder that is stopped or hung in another
process held every later scan for good, outside any scan timeout; after
``LOCK_TIMEOUT_SECONDS`` the wait raises ``TimeoutError`` naming the lock file, so
the scan fails with a cause rather than hanging. The bound is generous, because a
holder may be downloading a tool's database.

Failure modes
-------------
* A filesystem that does not support the OS lock (some network mounts) raises
  ``OSError`` from the OS call. That propagates, rather than running unlocked.
* A link at the lock file's name raises ``OSError`` where ``O_NOFOLLOW`` exists.
* The lock is advisory: only code that takes it is serialized.
"""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, Optional, Union

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

#: How long ``exclusive_lock`` waits for another process's lock before it gives
#: up with ``TimeoutError``: longer than a tool's database download, shorter than
#: forever.
LOCK_TIMEOUT_SECONDS = 1800.0

#: How often a waiting ``exclusive_lock`` asks for the OS lock again.
_LOCK_POLL_SECONDS = 0.1

_registry_lock = threading.Lock()
_thread_locks: Dict[str, threading.Lock] = {}


def _thread_lock_key(path: Union[str, Path]) -> str:
    """The key one lock file has whatever spelling names it: its real path, case
    folded where the platform's paths are (``os.path.normcase``)."""
    return os.path.normcase(os.path.realpath(path))


def _thread_lock_for(path: Path) -> threading.Lock:
    key = _thread_lock_key(path)
    with _registry_lock:
        return _thread_locks.setdefault(key, threading.Lock())


def _flock_within(fd: int, timeout: Optional[float], path: Path) -> None:
    """Take the exclusive OS lock on *fd*, waiting at most *timeout* seconds.

    None waits without bound. The lock is asked for without blocking and the ask
    repeated, so a holder that never releases ends in ``TimeoutError`` rather than
    a hang. A refusal other than "held by someone else" (``EWOULDBLOCK``)
    propagates as it is.
    """
    if timeout is None:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Another process has held the lock {path.as_posix()} for "
                    f"{timeout:g} seconds. If that process is gone, remove the "
                    "lock file and run ASH again."
                ) from None
            time.sleep(_LOCK_POLL_SECONDS)


@contextmanager
def exclusive_lock(
    path: Union[str, Path], *, timeout: Optional[float] = LOCK_TIMEOUT_SECONDS
) -> Iterator[None]:
    """Hold an exclusive lock on ``path`` (created if missing) for the block.

    ``timeout`` bounds the wait for another process's lock, in seconds; None waits
    without bound. The wait for another thread of this process is not bounded: it
    is the same scan's other scanner, which the scan's own timeout covers.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _thread_lock_for(path):
        # Read-only: flock needs no write access, and a lock file another user
        # owns is readable (0o644) where opening it for writing is refused. Not
        # following a link at the name, where the platform can refuse one.
        flags = os.O_RDONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o644)
        try:
            if fcntl is not None:
                _flock_within(fd, timeout, path)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
