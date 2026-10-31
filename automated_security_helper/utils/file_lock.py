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
lock a new file of the same name. It is opened for writing when this account may
write it, and read-only, without asking to create it, when it may not
(:func:`_open_lock_file`): on a network
mount (NFS, CIFS) ``flock`` is emulated with byte-range locks, and an exclusive
one needs a descriptor open for writing, so a read-only open made the lock raise
``EBADF`` there and every tool database refresh on a network home failed; a lock
file another user created (a shared tool cache, mode 0644) is readable where it is
not writable, and on a local filesystem ``flock`` takes an exclusive lock on a
read-only descriptor, so that user's update is serialized rather than failing with
``PermissionError``. It is opened without following a link at its name, where the
platform can refuse one (``O_NOFOLLOW``): a lock file lives in a shared cache or a
shared temporary directory, and a link planted at its name would make the lock be
taken on whatever the link points at.

The wait for the OS lock is bounded. A holder that is stopped or hung in another
process held every later scan for good, outside any scan timeout; after
``LOCK_TIMEOUT_SECONDS`` the wait raises ``TimeoutError`` naming the lock file, so
the scan fails with a cause rather than hanging. The bound is generous, because a
holder may be downloading a tool's database.

Failure modes
-------------
* A filesystem that does not support the OS lock (some network mounts) raises
  ``OSError`` from the OS call. That propagates, rather than running unlocked. So
  does ``EBADF`` from a network mount for a lock file this account can only read:
  there the emulated exclusive lock needs write access the account does not have.
* A link at the lock file's name raises ``OSError`` where ``O_NOFOLLOW`` exists.
* Anything but a regular file at the lock file's name (a FIFO, a device, a socket)
  raises ``OSError`` naming the lock file. The file is opened without blocking,
  because opening a FIFO blocks until its other end is opened: a FIFO planted at
  the name held the scan before any lock was asked for, outside every timeout.
* The lock is advisory: only code that takes it is serialized.
"""

from __future__ import annotations

import errno
import os
import stat
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
#: forever. It is the backstop for a holder that is gone: a healthy holder that
#: runs several commands under one lock, each with its own timeout, can hold it
#: longer than this, and such a caller passes its own bound as ``timeout=``
#: (``exclusive_lock``).
LOCK_TIMEOUT_SECONDS = 1800.0

#: How often a waiting ``exclusive_lock`` asks for the OS lock again.
_LOCK_POLL_SECONDS = 0.1

#: The errors a non-blocking ``flock`` answers when another holder has the lock:
#: ``EAGAIN`` and ``EWOULDBLOCK`` (one value on Linux) locally, and ``EACCES`` on
#: CIFS, where the emulated byte-range lock reports a conflict as a permission
#: error. ``EPERM`` and the rest are real refusals and are not waited out.
_LOCK_HELD_ERRNOS = frozenset({errno.EAGAIN, errno.EWOULDBLOCK, errno.EACCES})

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


def _open_lock_file(path: Path) -> int:
    """A descriptor on *path*, created if missing: open for writing where this
    account may write it, for reading alone where it may not.

    Read-write first. On a network mount (NFS since Linux 2.6.12, CIFS) ``flock``
    is emulated with byte-range locks, and an exclusive byte-range lock needs a
    descriptor open for writing: a read-only descriptor made ``flock(LOCK_EX)``
    raise ``EBADF`` there. Read-only only when the read-write open is refused for
    want of permission (``EACCES``, ``EPERM``) or because the file system is
    read-only (``EROFS``): a lock file another account created in a shared cache
    (mode 0644) is readable where it is not writable, a lock file on a read-only
    mount is too, and on a local filesystem ``flock`` takes an exclusive lock on a
    read-only descriptor, so the update is serialized rather than failing. A lock
    file that does not exist on a read-only mount cannot be made, and the
    ``EROFS`` of the read-write open propagates. Any other refusal (``EIO``,
    ``ENAMETOOLONG``) propagates at once. A link at the name is not followed
    where the platform can refuse one (``O_NOFOLLOW``).

    The read-only open does not ask to create the file. Only the read-write open
    does, and a refusal of it can come from the create itself: on Linux with
    ``fs.protected_regular`` set, an ``O_CREAT`` open of another account's
    regular file in a sticky, world-writable directory (the temporary directory)
    is refused whatever the access mode, though a plain read-only open of the
    same file succeeds. Repeating the create in the fallback made such a file
    unusable as a lock for the second account. When the name does not exist
    there is nothing to open read-only, and the read-write open's own refusal is
    the error raised.

    Opened without blocking (``O_NONBLOCK``, where it exists) and refused unless
    what was opened is a regular file. Opening a FIFO blocks until its other end
    is opened, so a FIFO planted at the name (the read-only fallback reaches it
    whenever this account may not open it for writing) held the scan before the
    lock was asked for and outside its timeout; opened without blocking it is
    opened at once, and ``fstat`` then says what it is. A device or a socket at
    the name is refused the same way. The flag is left on the descriptor, which
    is only ever locked and closed, never read or written.
    """
    common = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | common, 0o644)
    except OSError as refused:
        if not (isinstance(refused, PermissionError) or refused.errno == errno.EROFS):
            raise
        try:
            fd = os.open(path, os.O_RDONLY | common)
        except FileNotFoundError:
            raise refused from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(
                errno.EINVAL,
                f"The lock file {path.as_posix()} is not a regular file. Remove "
                "what is at that name and run ASH again.",
            )
    except BaseException:
        os.close(fd)
        raise
    return fd


def _flock_within(fd: int, timeout: Optional[float], path: Path) -> None:
    """Take the exclusive OS lock on *fd*, waiting at most *timeout* seconds.

    None waits without bound. The lock is asked for without blocking and the ask
    repeated, so a holder that never releases ends in ``TimeoutError`` rather than
    a hang. "Held by someone else" is ``EWOULDBLOCK`` (``EAGAIN``) on a local
    filesystem and ``EACCES`` on CIFS, whose emulated byte-range lock answers a
    conflict that way; both are waited out. Any other refusal propagates as it
    is.
    """
    if timeout is None:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as refused:
            if refused.errno not in _LOCK_HELD_ERRNOS:
                raise
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
    without bound. The default, :data:`LOCK_TIMEOUT_SECONDS`, is sized for a holder
    that is gone, not for a healthy one: a caller that holds the lock across
    several commands, each bounded by its own timeout, passes the sum of those
    bounds (plus a margin) here, or a waiting process gives up on a holder that is
    still working. The wait for another thread of this process is not bounded: it
    is the same scan's other scanner, which the scan's own timeout covers.

    Raises:
        TimeoutError: the wait for another process's lock ran out; the message
            names the lock file.
        OSError: the lock file could not be opened, or is not a regular file
            (``errno.EINVAL``; see ``_open_lock_file``). A caller with its own
            error contract wraps both in its own type.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _thread_lock_for(path):
        fd = _open_lock_file(path)
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
