# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three readings of ``exclusive_lock``.

- The per-path thread lock is keyed by the lock file's real path, so two spellings
  of one lock file (through a link, say) share one lock. Keyed by the spelling as
  given, they had two, and on Windows, where no OS lock is taken, nothing then
  serialized them.
- The lock file is opened without following a link at its name, where the
  platform can refuse one, since the file lives in a shared cache or temporary
  directory where another user can plant a link.
- The wait for another process's OS lock is bounded, and ends in ``TimeoutError``
  naming the lock file, where it held the scan for good.
- Anything but a regular file at the lock file's name is refused at once: a FIFO
  there was opened blocking and held the scan before the lock was asked for, or,
  where the open did not block, was locked as if it were the lock file.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import os
import sys
import time

import pytest

from automated_security_helper.utils import file_lock

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@needs_symlinks
def test_two_spellings_of_one_lock_file_share_one_thread_lock(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)

    first = file_lock._thread_lock_for(tmp_path / "real" / ".lock")
    second = file_lock._thread_lock_for(tmp_path / "link" / ".lock")

    assert first is second


def test_control_two_lock_files_get_two_thread_locks(tmp_path):
    first = file_lock._thread_lock_for(tmp_path / "a" / ".lock")
    second = file_lock._thread_lock_for(tmp_path / "b" / ".lock")

    assert first is not second


@needs_symlinks
@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="no O_NOFOLLOW here")
def test_a_link_at_the_lock_files_name_is_not_followed(tmp_path):
    target = tmp_path / "elsewhere.lock"
    target.touch()
    link = tmp_path / "cache" / ".lock"
    link.parent.mkdir()
    link.symlink_to(target)

    with pytest.raises(OSError):
        with file_lock.exclusive_lock(link):
            pass


@pytest.mark.skipif(file_lock.fcntl is None, reason="no OS lock on this platform")
def test_a_lock_another_process_holds_is_waited_for_a_bounded_time(tmp_path):
    lock_file = tmp_path / "cache" / ".lock"
    lock_file.parent.mkdir()
    lock_file.touch()
    # Another open file description of the same file conflicts with this
    # process's own later flock, as another process's would.
    holder = os.open(lock_file, os.O_RDONLY)
    file_lock.fcntl.flock(holder, file_lock.fcntl.LOCK_EX)
    try:
        with pytest.raises(TimeoutError) as refused:
            with file_lock.exclusive_lock(lock_file, timeout=0.3):
                pass
    finally:
        file_lock.fcntl.flock(holder, file_lock.fcntl.LOCK_UN)
        os.close(holder)

    assert lock_file.as_posix() in str(refused.value)


def test_control_a_free_lock_is_taken_at_once(tmp_path):
    entered = False
    with file_lock.exclusive_lock(tmp_path / "cache" / ".lock", timeout=0.3):
        entered = True

    assert entered
    assert file_lock.LOCK_TIMEOUT_SECONDS > 60


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
def test_a_fifo_at_the_lock_files_name_is_refused_without_waiting(tmp_path):
    """The lock file's name holds a FIFO. Before, the open either blocked until the
    FIFO's other end was opened (the read-only fallback, for a FIFO this account may
    not write) or, on Linux for a read-write open, succeeded and locked the FIFO as
    if it were the lock file. Either way no error named the lock file."""
    lock_file = tmp_path / "cache" / ".lock"
    lock_file.parent.mkdir()
    os.mkfifo(lock_file)

    started = time.monotonic()
    with pytest.raises(OSError) as refused:
        with file_lock.exclusive_lock(lock_file, timeout=0.3):
            pass

    assert lock_file.as_posix() in str(refused.value)
    assert "regular file" in str(refused.value)
    assert time.monotonic() - started < 5


def test_control_an_existing_regular_lock_file_is_accepted(tmp_path):
    lock_file = tmp_path / "cache" / ".lock"
    lock_file.parent.mkdir()
    lock_file.write_text("", encoding="utf-8")

    entered = False
    with file_lock.exclusive_lock(lock_file, timeout=0.3):
        entered = True

    assert entered
