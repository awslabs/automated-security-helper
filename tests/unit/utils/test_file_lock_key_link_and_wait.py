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

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import os
import sys

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
