# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``exclusive_lock`` opens its lock file for writing, and read-only only when it must.

On a network mount (NFS since Linux 2.6.12, CIFS) ``flock`` is emulated with
byte-range locks, and an exclusive byte-range lock needs a descriptor open for
writing: a lock file opened read-only made ``flock(LOCK_EX)`` raise ``EBADF`` on
such a mount, so every tool database refresh on a network home failed. The file
is opened read-write first. It is opened read-only only when that open is
refused: a lock file another account created in a shared cache (mode 0644) is
readable where it is not writable, and on a local filesystem ``flock`` takes an
exclusive lock on a read-only descriptor, so the second account's update is
serialized rather than failing with ``PermissionError``.
"""

from __future__ import annotations

import errno
import os
import stat
import sys

import pytest

from automated_security_helper.utils import file_lock

pytestmark = pytest.mark.unit


def _recording_open(monkeypatch, opened):
    real_open = os.open

    def recording(path, flags, *args, **kwargs):
        opened.append((os.fspath(path), flags))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(file_lock.os, "open", recording)


def _opens_of(opened, lock_file):
    return [flags for path, flags in opened if path == os.fspath(lock_file)]


def test_a_lock_file_this_account_can_write_is_opened_for_writing_once(
    tmp_path, monkeypatch
):
    opened = []
    _recording_open(monkeypatch, opened)
    lock_file = tmp_path / "cache" / ".lock"

    with file_lock.exclusive_lock(lock_file):
        pass

    (flags,) = _opens_of(opened, lock_file)
    assert flags & os.O_CREAT
    assert flags & os.O_ACCMODE == os.O_RDWR
    assert lock_file.is_file()


@pytest.mark.skipif(file_lock.fcntl is None, reason="no flock on this platform")
def test_the_lock_is_taken_on_a_descriptor_open_for_writing(tmp_path, monkeypatch):
    """A network mount answers an exclusive lock on a read-only descriptor with
    EBADF; the stand-in does the same, so the lock succeeds only when the
    descriptor is writable."""
    real_flock = file_lock.fcntl.flock

    def network_mount_flock(fd, operation):
        if operation & file_lock.fcntl.LOCK_EX:
            mode = file_lock.fcntl.fcntl(fd, file_lock.fcntl.F_GETFL) & os.O_ACCMODE
            if mode == os.O_RDONLY:
                raise OSError(errno.EBADF, "Bad file descriptor")
        return real_flock(fd, operation)

    monkeypatch.setattr(file_lock.fcntl, "flock", network_mount_flock)

    entered = False
    with file_lock.exclusive_lock(tmp_path / "cache" / ".lock"):
        entered = True

    assert entered


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="a read-only file is writable to the superuser and to Windows' owner",
)
def test_a_lock_file_this_account_cannot_write_is_opened_read_only_and_locked(
    tmp_path, monkeypatch
):
    lock_file = tmp_path / "shared" / ".lock"
    lock_file.parent.mkdir()
    lock_file.touch()
    lock_file.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    opened = []
    _recording_open(monkeypatch, opened)

    entered = False
    with file_lock.exclusive_lock(lock_file):
        entered = True

    assert entered
    writing, reading = _opens_of(opened, lock_file)
    assert writing & os.O_ACCMODE == os.O_RDWR
    assert reading & os.O_ACCMODE == os.O_RDONLY


def test_control_a_refusal_other_than_permission_propagates(tmp_path, monkeypatch):
    real_open = os.open

    def refusing(path, flags, *args, **kwargs):
        if os.fspath(path).endswith(".lock"):
            raise OSError(errno.EROFS, "Read-only file system")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(file_lock.os, "open", refusing)

    with pytest.raises(OSError) as raised:
        with file_lock.exclusive_lock(tmp_path / "cache" / ".lock"):
            pass

    assert raised.value.errno == errno.EROFS
