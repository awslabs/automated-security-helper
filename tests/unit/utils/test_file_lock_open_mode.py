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
serialized rather than failing with ``PermissionError``. The read-only open does not
ask to create the file: a kernel can refuse the create alone (see
``_refuse_every_create``).
"""

from __future__ import annotations

import errno
import os
import stat
import sys

import pytest

from automated_security_helper.utils import file_lock

pytestmark = pytest.mark.unit

# The bits of an open's flags that say how it reads and writes. ``os.O_ACCMODE`` is
# not defined on Windows, where the three access modes are 0, 1 and 2 and so
# occupy the two low bits all the same.
_ACCESS_MODE = getattr(os, "O_ACCMODE", os.O_RDONLY | os.O_WRONLY | os.O_RDWR)


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
    assert flags & _ACCESS_MODE == os.O_RDWR
    assert lock_file.is_file()


@pytest.mark.skipif(file_lock.fcntl is None, reason="no flock on this platform")
def test_the_lock_is_taken_on_a_descriptor_open_for_writing(tmp_path, monkeypatch):
    """A network mount answers an exclusive lock on a read-only descriptor with
    EBADF; the stand-in does the same, so the lock succeeds only when the
    descriptor is writable."""
    real_flock = file_lock.fcntl.flock

    def network_mount_flock(fd, operation):
        if operation & file_lock.fcntl.LOCK_EX:
            mode = file_lock.fcntl.fcntl(fd, file_lock.fcntl.F_GETFL) & _ACCESS_MODE
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
    assert writing & _ACCESS_MODE == os.O_RDWR
    assert reading & _ACCESS_MODE == os.O_RDONLY


def _refuse_every_create(monkeypatch, lock_file, opened):
    """Stand in for a kernel that refuses an open that asks to create ``lock_file``.

    Linux with ``fs.protected_regular`` set refuses an ``O_CREAT`` open of another
    account's regular file in a sticky, world-writable directory, whatever the
    access mode, and the test cannot make a file this user does not own, so the
    refusal is simulated: an open of ``lock_file`` with ``O_CREAT`` raises
    ``PermissionError``, and one without it goes through. Every open of the file is
    recorded in ``opened`` as its flags."""
    real_open = os.open

    def protected(path, flags, *args, **kwargs):
        if os.fspath(path) == os.fspath(lock_file):
            opened.append(flags)
            if flags & os.O_CREAT:
                raise PermissionError(
                    errno.EACCES, "Permission denied", os.fspath(path)
                )
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(file_lock.os, "open", protected)


def test_the_read_only_fallback_does_not_ask_to_create_the_lock_file(
    tmp_path, monkeypatch
):
    """When the read-write open is refused for the create itself, the fallback has to
    leave the create out, or the second account's open is refused the same way and
    the file cannot be a lock for it. The lock file exists here, so the read-only
    open without ``O_CREAT`` succeeds and the lock is taken."""
    lock_file = tmp_path / "shared" / ".lock"
    lock_file.parent.mkdir()
    lock_file.touch()
    opened = []
    _refuse_every_create(monkeypatch, lock_file, opened)

    entered = False
    with file_lock.exclusive_lock(lock_file):
        entered = True

    assert entered
    writing, reading = opened
    assert writing & os.O_CREAT
    assert writing & _ACCESS_MODE == os.O_RDWR
    assert reading & _ACCESS_MODE == os.O_RDONLY
    assert not reading & os.O_CREAT


def test_control_a_refused_create_of_a_missing_lock_file_raises_that_refusal(
    tmp_path, monkeypatch
):
    """Nothing exists to open read-only, so the error is the create's own
    ``PermissionError`` and no lock file appears, not the ``FileNotFoundError`` of
    the read-only open that was tried after it."""
    lock_file = tmp_path / "shared" / ".lock"
    opened = []
    _refuse_every_create(monkeypatch, lock_file, opened)

    with pytest.raises(PermissionError) as raised:
        with file_lock.exclusive_lock(lock_file):
            pass

    assert raised.value.errno == errno.EACCES
    assert not lock_file.exists()
    assert [flags & _ACCESS_MODE for flags in opened] == [os.O_RDWR, os.O_RDONLY]


def _refusing_writes_with(monkeypatch, code, opened):
    """Opens of the lock file for writing fail with *code*; every open is recorded.
    Opening it read-only is not refused, so a fallback to it would succeed."""
    real_open = os.open

    def refusing(path, flags, *args, **kwargs):
        if os.fspath(path).endswith(".lock"):
            opened.append(flags & _ACCESS_MODE)
            if flags & _ACCESS_MODE != os.O_RDONLY:
                raise OSError(code, os.strerror(code), os.fspath(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(file_lock.os, "open", refusing)


@pytest.mark.parametrize("code", [errno.EIO, errno.ENAMETOOLONG])
def test_control_a_refusal_other_than_permission_or_a_read_only_file_system_propagates(
    tmp_path, monkeypatch, code
):
    opened = []
    _refusing_writes_with(monkeypatch, code, opened)

    with pytest.raises(OSError) as raised:
        with file_lock.exclusive_lock(tmp_path / "cache" / ".lock"):
            pass

    assert raised.value.errno == code
    # Exactly one open: the error came from the read-write open and was not
    # followed by a read-only try, which the refusal above would have let succeed.
    assert opened == [os.O_RDWR]


@pytest.mark.skipif(file_lock.fcntl is None, reason="no flock on this platform")
def test_a_read_only_file_system_falls_back_to_a_read_only_lock(tmp_path, monkeypatch):
    """A lock file that already exists on a read-only mount cannot be opened for
    writing (EROFS) but can be locked read-only, as a file this account may not
    write can; the lock is taken, not refused."""
    lock_file = tmp_path / "cache" / ".lock"
    lock_file.parent.mkdir()
    lock_file.touch()
    opened = []
    _refusing_writes_with(monkeypatch, errno.EROFS, opened)

    entered = False
    with file_lock.exclusive_lock(lock_file):
        entered = True

    assert entered
    assert opened == [os.O_RDWR, os.O_RDONLY]


def test_a_lock_file_that_cannot_be_made_on_a_read_only_file_system_is_refused(
    tmp_path, monkeypatch
):
    """A read-only mount refuses to make the name, and there is nothing to open
    read-only at a name that does not exist; the read-write open's EROFS is the
    caller's, not the read-only open's FileNotFoundError."""
    real_open = os.open

    def read_only_mount(path, flags, *args, **kwargs):
        writes = flags & (os.O_CREAT | _ACCESS_MODE) != os.O_RDONLY
        if os.fspath(path).endswith(".lock") and writes:
            raise OSError(errno.EROFS, "Read-only file system", os.fspath(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(file_lock.os, "open", read_only_mount)

    with pytest.raises(OSError) as raised:
        with file_lock.exclusive_lock(tmp_path / "cache" / ".lock"):
            pass

    assert raised.value.errno == errno.EROFS
