# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A lock another process holds is waited for, whichever error says so.

A non-blocking ``flock`` answers "held by someone else" with ``EWOULDBLOCK``
(``EAGAIN``) on a local filesystem. On CIFS the emulated byte-range lock answers a
conflicting lock with ``EACCES``, which Python raises as ``PermissionError``. The
old blocking ``flock`` waited on both; a wait that treated only ``EWOULDBLOCK`` as
contention made a second concurrent refresh on a CIFS home fail at once with a
permission error, though the module names CIFS as supported. Any other refusal is
a real failure and propagates.
"""

from __future__ import annotations

import errno

import pytest

from automated_security_helper.utils import file_lock

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(file_lock.fcntl is None, reason="no OS lock on this platform"),
]


def _refusing_flock(monkeypatch, error_number, *, times):
    """``flock`` refuses ``times`` exclusive asks with *error_number* (all of them
    when ``times`` is None), then behaves as it does. Returns the count of asks."""
    real_flock = file_lock.fcntl.flock
    asked = {"exclusive": 0}

    def flock(fd, operation):
        if operation & file_lock.fcntl.LOCK_EX:
            asked["exclusive"] += 1
            if times is None or asked["exclusive"] <= times:
                raise OSError(error_number, "refused by the stand-in")
        return real_flock(fd, operation)

    monkeypatch.setattr(file_lock.fcntl, "flock", flock)
    monkeypatch.setattr(file_lock, "_LOCK_POLL_SECONDS", 0.0)
    return asked


@pytest.mark.parametrize(
    "held_as",
    [
        pytest.param(errno.EACCES, id="cifs-eacces"),
        pytest.param(errno.EAGAIN, id="local-eagain"),
        pytest.param(errno.EWOULDBLOCK, id="local-ewouldblock"),
    ],
)
def test_a_lock_reported_as_held_is_waited_for_until_it_is_free(
    tmp_path, monkeypatch, held_as
):
    asked = _refusing_flock(monkeypatch, held_as, times=3)

    entered = False
    with file_lock.exclusive_lock(tmp_path / "cache" / ".lock", timeout=30):
        entered = True

    assert entered
    assert asked["exclusive"] == 4


@pytest.mark.parametrize(
    "held_as",
    [
        pytest.param(errno.EACCES, id="cifs-eacces"),
        pytest.param(errno.EAGAIN, id="local-eagain"),
    ],
)
def test_a_lock_that_stays_held_ends_in_a_timeout_naming_the_lock_file(
    tmp_path, monkeypatch, held_as
):
    lock_file = tmp_path / "cache" / ".lock"
    _refusing_flock(monkeypatch, held_as, times=None)

    with pytest.raises(TimeoutError) as refused:
        with file_lock.exclusive_lock(lock_file, timeout=0.2):
            pass

    assert lock_file.as_posix() in str(refused.value)


def test_control_a_refusal_that_is_not_contention_propagates_at_once(
    tmp_path, monkeypatch
):
    asked = _refusing_flock(monkeypatch, errno.EPERM, times=None)

    with pytest.raises(OSError) as refused:
        with file_lock.exclusive_lock(tmp_path / "cache" / ".lock", timeout=30):
            pass

    assert refused.value.errno == errno.EPERM
    assert not isinstance(refused.value, TimeoutError)
    assert asked["exclusive"] == 1
