# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A lock denied by permission is not waited out for half an hour.

``EACCES`` is how CIFS reports a conflicting byte-range lock, so the wait for the
OS lock treats it as "held" and asks again. It is also what a Linux security
module (AppArmor, SELinux) answers when it denies the ``lock`` permission, and
that answer never changes. Waiting the whole of ``LOCK_TIMEOUT_SECONDS`` for it
and then saying another process holds the lock hid the cause for the length of
the wait. A run of ``EACCES`` answers alone is now bounded and the error names
the permission error; ``EAGAIN`` and ``EWOULDBLOCK`` are real "held" answers and
keep the whole wait.

The tests drive ``_flock_within`` with a stand-in for ``fcntl.flock`` and a fake
clock, so no wait is real and no lock is taken by another process.
"""

from __future__ import annotations

import errno
import types

import pytest

from automated_security_helper.utils import file_lock

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(file_lock.fcntl is None, reason="no OS lock on this platform"),
]

_POLL = 1.0


class _FakeClock:
    """A clock that only moves when ``sleep`` is called."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _install(monkeypatch, answers):
    """``flock`` answers each exclusive ask with the next of *answers* (an errno,
    or None for success); the last answer repeats. Returns the clock and the
    list of asks."""
    clock = _FakeClock()
    asked: list[int] = []

    def flock(fd, operation):
        index = min(len(asked), len(answers) - 1)
        asked.append(index)
        answer = answers[index]
        if answer is not None:
            raise OSError(answer, "refused by the stand-in")

    monkeypatch.setattr(
        file_lock,
        "time",
        types.SimpleNamespace(monotonic=clock.monotonic, sleep=clock.sleep),
    )
    monkeypatch.setattr(file_lock.fcntl, "flock", flock)
    monkeypatch.setattr(file_lock, "_LOCK_POLL_SECONDS", _POLL)
    return clock, asked


def test_a_run_of_permission_errors_ends_early_naming_the_permission_error(
    tmp_path, monkeypatch
):
    lock_file = tmp_path / "cache" / ".lock"
    clock, _ = _install(monkeypatch, [errno.EACCES])
    begun = clock.now

    with pytest.raises(TimeoutError) as refused:
        file_lock._flock_within(0, 3600.0, lock_file)

    waited = clock.now - begun
    assert waited <= file_lock._PERMISSION_DENIED_WAIT_SECONDS + _POLL
    assert waited < 3600.0
    text = str(refused.value)
    assert lock_file.as_posix() in text
    assert "EACCES" in text
    assert "security policy" in text


def test_a_lock_that_stays_held_keeps_the_whole_wait_and_names_the_last_answer(
    tmp_path, monkeypatch
):
    lock_file = tmp_path / "cache" / ".lock"
    clock, _ = _install(monkeypatch, [errno.EAGAIN])
    begun = clock.now

    with pytest.raises(TimeoutError) as refused:
        file_lock._flock_within(0, 3600.0, lock_file)

    assert clock.now - begun >= 3600.0
    assert lock_file.as_posix() in str(refused.value)
    assert "EAGAIN" in str(refused.value)


def test_a_permission_error_run_that_ends_inside_the_bound_is_waited_out(
    tmp_path, monkeypatch
):
    lock_file = tmp_path / "cache" / ".lock"
    refusals = int(file_lock._PERMISSION_DENIED_WAIT_SECONDS / _POLL) - 5
    clock, asked = _install(monkeypatch, [errno.EACCES] * refusals + [None])
    begun = clock.now

    file_lock._flock_within(0, 3600.0, lock_file)

    assert len(asked) == refusals + 1
    assert clock.now - begun < file_lock._PERMISSION_DENIED_WAIT_SECONDS


def test_an_answer_that_says_held_ends_the_run_of_permission_errors(
    tmp_path, monkeypatch
):
    """Each run of permission errors stays inside the bound, and a held answer
    between them proves a holder exists, so the whole wait is kept."""
    lock_file = tmp_path / "cache" / ".lock"
    run = int(file_lock._PERMISSION_DENIED_WAIT_SECONDS / _POLL) - 5
    answers = ([errno.EACCES] * run + [errno.EAGAIN]) * 3 + [None]
    clock, asked = _install(monkeypatch, answers)
    begun = clock.now

    file_lock._flock_within(0, 3600.0, lock_file)

    assert len(asked) == len(answers)
    assert clock.now - begun > file_lock._PERMISSION_DENIED_WAIT_SECONDS
