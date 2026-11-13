# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The presence registry's blocking lock waits on Windows as it does on POSIX.

``msvcrt.locking`` with ``LK_LOCK`` tries once a second for ten seconds and
then raises, so a stdio server that waited behind a sibling's exit for longer
than that read the refusal as "no registry", ran uncounted, and had the shared
default workspace removed under it by the next server to exit. The lock is now
asked for again until it is granted. The Windows module is a stand-in here, so
these run on every platform.
"""

from __future__ import annotations

import errno
import sys
import types
from types import SimpleNamespace
from typing import List

import pytest

from automated_security_helper.cli.mcp import sessions

pytestmark = pytest.mark.unit


def _windows_with(locking, monkeypatch) -> None:
    fake = types.ModuleType("msvcrt")
    fake.LK_LOCK = 1
    fake.LK_NBLCK = 2
    fake.locking = locking
    monkeypatch.setitem(sys.modules, "msvcrt", fake)
    monkeypatch.setattr(sys, "platform", "win32")


def _handle() -> SimpleNamespace:
    return SimpleNamespace(seek=lambda offset: None, fileno=lambda: 7)


def test_the_lock_is_asked_for_again_after_the_calls_own_timeout(monkeypatch):
    attempts: List[int] = []

    def locking(fd: int, mode: int, nbytes: int) -> None:
        attempts.append(mode)
        if len(attempts) < 3:
            raise OSError(errno.EDEADLK, "Resource deadlock avoided")

    _windows_with(locking, monkeypatch)

    sessions._lock_blocking(_handle())

    assert attempts == [1, 1, 1], "the lock was not asked for again"


def test_a_refusal_for_access_is_asked_again_too(monkeypatch):
    attempts: List[int] = []

    def locking(fd: int, mode: int, nbytes: int) -> None:
        attempts.append(mode)
        if len(attempts) < 2:
            raise OSError(errno.EACCES, "Permission denied")

    _windows_with(locking, monkeypatch)

    sessions._lock_blocking(_handle())

    assert attempts == [1, 1]


def test_an_error_that_is_not_the_locks_refusal_is_raised(monkeypatch):
    calls: list = []

    def locking(fd: int, mode: int, nbytes: int) -> None:
        calls.append(mode)
        if len(calls) > 1:
            # A lock that retried EBADF would spin here forever with no sleep;
            # the second call fails the test instead of hanging the suite.
            raise AssertionError("EBADF was retried")
        raise OSError(errno.EBADF, "Bad file descriptor")

    _windows_with(locking, monkeypatch)

    with pytest.raises(OSError) as raised:
        sessions._lock_blocking(_handle())

    assert raised.value.errno == errno.EBADF
