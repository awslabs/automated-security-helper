# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A second Ctrl-C during an interrupt stop stops the registered child itself.

``stop_after_interrupt`` registers the child it waits out with
``interrupt_stop_in_progress(process)``. The SIGINT dispatch that decides
"chain, not die-now" then stops that child in the handler, one syscall, so the
documented "a second Ctrl-C during the wait kills it at once" does not depend
on which frame the chained interrupt lands in.
"""

from __future__ import annotations

import os
import signal
import subprocess  # nosec B404 - spawns the running interpreter, fixed argv
import sys
from typing import Iterator, List

import pytest

from automated_security_helper.core import cancellation

pytestmark = pytest.mark.unit

_SLEEPER = "import time; time.sleep(60)"


@pytest.fixture
def sleeper() -> Iterator["subprocess.Popen[bytes]"]:
    child = subprocess.Popen(  # nosec B603 - fixed argv
        [sys.executable, "-c", _SLEEPER]
    )
    try:
        yield child
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=30)


@pytest.fixture
def second_press(monkeypatch) -> List[object]:
    """The dispatch's state for a second Ctrl-C, with the chain recorded.

    The previous handler is a stub, so the chained interrupt does not raise into
    the test; every module global touched is restored by ``monkeypatch``.
    """
    chained: List[object] = []
    monkeypatch.setattr(cancellation, "_SIGINT_SEEN", True)
    monkeypatch.setattr(cancellation, "_SIGTERM_SEEN", False)
    monkeypatch.setattr(
        cancellation, "_PREVIOUS_SIGINT", lambda signum, frame: chained.append(signum)
    )
    monkeypatch.setattr(cancellation, "_INTERRUPT_STOP_WAITS", 0)
    monkeypatch.setattr(cancellation, "_INTERRUPT_STOP_PROCESSES", ())
    return chained


def test_the_second_press_kills_the_registered_child(
    sleeper: "subprocess.Popen[bytes]", second_press: List[object]
) -> None:
    with cancellation.interrupt_stop_in_progress(sleeper):
        assert cancellation._INTERRUPT_STOP_PROCESSES == (sleeper,)
        cancellation._handle_sigint(signal.SIGINT, None)
        assert sleeper.wait(timeout=30) != 0
    assert second_press == [signal.SIGINT]
    assert cancellation._INTERRUPT_STOP_PROCESSES == ()


class _OsWithoutWaitid:
    """``os`` as macOS has it: everything but ``waitid``."""

    def __getattr__(self, name: str) -> object:
        if name == "waitid":
            raise AttributeError(name)
        return getattr(os, name)


@pytest.mark.skipif(os.name == "nt", reason="the pid signal is POSIX's path")
def test_the_second_press_kills_the_child_where_os_has_no_waitid(
    sleeper: "subprocess.Popen[bytes]", second_press: List[object], monkeypatch
) -> None:
    """macOS has no os.waitid; the handler must still stop the child, not raise."""
    monkeypatch.setattr(cancellation, "os", _OsWithoutWaitid())

    with cancellation.interrupt_stop_in_progress(sleeper):
        cancellation._handle_sigint(signal.SIGINT, None)
        assert sleeper.wait(timeout=30) != 0
    assert second_press == [signal.SIGINT]


@pytest.mark.skipif(
    not hasattr(os, "waitid"), reason="the reap-free check needs os.waitid"
)
def test_the_second_press_does_not_reap_a_child_that_has_exited(
    second_press: List[object],
) -> None:
    """The handler's kill is reap-free: a child that already exited stays reapable.

    Popen.kill polls first, and a poll reaps an exited child while its die-now
    record may still be recorded; the pid could then be reused and killed by a
    later sweep. The handler checks with waitid (WNOWAIT) and leaves the reap to
    the arm that discards the record first.
    """
    child = subprocess.Popen([sys.executable, "-c", "pass"])  # nosec B603
    try:
        # Observed to have exited, without reaping it.
        os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
        with cancellation.interrupt_stop_in_progress(child):
            cancellation._handle_sigint(signal.SIGINT, None)
        assert child.returncode is None, "the handler reaped the exited child"
        assert second_press == [signal.SIGINT]
    finally:
        assert child.wait(timeout=30) == 0


class _OsWherePidIsReused:
    """``os`` where waitid finds a live child under the pid and kill is recorded.

    That is what a reused pid looks like to the handler: the child it was given
    has been reaped, and another child of this process now has the same pid.
    """

    def __init__(self) -> None:
        self.killed: List[tuple] = []

    def waitid(self, *args: object) -> None:
        return None

    def kill(self, pid: int, signum: int) -> None:
        self.killed.append((pid, signum))

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)


@pytest.mark.skipif(os.name == "nt", reason="the pid signal is POSIX's path")
def test_the_second_press_signals_no_pid_of_a_child_already_reaped(
    second_press: List[object], monkeypatch
) -> None:
    """A registered child this process has reaped is skipped before any check.

    The stop's own waits reap the child while it is still registered; a Ctrl-C
    between that reap and the registration ending must not signal a pid that
    another child may hold by now (waitid on the bare pid cannot tell).
    """
    child = subprocess.Popen([sys.executable, "-c", "pass"])  # nosec B603
    assert child.wait(timeout=30) == 0
    spy = _OsWherePidIsReused()
    monkeypatch.setattr(cancellation, "os", spy)

    with cancellation.interrupt_stop_in_progress(child):
        cancellation._handle_sigint(signal.SIGINT, None)

    assert spy.killed == []
    assert second_press == [signal.SIGINT]


def test_a_wait_with_no_child_registered_only_chains(
    sleeper: "subprocess.Popen[bytes]", second_press: List[object]
) -> None:
    with cancellation.interrupt_stop_in_progress():
        assert cancellation._INTERRUPT_STOP_PROCESSES == ()
        cancellation._handle_sigint(signal.SIGINT, None)
    assert second_press == [signal.SIGINT]
    assert sleeper.poll() is None
