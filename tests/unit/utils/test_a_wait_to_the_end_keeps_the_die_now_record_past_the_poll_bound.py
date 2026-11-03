# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A wait that blocks until the child's end keeps its die-now record that long.

On a build without ``os.waitid`` the wait before a reap polls for the exit. For a
child that was just sent a kill the poll is bounded: one still alive after the
bound survived the kill, and a die-now sweep can do nothing more to it. The Nix
shell is waited on differently. It was never signaled and is healthy, and the
caller wants to block until its end, so a bound there drops the record while the
shell is alive and out of reach of a die-now sweep for the rest of the scan.

The children here are fakes: no process is started and no signal is sent.
"""

from __future__ import annotations

import os
import subprocess
import threading
from types import SimpleNamespace
from typing import List, Tuple

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.interactions import run_ash_nix
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

# Above the kernel's pid space (pid_max is at most 2**22).
_PID = 2**30 + 71

#: How many polls report the child alive: well past the shortened bound below.
_POLLS_ALIVE = 12


class _OsWithoutWaitid:
    """``os`` as a build without ``waitid`` has it (CPython on macOS, Windows)."""

    def __getattr__(self, attribute: str):
        if attribute == "waitid":
            raise AttributeError(attribute)
        return getattr(os, attribute)


class _FakeChild:
    """A child that reports alive for ``_POLLS_ALIVE`` polls and then exits."""

    def __init__(self) -> None:
        self.pid = _PID
        self.returncode = None
        self.polls = 0

    def poll(self):
        self.polls += 1
        if self.polls > _POLLS_ALIVE:
            self.returncode = 0
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0


@pytest.fixture
def no_waitid(monkeypatch):
    """No waitid, a short bound and short slices, and an empty die-now mirror."""
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())
    monkeypatch.setattr(subprocess_utils, "os", _OsWithoutWaitid())
    monkeypatch.setattr(subprocess_utils, "_REAP_POLL_BOUND_SECONDS", 0.1)
    monkeypatch.setattr(subprocess_utils, "INTERRUPT_WAIT_SLICE_SECONDS", 0.02)


class _Discards:
    """Each discard of the die-now record, with whether the child had ended."""

    def __init__(self, child: _FakeChild) -> None:
        self.child = child
        self.seen: List[Tuple[int, bool]] = []

    def __call__(self, pid: int) -> None:
        self.seen.append((pid, self.child.returncode is not None))
        self.real(pid)

    real = staticmethod(subprocess_utils.discard_tool_pid)


@pytest.fixture
def child(monkeypatch) -> _FakeChild:
    return _FakeChild()


@pytest.fixture
def at_discard(monkeypatch, child) -> _Discards:
    """The spy on the discard, and a die-now mirror of this test's own.

    The mirror is replaced here, not only in ``no_waitid``, because the waitid
    test cannot use that fixture: a discard the code under test failed to make
    would otherwise leave the fake pid in the session-wide mirror for every
    later test. The original is put back after the test."""
    spy = _Discards(child)
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())
    monkeypatch.setattr(subprocess_utils, "discard_tool_pid", spy)
    cancellation.record_tool_pid(child.pid)
    return spy


def _sleeping_fails_on_the_main_thread(monkeypatch, message: str) -> None:
    """``time.sleep`` replaced so the thread under test fails on a sleep and any
    other thread (a background thread of the session) sleeps as usual: the
    replacement is process-wide, and a failure delivered to a thread that is
    not the test's would be raised there, not in the test."""
    real_sleep = subprocess_utils.time.sleep

    def sleep(seconds):
        if threading.current_thread() is threading.main_thread():
            pytest.fail(message)
        real_sleep(seconds)

    monkeypatch.setattr(subprocess_utils.time, "sleep", sleep)


def test_a_wait_that_is_not_after_a_kill_keeps_the_record_until_the_child_ends(
    no_waitid, child, at_discard
):
    subprocess_utils.discard_tool_pid_before_reap(child, just_killed=False)  # type: ignore[arg-type]

    assert at_discard.seen == [(_PID, True)], (
        f"the record was dropped while the child was still alive: {at_discard.seen}"
    )
    assert child.polls > _POLLS_ALIVE


def test_a_wait_after_a_kill_still_gives_up_at_the_bound(no_waitid, child, at_discard):
    """The control: a child that survives a kill is dropped at the bound."""
    subprocess_utils.discard_tool_pid_before_reap(child)  # type: ignore[arg-type]

    assert at_discard.seen == [(_PID, False)], at_discard.seen
    assert child.polls <= _POLLS_ALIVE


@pytest.mark.skipif(not hasattr(os, "waitid"), reason="the blocking arm is waitid's")
def test_a_wait_to_the_end_with_waitid_blocks_instead_of_polling(
    monkeypatch, child, at_discard
):
    """With waitid the wait to the end is one blocking call, no WNOHANG and no
    slices, as its docstring says; the just-killed wait keeps its bounded
    slices (the control)."""
    seen: List[Tuple[int, int, int]] = []

    def waitid(idtype, pid, options):
        seen.append((idtype, pid, options))
        # The exit the wait saw; WNOWAIT leaves the reap to the caller.
        child.returncode = 0
        return SimpleNamespace(si_pid=pid)

    monkeypatch.setattr(subprocess_utils.os, "waitid", waitid)
    _sleeping_fails_on_the_main_thread(
        monkeypatch, "the wait to the end slept between polls"
    )

    subprocess_utils.discard_tool_pid_before_reap(child, just_killed=False)  # type: ignore[arg-type]

    assert seen == [(os.P_PID, _PID, os.WEXITED | os.WNOWAIT)], seen
    assert at_discard.seen == [(_PID, True)], at_discard.seen

    seen.clear()
    child.returncode = None
    subprocess_utils.discard_tool_pid_before_reap(child)  # type: ignore[arg-type]
    assert seen == [(os.P_PID, _PID, os.WEXITED | os.WNOHANG | os.WNOWAIT)], seen


def test_a_sleep_on_another_thread_is_not_the_main_threads_failure(monkeypatch):
    """The sleep guard fails the main thread only: a background thread that
    sleeps while it is installed gets the real sleep."""
    _sleeping_fails_on_the_main_thread(monkeypatch, "the main thread slept")
    ran: List[bool] = []

    def background() -> None:
        subprocess_utils.time.sleep(0)
        ran.append(True)

    worker = threading.Thread(target=background, daemon=True)
    worker.start()
    worker.join(timeout=5.0)

    assert ran == [True], "the background thread was failed or never ran"
    with pytest.raises(pytest.fail.Exception, match="the main thread slept"):
        subprocess_utils.time.sleep(0)


def test_the_nix_shell_without_a_cancel_event_keeps_its_record_until_it_ends(
    no_waitid, child, at_discard, monkeypatch
):
    fake_subprocess = SimpleNamespace(
        Popen=lambda *args, **kwargs: child,
        DEVNULL=subprocess.DEVNULL,
        CompletedProcess=subprocess.CompletedProcess,
    )
    monkeypatch.setattr(run_ash_nix, "subprocess", fake_subprocess)

    result = run_ash_nix._enter_shell(["nix", "develop"], env={})

    assert result.returncode == 0
    assert at_discard.seen and at_discard.seen[0] == (_PID, True), (
        f"the shell's record was dropped while it was alive: {at_discard.seen}"
    )
    assert _PID not in cancellation._TOOL_PIDS
