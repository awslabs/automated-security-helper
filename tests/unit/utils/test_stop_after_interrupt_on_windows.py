# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""On Windows, a container runtime gets the Ctrl-C and its grace, as on POSIX.

The runtime is started without CREATE_NEW_PROCESS_GROUP, so it shares ASH's console,
and Windows passes a Ctrl-C typed there to every process attached to the console
(https://learn.microsoft.com/windows/console/ctrl-c-and-ctrl-break-signals). The
runtime already has the interrupt. stop_after_interrupt treated a Windows child as
one that had not, and terminated it at once, which cut short the runtime's own
handling: with `docker run --rm` attached, that can leave the container running
after ASH exits.

On Windows the grace is waited out in slices of a poll and a sleep: Popen.wait
there is one WaitForSingleObject, which a Ctrl-C does not end, so a second
Ctrl-C would have landed only after the whole grace. It is not Popen.wait with
a slice timeout either: a Ctrl-C inside that call runs CPython's own wait for
the child with a time that is negative once the slice's window is spent, which
Windows reads as an enormous wait. The tests here pin that the grace path
makes no timed Popen.wait.

Real Windows does not run here, and act does not run windows-latest. These tests
stand in for the platform and the console; the windows-latest CI leg is the real
check.
"""

from __future__ import annotations

import ctypes
import os
import subprocess  # nosec B404 - only its TimeoutExpired is used
import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    INTERRUPT_GRACE_SECONDS,
    INTERRUPT_WAIT_SLICE_SECONDS,
    stop_after_interrupt,
)
from tests.utils.windows_console import WindowsOs, as_windows, with_a_slice_clock

#: How many slices the grace is waited out in on Windows.
_SLICES = round(INTERRUPT_GRACE_SECONDS / INTERRUPT_WAIT_SLICE_SECONDS)

#: One slice's sleep.
_SLICE = INTERRUPT_WAIT_SLICE_SECONDS

#: The reap after a kill: bounded (_REAP_SECONDS), never an unbounded wait, so
#: a child SIGKILL does not end (uninterruptible sleep) cannot hang ASH.
_REAP = ("wait", subprocess_utils._REAP_SECONDS)


class _Child:
    """The members stop_after_interrupt uses, recorded. Anything else raises.

    The child ends *exits_after* seconds into the (fake) clock and, with
    *still_running*, never ends. It exists as far as ``poll`` says, and every
    ``wait`` is recorded: the Windows tests pin that the grace path polls and
    sleeps instead of making a timed ``wait`` (see the module docstring).
    """

    #: Above the kernel's pid space, as the mirror cells' stand-ins are, so
    #: nothing running can share it. The die-now record keeping reads the pid
    #: and the exit before the reap; a pid that leads no real child reads as
    #: already ended there, which only drops a record these cells never make.
    pid = 2**30 + 41

    def __init__(self, *, clock=None, exits_after=0.0, still_running=False):
        self._clock = clock
        self._exits_after = None if still_running else exits_after
        self.calls = []
        #: Read, never written, by the die-now observation: None, as for a
        #: child not yet reaped.
        self.returncode = None

    def send_signal(self, signum):
        self.calls.append(("send_signal", signum))

    def terminate(self):
        self.calls.append(("terminate",))

    def kill(self):
        self.calls.append(("kill",))
        # A killed child has ended: the poll arm of the die-now observation
        # then sees the exit at once instead of waiting out its bound.
        self.returncode = -9

    def poll(self):
        # The grace wait's poll, and the die-now observation's fallback on a
        # build without os.waitid (Windows, macOS): the exit, once it is due.
        if (
            self.returncode is None
            and self._exits_after is not None
            and (
                self._clock is None
                or self._clock.now - self._clock.start >= self._exits_after
            )
        ):
            self.returncode = 0
        return self.returncode

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        return 0


@pytest.fixture
def clock(monkeypatch):
    """The sliced waits' clock and sleep, driven by the test."""
    fake = with_a_slice_clock(monkeypatch)
    fake.start = fake.now
    return fake


@pytest.mark.unit
def test_the_slices_add_up_to_the_grace():
    assert _SLICES * INTERRUPT_WAIT_SLICE_SECONDS == pytest.approx(
        INTERRUPT_GRACE_SECONDS
    )
    assert INTERRUPT_WAIT_SLICE_SECONDS <= 0.5, "a second Ctrl-C should land quickly"


@pytest.mark.unit
class TestWithAConsole:
    """The runtime shares the console, so it has the Ctrl-C already."""

    @pytest.fixture(autouse=True)
    def windows_with_a_console(self, monkeypatch):
        as_windows(monkeypatch, console=True)

    def test_a_runtime_that_stops_within_the_grace_is_left_to_stop(self, clock):
        child = _Child(clock=clock)

        stop_after_interrupt(child)

        assert child.calls == []
        assert clock.sleeps == []

    def test_a_runtime_that_stops_late_in_the_grace_is_still_left_to_stop(self, clock):
        child = _Child(clock=clock, exits_after=(_SLICES - 1) * _SLICE)

        stop_after_interrupt(child)

        assert child.calls == []
        assert clock.sleeps == [_SLICE] * (_SLICES - 1)

    def test_a_runtime_still_running_after_the_grace_is_killed(self, clock):
        """Not terminated first: terminate() before the grace is the defect."""
        child = _Child(clock=clock, still_running=True)

        stop_after_interrupt(child)

        assert clock.sleeps == [_SLICE] * _SLICES
        assert child.calls == [("kill",), _REAP]

    def test_a_second_ctrl_c_while_waiting_kills_at_once(self, clock):
        """It lands between two slices, not after the whole grace."""
        clock.interrupt_on = 2
        child = _Child(clock=clock, still_running=True)

        with pytest.raises(KeyboardInterrupt):
            stop_after_interrupt(child)

        assert clock.sleeps == [_SLICE, _SLICE]
        assert child.calls == [("kill",), _REAP]

    def test_the_grace_path_never_calls_a_timed_popen_wait(self, clock):
        """Popen.wait(timeout=...) has its own Ctrl-C handler, which waits a
        negative time once the window is spent: not on this path."""
        child = _Child(clock=clock, still_running=True)

        stop_after_interrupt(child)

        waits = [call for call in child.calls if call[0] == "wait"]
        assert waits == [_REAP], waits

    def test_a_ctrl_c_during_the_sleep_reaches_the_caller(self, clock):
        """_wait_out lets the KeyboardInterrupt the sleep raises go up."""
        clock.interrupt_on = 1
        child = _Child(clock=clock, still_running=True)

        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._wait_out(child, INTERRUPT_GRACE_SECONDS)

        assert clock.sleeps == [_SLICE]
        assert child.calls == []

    def test_a_runtime_that_outlives_the_grace_raises_timeout_expired(self, clock):
        child = _Child(clock=clock, still_running=True)

        with pytest.raises(subprocess.TimeoutExpired) as raised:
            subprocess_utils._wait_out(child, INTERRUPT_GRACE_SECONDS)

        assert raised.value.timeout == INTERRUPT_GRACE_SECONDS
        assert clock.sleeps == [_SLICE] * _SLICES
        assert child.calls == []


@pytest.mark.unit
class TestWithoutAConsole:
    """No console, so the Ctrl-C did not reach the runtime: it is stopped.

    TerminateProcess ends it at once, so the wait after is a formality.
    """

    @pytest.fixture(autouse=True)
    def windows_without_a_console(self, monkeypatch):
        as_windows(monkeypatch, console=False)

    def test_the_runtime_is_terminated(self, clock):
        child = _Child(clock=clock)

        stop_after_interrupt(child)

        assert child.calls == [("terminate",)]
        assert clock.sleeps == []

    def test_a_runtime_that_outlives_it_is_killed(self, clock):
        child = _Child(clock=clock, still_running=True)

        stop_after_interrupt(child)

        assert clock.sleeps == [_SLICE] * _SLICES
        assert child.calls == [("terminate",), ("kill",), _REAP]


@pytest.mark.skipif(os.name == "nt", reason="the POSIX wait")
@pytest.mark.unit
class TestOnPosixTheWaitIsOne:
    """POSIX reaps with one wait carrying the whole grace, never sliced waits.

    The POSIX arm first OBSERVES the exit without reaping, so the die-now
    record is discarded before the pid can be reused, and only then reaps,
    with a single wait whose timeout is the full grace. Slice-sized wait
    calls are the Windows arm's shape alone. The stand-in's pid leads no
    real child, so the observation reads it as already ended at its first
    pass, and the one recorded call is that reap.
    """

    def test_one_wait_for_the_whole_grace(self, monkeypatch):
        monkeypatch.setattr(
            subprocess_utils, "_child_got_the_terminals_interrupt", lambda: True
        )
        # The die-now observation reads a stand-in pid as already ended
        # through os.waitid (OSError on a pid past the kernel's space), but
        # CPython on macOS has no os.waitid and the fallback polls, which
        # this stand-in answers as still running; the observation is stood in
        # as already-ended so every POSIX build measures the one reaping wait.
        monkeypatch.setattr(
            subprocess_utils, "discard_tool_pid_once_exited", lambda _process: True
        )
        child = _Child()

        stop_after_interrupt(child)

        assert child.calls == [("wait", INTERRUPT_GRACE_SECONDS)]


@pytest.mark.unit
class TestTheConsoleCheck:
    """Attached to a console exactly when GetConsoleProcessList does not fail.

    "If the return value is zero, the function has failed, because every console has
    at least one process associated with it."
    (https://learn.microsoft.com/windows/console/getconsoleprocesslist) With more
    processes attached than the buffer holds, it returns how many, which is not zero
    either. GetConsoleWindow would be the wrong probe: it answers whether the
    console has a window, which a console need not have.
    """

    @staticmethod
    def _kernel32(monkeypatch, returned):
        calls = []

        def get_console_process_list(buffer, count):
            # What the real call needs: a DWORD array with room for count ids. A
            # NULL buffer fails, so it reads as no console on every Windows host,
            # and a byte array takes a 4-byte write into 1 byte.
            assert isinstance(buffer, ctypes.Array), buffer
            assert buffer._type_ is ctypes.c_ulong, buffer._type_
            assert len(buffer) >= count, (len(buffer), count)
            calls.append(count)
            return returned

        kernel32 = SimpleNamespace(GetConsoleProcessList=get_console_process_list)
        monkeypatch.setattr(
            ctypes, "windll", SimpleNamespace(kernel32=kernel32), raising=False
        )
        return calls

    @pytest.mark.parametrize(
        "returned, attached",
        [
            pytest.param(1, True, id="this-process-alone"),
            pytest.param(3, True, id="more-than-the-buffer-holds"),
            pytest.param(0, False, id="not-attached"),
        ],
    )
    def test_it_reads_get_console_process_list(self, monkeypatch, returned, attached):
        calls = self._kernel32(monkeypatch, returned)

        assert subprocess_utils._has_a_console() is attached
        assert calls == [1]

    def test_without_the_windows_api_there_is_no_console(self, monkeypatch):
        monkeypatch.delattr(ctypes, "windll", raising=False)

        assert subprocess_utils._has_a_console() is False

    def test_a_python_without_ctypes_has_no_console(self, monkeypatch):
        """A Windows Python built without _ctypes: ImportError, not a crash."""
        monkeypatch.setitem(sys.modules, "ctypes", None)

        assert subprocess_utils._has_a_console() is False

    def test_and_its_runtime_is_stopped_as_without_a_console(self, monkeypatch):
        """The Ctrl-C handler raised ModuleNotFoundError: no wait, kill or exit 130."""
        monkeypatch.setattr(subprocess_utils, "os", WindowsOs())
        monkeypatch.setitem(sys.modules, "ctypes", None)
        child = _Child()

        stop_after_interrupt(child)

        assert child.calls == [("terminate",)]


class _OsWithoutWaitid:
    """``os`` as a build without ``waitid`` has it (CPython on macOS, Windows)."""

    def __getattr__(self, attribute: str):
        if attribute == "waitid":
            raise AttributeError(attribute)
        return getattr(os, attribute)


@pytest.mark.integration
def test_a_build_without_waitid_keeps_the_record_while_the_child_is_alive(
    monkeypatch,
):
    """The wait before a reap polls for the exit with the die-now record still
    registered, and discards it only once the child has ended, so a die-now
    sweep during the wait can still kill the child."""
    from automated_security_helper.core import cancellation

    monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())
    monkeypatch.setattr(subprocess_utils, "os", _OsWithoutWaitid())
    assert not hasattr(subprocess_utils.os, "waitid")
    child = subprocess.Popen(  # nosec B603 - the running interpreter, fixed argv
        [sys.executable, "-c", "import time; time.sleep(0.3)"],
        stdin=subprocess.DEVNULL,
    )
    cancellation.record_tool_pid(child.pid)
    at_discard = []
    real_discard = subprocess_utils.discard_tool_pid

    def spy_discard(pid: int) -> None:
        at_discard.append((pid, child.poll() is not None))
        real_discard(pid)

    monkeypatch.setattr(subprocess_utils, "discard_tool_pid", spy_discard)

    try:
        assert child.pid in cancellation._TOOL_PIDS
        subprocess_utils.discard_tool_pid_before_reap(child)

        assert at_discard == [(child.pid, True)], (
            f"the record was discarded while the child was still running: {at_discard}"
        )
        assert child.pid not in cancellation._TOOL_PIDS
        assert child.returncode is not None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
