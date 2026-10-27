# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The container and Nix launchers' child waits read the scan's cancel event.

Each launcher has exactly one place it sits while its child runs: container
mode's ``run_cmd_direct`` poll loop and Nix mode's ``_enter_shell`` wait. A
cancel set while the child runs -- the SIGTERM handler does nothing more than
set it -- must stop the child through the launcher's interrupt stop path and
raise ``ScanCancelled`` instead of waiting the child out and returning a
result as though nothing had been asked. The children here are the test's own
interpreter sleeping; nothing is built, run, or entered.

The controls pin the other side: with no cancel asked for, both waits still
return the child's own result, including outside any cancel scope, where
``current_cancel_event()`` is None.
"""

from __future__ import annotations

import subprocess  # nosec B404 - the children are this test's own interpreter
import sys
import threading
import time
from pathlib import Path

import pytest

from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
)
from automated_security_helper.interactions.run_ash_container import run_cmd_direct
from automated_security_helper.interactions.run_ash_nix import _enter_shell
from automated_security_helper.utils import subprocess_utils
from tests.utils.processes import process_running

#: Long enough that "the wait returned early" is unambiguous, short enough
#: that the pre-fix red -- the wait sitting the child out -- stays bounded.
_CHILD_SLEEP_SECONDS = 20.0

#: Well above a prompt stop's cost (one poll interval plus the child dying on
#: SIGINT) and well below the child's sleep, so the bound distinguishes the
#: two without caring about host load.
_STOPPED_WITHIN_SECONDS = 10.0

_SLEEPING_CHILD = [
    sys.executable,
    "-c",
    f"import time; time.sleep({_CHILD_SLEEP_SECONDS})",
]

_QUICK_CHILD = [sys.executable, "-c", "raise SystemExit(0)"]


def _cancelled_event() -> CancelEvent:
    event = CancelEvent()
    event.set()
    return event


def _child_that_reports_start(marker: Path) -> list[str]:
    """A sleeping child that first proves it is running by writing ``marker``."""
    return [
        sys.executable,
        "-c",
        (
            "import pathlib, time; "
            f"pathlib.Path({str(marker)!r}).write_text('started', encoding='utf-8'); "
            f"time.sleep({_CHILD_SLEEP_SECONDS})"
        ),
    ]


def _set_once_the_child_started(event: CancelEvent, marker: Path) -> None:
    """Set ``event`` only after ``marker`` appears, so the cancel is mid-wait.

    A time.sleep delay would race the spawn: a cancel that lands first takes
    the pre-spawn refusal and the cell would pass without ever reading the
    wait loop. Waiting for the child's own marker makes the order a fact. If
    the child never starts, the event is set at the deadline anyway, so the
    cell fails on its time bound instead of sitting the sleep out.
    """

    def _watch() -> None:
        deadline = time.monotonic() + _CHILD_SLEEP_SECONDS
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.05)
        event.set()

    threading.Thread(target=_watch, daemon=True).start()


class TestContainerRuntimeWait:
    def test_a_cancel_during_the_wait_stops_the_child_and_raises(self):
        started = time.monotonic()
        with cancel_scope(_cancelled_event()):
            with pytest.raises(ScanCancelled):
                run_cmd_direct(_SLEEPING_CHILD, check=False)
        assert time.monotonic() - started < _STOPPED_WITHIN_SECONDS

    def test_a_cancel_set_after_the_child_started_stops_it_mid_wait(
        self, tmp_path, monkeypatch
    ):
        """The poll loop's own pin: the event is set only once the child has
        proved it is running, so the stop can only have come from the wait,
        never from a refusal before the spawn. The spawned child is captured
        so the cell can assert the child itself was stopped: the elapsed
        bound alone was once answered by the arm's reader joins, which cost
        almost exactly the bound with no stop at all."""
        event = CancelEvent()
        marker = tmp_path / "child-started"
        spawned: "list[subprocess.Popen]" = []
        real_spawn = subprocess_utils.create_process_with_pipes

        def _capturing_spawn(**kwargs):
            process = real_spawn(**kwargs)
            spawned.append(process)
            return process

        monkeypatch.setattr(
            subprocess_utils, "create_process_with_pipes", _capturing_spawn
        )
        started = time.monotonic()
        with cancel_scope(event):
            _set_once_the_child_started(event, marker)
            with pytest.raises(ScanCancelled):
                run_cmd_direct(_child_that_reports_start(marker), check=False)
        assert marker.exists()
        (child,) = spawned
        # Read before the cleanup below, asserted after it: killing the
        # survivor first would hide exactly what the assertion looks for.
        # The OS is read first and poll() second: poll() answers from the
        # Popen bookkeeping, which the stop path under test could have
        # written without stopping anything, while /proc cannot be told a
        # running process is gone. A child the arm killed but has not yet
        # reaped is a zombie, which process_running counts as stopped.
        still_running_after_the_raise = process_running(child.pid)
        code_after_the_raise = child.poll()
        if still_running_after_the_raise or code_after_the_raise is None:
            child.kill()
            child.wait(timeout=30)
        assert not still_running_after_the_raise, (
            "the cancel arm raised without stopping the child it was watching: "
            "whatever its recorded code says, the process itself still runs"
        )
        assert code_after_the_raise is not None, (
            "the cancel arm raised without stopping the child it was watching"
        )
        # The stop kills the child by signal, so its code is never the 0 a
        # child that slept its sleep out exits with.
        assert code_after_the_raise != 0
        assert time.monotonic() - started < _STOPPED_WITHIN_SECONDS

    def test_with_no_cancel_asked_for_the_wait_returns_the_childs_result(self):
        with cancel_scope(CancelEvent()):
            result = run_cmd_direct(_QUICK_CHILD, check=False)
        assert result.returncode == 0

    def test_outside_any_scope_the_wait_returns_the_childs_result(self):
        result = run_cmd_direct(_QUICK_CHILD, check=False)
        assert result.returncode == 0


class TestNixShellWait:
    def test_a_cancel_during_the_wait_stops_the_shell_and_raises(self):
        started = time.monotonic()
        with cancel_scope(_cancelled_event()):
            with pytest.raises(ScanCancelled):
                _enter_shell(list(_SLEEPING_CHILD), env={})
        assert time.monotonic() - started < _STOPPED_WITHIN_SECONDS

    def test_a_cancel_set_after_the_shell_started_stops_it_mid_wait(
        self, tmp_path, monkeypatch
    ):
        """The wait's own pin, synchronized as the container cell is: the
        event is set only once the shell's child has proved it is running.
        The shell is captured so the cell can assert it was stopped, not
        only that the wait returned quickly."""
        import automated_security_helper.interactions.run_ash_nix as nix_launcher

        event = CancelEvent()
        marker = tmp_path / "shell-started"
        spawned: "list[subprocess.Popen]" = []
        real_popen = subprocess.Popen

        def _capturing_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            return process

        monkeypatch.setattr(nix_launcher.subprocess, "Popen", _capturing_popen)
        started = time.monotonic()
        with cancel_scope(event):
            _set_once_the_child_started(event, marker)
            with pytest.raises(ScanCancelled):
                _enter_shell(_child_that_reports_start(marker), env={})
        assert marker.exists()
        (shell,) = spawned
        # Read before the cleanup below, asserted after it: killing the
        # survivor first would hide exactly what the assertion looks for.
        # As in the container cell: the OS first, poll() second, because the
        # bookkeeping read is writable by the very path under test and a
        # killed-but-unreaped shell is a zombie process_running counts as
        # stopped.
        still_running_after_the_raise = process_running(shell.pid)
        code_after_the_raise = shell.poll()
        if still_running_after_the_raise or code_after_the_raise is None:
            shell.kill()
            shell.wait(timeout=30)
        assert not still_running_after_the_raise, (
            "the wait raised without stopping the shell it was watching: "
            "whatever its recorded code says, the process itself still runs"
        )
        assert code_after_the_raise is not None, (
            "the wait raised without stopping the shell it was watching"
        )
        # As the container cell holds: the stop's kill is never the sleep's
        # own clean exit.
        assert code_after_the_raise != 0
        assert time.monotonic() - started < _STOPPED_WITHIN_SECONDS

    def test_with_no_cancel_asked_for_the_wait_returns_the_shells_result(self):
        with cancel_scope(CancelEvent()):
            result = _enter_shell(list(_QUICK_CHILD), env={})
        assert result.returncode == 0

    def test_outside_any_scope_the_wait_returns_the_shells_result(self):
        result = _enter_shell(list(_QUICK_CHILD), env={})
        assert result.returncode == 0


class TestACancelledScanSpawnsNoChild:
    """The launchers refuse to start a child into a cancel already asked for.

    A SIGTERM that lands between the image build returning and the runtime
    start leaves exactly this window: the event is set, nothing has read it
    yet, and the next step is the spawn. The wait cells above cannot see the
    window -- an event set before the call is answered before any child
    exists -- so these cells read the spawn itself: it must never happen,
    as every other spawn path already refuses (utils/subprocess_utils.py).
    """

    def test_the_container_wait_refuses_to_start_the_runtime(self, monkeypatch):
        spawned: list[object] = []

        def _record_spawn(*args: object, **kwargs: object) -> object:
            spawned.append((args, kwargs))
            raise RuntimeError("a runtime was started into a cancelled scan")

        monkeypatch.setattr(
            subprocess_utils, "create_process_with_pipes", _record_spawn
        )
        with cancel_scope(_cancelled_event()):
            with pytest.raises(ScanCancelled):
                run_cmd_direct(_SLEEPING_CHILD, check=False)
        assert spawned == []

    def test_the_nix_wait_refuses_to_start_the_shell(self, monkeypatch):
        import automated_security_helper.interactions.run_ash_nix as nix_launcher

        spawned: list[object] = []

        def _record_spawn(*args: object, **kwargs: object) -> object:
            spawned.append((args, kwargs))
            raise RuntimeError("a shell was started into a cancelled scan")

        monkeypatch.setattr(nix_launcher.subprocess, "Popen", _record_spawn)
        with cancel_scope(_cancelled_event()):
            with pytest.raises(ScanCancelled):
                _enter_shell(list(_SLEEPING_CHILD), env={})
        assert spawned == []


class TestTheCancelArmAlwaysSignalsTheChild:
    def test_false_sends_the_interrupt_even_when_the_terminal_claims_delivery(
        self, monkeypatch
    ):
        """The cancel arms pass ``child_got_the_interrupt=False`` for a reason.

        The terminal probe answers "did the child get the operator's Ctrl-C",
        and at a terminal it says yes. A SIGTERM-triggered cancel delivered
        nothing to the child, so the flag must beat the probe: the child gets
        the interrupt and dies at once, instead of sitting out the whole grace
        and being killed. The probe is forced to its at-a-terminal answer, and
        the bound is under the grace, so a stop that fell back to grace-and-kill
        fails here.
        """
        monkeypatch.setattr(
            subprocess_utils, "_child_got_the_terminals_interrupt", lambda: True
        )
        # The child resets its SIGINT disposition: under a parent that ignores
        # SIGINT (nohup, some CI wrappers), the child would inherit SIG_IGN,
        # CPython would install no KeyboardInterrupt handler, and the sent
        # interrupt would do nothing -- the stop would wait out the grace and
        # kill, failing the bound below although the code under test sent the
        # signal it should. The reset makes the cell measure the stop path,
        # not the shell that started pytest, and the ready line keeps the
        # stop from firing into the interpreter's startup window, before the
        # reset has run.
        process = subprocess.Popen(  # nosec B603 - this test's own interpreter
            [
                sys.executable,
                "-c",
                (
                    "import signal, time\n"
                    "signal.signal(signal.SIGINT, signal.default_int_handler)\n"
                    "print('ready', flush=True)\n"
                    "time.sleep(20)"
                ),
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "ready"
        started = time.monotonic()
        subprocess_utils.stop_after_interrupt(
            process, grace=3.0, child_got_the_interrupt=False
        )
        assert process.returncode is not None
        assert time.monotonic() - started < 2.0


class TestTheCancelArmSaysTheChildHasNoInterrupt:
    """Each launcher's cancel arm passes exactly ``child_got_the_interrupt=False``.

    The SIGTERM that set the event was delivered to this process alone, so the
    child has received nothing; the default (None) asks the terminal, which at a
    terminal would wrongly report the child interrupted and skip the send,
    leaving the child its whole grace and no chance at a clean stop. The cancel
    is set only AFTER the spawn, by the child's own first wait: set before it,
    the pre-spawn check refuses the start and the arm under test never runs, so
    a cell cannot see the kwarg. The stop is recorded, not run: the kwargs are
    the assertion, and a flipped or dropped value fails it.
    """

    def test_the_container_cancel_arm_passes_false(self, monkeypatch):
        from automated_security_helper.interactions import run_ash_container

        event = CancelEvent()

        class _Runtime:
            pid = 54321
            returncode: int | None = None
            stdout = iter(())
            stderr = iter(())

            def poll(self):
                # The spawn already happened with the event unset; the cancel
                # lands while the runtime runs, at its first poll.
                event.set()
                return self.returncode

        runtime = _Runtime()
        monkeypatch.setattr(
            subprocess_utils, "create_process_with_pipes", lambda **kwargs: runtime
        )
        stops: list[tuple[object, tuple, dict]] = []

        def _recorded_stop(process, *args, **kwargs):
            stops.append((process, args, kwargs))
            runtime.returncode = -2

        monkeypatch.setattr(run_ash_container, "_stop_after_interrupt", _recorded_stop)

        with cancel_scope(event):
            with pytest.raises(ScanCancelled):
                run_cmd_direct(["runtime", "run", "scan"], check=False)

        ((process, args, kwargs),) = stops
        assert process is runtime
        assert args == ()
        assert kwargs == {"child_got_the_interrupt": False}

    def test_the_nix_cancel_arm_passes_false(self, monkeypatch):
        import automated_security_helper.interactions.run_ash_nix as nix_launcher

        event = CancelEvent()

        class _Shell:
            # Above the kernel's pid space, as the mirror cells' stand-ins
            # are, so nothing running can share it.
            pid = 2**30 + 22
            _code: int | None = None

            @property
            def returncode(self):
                # The wait loop observes the shell through this read each
                # pass, so the first read is the "shell is running" moment:
                # the spawn already happened with the event unset, and the
                # cancel lands here, mid-wait.
                event.set()
                return self._code

            @returncode.setter
            def returncode(self, value):
                self._code = value

            def wait(self, timeout=None):
                return self._code

        shell = _Shell()
        monkeypatch.setattr(
            nix_launcher.subprocess, "Popen", lambda *args, **kwargs: shell
        )

        def _ended_without_a_child(process):
            # The faked shell leads no real child for os.waitid to observe
            # (a foreign pid reads as already ended, which would end the wait
            # before the cancel is ever checked), so the observation reads
            # the recorded exit directly and drops the record as the real
            # helper does, keeping the die-now mirror empty after the cell.
            if process.returncode is None:
                return False
            subprocess_utils.discard_tool_pid(process.pid)
            return True

        monkeypatch.setattr(
            nix_launcher, "discard_tool_pid_once_exited", _ended_without_a_child
        )
        stops: list[tuple[object, tuple, dict]] = []

        def _recorded_stop(process, *args, **kwargs):
            stops.append((process, args, kwargs))
            shell.returncode = -2

        monkeypatch.setattr(nix_launcher, "stop_after_interrupt", _recorded_stop)

        with cancel_scope(event):
            with pytest.raises(ScanCancelled):
                _enter_shell(["nix", "develop"], env={})

        ((process, args, kwargs),) = stops
        assert process is shell
        assert args == ()
        assert kwargs == {"child_got_the_interrupt": False}


class TestTheLaunchersRecordTheirChildForTheDieNowKill:
    """Each launcher records its child's pid for the die-now kill while the
    child runs, and the record does not outlive the wait.

    The children are not group leaders, so the group record's killpg cannot
    reach them (ESRCH, passed over): only the pid record
    (core/cancellation._TOOL_PIDS) lets a second SIGTERM end a running
    runtime or shell. The mid-run read is synchronized by the child's own
    marker, so the pid seen recorded is provably the running child's. The
    discard on every OTHER exit path is policed by the autouse stale-mirror
    guard in tests/conftest.py, which fails any cell that leaves an entry
    behind; these cells pin the cancel path's discard directly."""

    def _recorded_while_running_and_after(
        self, tmp_path, monkeypatch, launcher, spawn_patch
    ):
        from automated_security_helper.core import cancellation

        event = CancelEvent()
        marker = tmp_path / "child-started"
        spawned: "list[subprocess.Popen]" = []
        spawn_patch(monkeypatch, spawned)
        seen: "list[tuple[int, ...]]" = []

        def _read_then_cancel() -> None:
            deadline = time.monotonic() + _CHILD_SLEEP_SECONDS
            while time.monotonic() < deadline and not marker.exists():
                time.sleep(0.05)
            seen.append(cancellation._TOOL_PIDS)
            event.set()

        with cancel_scope(event):
            threading.Thread(target=_read_then_cancel, daemon=True).start()
            with pytest.raises(ScanCancelled):
                launcher(_child_that_reports_start(marker))
        (child,) = spawned
        (while_running,) = seen
        assert while_running == (child.pid,)
        assert child.pid not in cancellation._TOOL_PIDS

    def test_the_container_wait_records_and_discards(self, tmp_path, monkeypatch):
        def _patch(monkeypatch, spawned):
            real_spawn = subprocess_utils.create_process_with_pipes

            def _capturing_spawn(**kwargs):
                process = real_spawn(**kwargs)
                spawned.append(process)
                return process

            monkeypatch.setattr(
                subprocess_utils, "create_process_with_pipes", _capturing_spawn
            )

        self._recorded_while_running_and_after(
            tmp_path,
            monkeypatch,
            lambda cmd: run_cmd_direct(cmd, check=False),
            _patch,
        )

    def test_the_nix_wait_records_and_discards(self, tmp_path, monkeypatch):
        import automated_security_helper.interactions.run_ash_nix as nix_launcher

        def _patch(monkeypatch, spawned):
            real_popen = subprocess.Popen

            def _capturing_popen(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                spawned.append(process)
                return process

            monkeypatch.setattr(nix_launcher.subprocess, "Popen", _capturing_popen)

        self._recorded_while_running_and_after(
            tmp_path,
            monkeypatch,
            lambda cmd: _enter_shell(cmd, env={}),
            _patch,
        )
