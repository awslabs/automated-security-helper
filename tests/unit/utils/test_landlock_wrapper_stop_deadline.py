# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stopped Landlock wrapper finishes reaping inside half a second.

ASH stops the wrapper with SIGTERM and SIGKILLs it when the grace after that
signal ends. A wrapper killed while it reaps leaves what its scanner started
running, reparented elsewhere and never reaped. After its scanner exits on its own
the wrapper reaps for up to REAP_DEADLINE_SECONDS; once asked to stop, for
STOP_REAP_DEADLINE_SECONDS from that signal, whichever ends first.

Measured on run_and_reap itself, in a child interpreter that loads the wrapper by
path, with a descendant that never goes away, so that only a deadline ends the
reap loop. The control shows the loop then runs to REAP_DEADLINE_SECONDS when no
stop comes.
"""

import signal
import subprocess  # nosec B404 - runs the wrapper's reap loop in a child
import sys
import time

import pytest

# The wrapper binds libc at import (ctypes.CDLL(None)), which Windows rejects, so the
# module is skipped before the import, as test_sandbox_socket_filter.py does.
if sys.platform != "linux":
    pytest.skip("the wrapper uses prctl and /proc, Linux only", allow_module_level=True)

from automated_security_helper.utils.sandbox import landlock_exec  # noqa: E402
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS, KillAfter  # noqa: E402


#: The shortest grace after SIGTERM the wrapper is to fit inside.
GRACE_SECONDS = 0.5

# argv[1]: the wrapper's path. argv[2]: "stop" for a scanner that runs until it
# is stopped, "exit" for one that exits at once, "late" for one whose stop takes
# longer than STOP_REAP_DEADLINE_SECONDS to end it (each signal the wrapper sends
# waits 0.4 s first). Writes "ready <scanner pid>" once the stop signals are held
# for the handler, "reaping" when the reap loop starts, and "kill <id>" for each
# signal the wrapper sends, whether to a pid (os.kill) or to a process group
# (os.killpg): the scanner calls setsid in the wrapper's child setup, so its group
# id is its pid, and a group signal to it is written with the scanner's pid too.
DRIVER = """
import importlib.util, os, sys, time

spec = importlib.util.spec_from_file_location("landlock_exec", sys.argv[1])
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)
announced = []
send = os.kill
send_group = os.killpg
# Above the kernel's largest pid (2**22), so no process has it and every kill of
# it fails; the loop sees this descendant on every pass.
NEVER_GONE = 2**22 + 1
late = sys.argv[2] == "late"


def never_gone(*_args, **_kwargs):
    # Called as the wrapper calls _descendants: with its deadline, which this
    # descendant ignores, since the loop's own deadline is what is measured.
    if not announced:
        announced.append(True)
        os.write(1, b"reaping\\n")
    return [NEVER_GONE]


def recorded(target):
    # One line per signal, by pid or by group: the wrapper stops a scanner through
    # its group (os.killpg), and signals the pid itself only when the scanner has
    # left that group, so a recorder on os.kill alone would see no stop at all.
    if target != NEVER_GONE:
        os.write(1, b"kill %d\\n" % target)
        if late:
            time.sleep(0.4)


def recorded_kill(target, signum):
    recorded(target)
    return send(target, signum)


def recorded_killpg(group, signum):
    recorded(group)
    return send_group(group, signum)


def restrict():
    # In the forked child, after the parent blocked the stop signals.
    os.write(1, b"ready %d\\n" % os.getpid())


wrapper._descendants = never_gone
os.kill = recorded_kill
os.killpg = recorded_killpg
command = ["/bin/true"] if sys.argv[2] == "exit" else ["/bin/sleep", "30"]
sys.exit(wrapper.run_and_reap(command, restrict))
"""


def _driver(scanner: str):
    """The driver process and its scanner's pid."""
    process = subprocess.Popen(  # nosec B603 - fixed argv
        [sys.executable, "-I", "-c", DRIVER, landlock_exec.__file__, scanner],
        stdout=subprocess.PIPE,
    )
    # readline() blocks until the driver writes or exits; the kill ends one that
    # does neither.
    with KillAfter(process, "the wrapper's driver"):
        word, pid = process.stdout.readline().split()
    assert word == b"ready"
    return process, int(pid)


def _killed(process: subprocess.Popen) -> set:
    """The pids and group ids the wrapper signalled after the last line read."""
    lines = process.stdout.read().split(b"\n")
    return {int(line.split()[1]) for line in lines if line.startswith(b"kill ")}


def _wait_until_asleep(process: subprocess.Popen) -> None:
    """Return once the wrapper is asleep in the wait for its scanner.

    "ready" comes from the forked scanner, which can write it before the wrapper
    has installed its handlers and entered that wait. Python runs a signal handler
    only between bytecodes or when a blocking call is interrupted, so a SIGTERM
    that lands in the few instructions between the unblock and the blocking
    waitid() is not seen until waitid() returns, here 30 s later when the
    scanner's sleep ends. What this file measures is how long the wrapper takes
    once it has been told to end the scanner, so the signal is sent only while
    the wrapper is in that wait, where it interrupts the call.
    """
    deadline = time.monotonic() + CHILD_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        with open(f"/proc/{process.pid}/stat", "rb") as stat:
            state = stat.read().rsplit(b")", 1)[1].split()[0]
        if state == b"S":
            return
        time.sleep(0.005)
    raise AssertionError("the wrapper never went to sleep in its wait for the scanner")


def _stop_and_time(process: subprocess.Popen) -> float:
    started = time.monotonic()
    process.send_signal(signal.SIGTERM)
    process.wait(timeout=30)
    return time.monotonic() - started


def _finish(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.kill()
        process.wait(timeout=CHILD_TIMEOUT_SECONDS)
    process.stdout.close()


@pytest.mark.integration
def test_a_wrapper_stopped_while_its_scanner_runs_finishes_inside_the_grace():
    process, scanner = _driver("stop")
    try:
        with KillAfter(process, "the wrapper's driver"):
            _wait_until_asleep(process)
            elapsed = _stop_and_time(process)
            killed = _killed(process)
    finally:
        _finish(process)

    assert elapsed < GRACE_SECONDS, elapsed
    assert scanner in killed, "the stop did not end the running scanner"


@pytest.mark.integration
def test_a_wrapper_stopped_while_it_reaps_finishes_inside_the_grace():
    """The scanner exited on its own; the stop comes during the reap.

    The scanner has been reaped by then, so its pid may be another process's
    already, and the stop must not signal it.
    """
    process, scanner = _driver("exit")
    try:
        with KillAfter(process, "the wrapper's driver"):
            assert process.stdout.readline() == b"reaping\n"
            elapsed = _stop_and_time(process)
            killed = _killed(process)
    finally:
        _finish(process)

    assert elapsed < GRACE_SECONDS, elapsed
    assert process.returncode == 0
    assert scanner not in killed, "the stop signalled the reaped scanner's pid"


@pytest.mark.integration
def test_a_stop_whose_deadline_passed_before_the_scanner_exited_still_reaps_once():
    """The scanner outlived STOP_REAP_DEADLINE_SECONDS after the stop.

    The deadline is already behind when the reap starts; one pass is still made,
    so what the scanner left is killed at least once.
    """
    process, scanner = _driver("late")
    try:
        _wait_until_asleep(process)
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=30)
        lines = process.stdout.read().split(b"\n")
    finally:
        _finish(process)

    assert f"kill {scanner}".encode() in lines, "the stop did not end the scanner"
    assert b"reaping" in lines, "no reap pass after a stop that outlived its deadline"


@pytest.mark.integration
def test_without_a_stop_the_reap_runs_to_its_own_deadline():
    """Control: the descendant that never goes away keeps the loop running."""
    process, _scanner = _driver("exit")
    try:
        with KillAfter(process, "the wrapper's driver"):
            assert process.stdout.readline() == b"reaping\n"
        started = time.monotonic()
        process.wait(timeout=30)
        elapsed = time.monotonic() - started
    finally:
        _finish(process)

    assert elapsed > landlock_exec.REAP_DEADLINE_SECONDS - 0.5, elapsed
    assert process.returncode == 0


@pytest.mark.unit
def test_the_stop_deadline_is_inside_the_grace_and_the_normal_one():
    assert 0 < landlock_exec.STOP_REAP_DEADLINE_SECONDS < GRACE_SECONDS
    assert (
        landlock_exec.STOP_REAP_DEADLINE_SECONDS < landlock_exec.REAP_DEADLINE_SECONDS
    )
