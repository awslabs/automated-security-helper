# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The SIGTERM handler's pid mirror follows the registry like the group one.

Launcher children that lead no process group of their own cannot be stopped
by the die-now ``killpg`` -- on a non-leader's pid it is ESRCH or the wrong
group -- so they are recorded by plain pid in a second lock-free tuple,
``cancellation._TOOL_PIDS``, and killed one ``os.kill`` at a time. The same
reuse hazard as the group mirror applies, sharper: a single pid is reused
faster than a pgid, so a stale entry aims the die-now SIGKILL at whatever
process holds that pid next. The test helper's ``forget_running_groups``
therefore discards this mirror with the registry too.
"""

from __future__ import annotations

import signal
import subprocess
import sys

from automated_security_helper.core import cancellation
from automated_security_helper.utils import subprocess_utils
from tests.utils.processes import forget_running_groups


def test_forget_running_groups_clears_a_recorded_pid():
    """A reaped child's pid leaves the pid mirror when the registry forgets
    it, exactly as the group mirror does."""
    process = subprocess.Popen(  # noqa: S603 -- own sleeper, reaped below
        [sys.executable, "-c", "import time; time.sleep(60)"]
    )
    try:
        with subprocess_utils._RUNNING_GROUPS_LOCK:
            subprocess_utils._RUNNING_GROUPS[process.pid] = process
        cancellation.record_tool_pid(process.pid)

        process.kill()
        process.wait(timeout=10)

        forget_running_groups()

        assert process.pid not in cancellation._TOOL_PIDS
        assert process.pid not in subprocess_utils._RUNNING_GROUPS
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        if hasattr(cancellation, "discard_tool_pid"):
            cancellation.discard_tool_pid(process.pid)
        with subprocess_utils._RUNNING_GROUPS_LOCK:
            subprocess_utils._RUNNING_GROUPS.pop(process.pid, None)


def test_the_die_now_kill_signals_recorded_pids_one_at_a_time(monkeypatch):
    """The default-kill branch kills recorded plain pids with ``os.kill``,
    never ``killpg``: these children lead no group of their own."""
    sent: list = []
    killed_groups: list = []
    monkeypatch.setattr("os.kill", lambda pid, sig: sent.append((pid, sig)))
    monkeypatch.setattr(
        "os.killpg", lambda pgid, sig: killed_groups.append((pgid, sig))
    )
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", ())
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", (), raising=False)
    # Above the kernel's pid space (pid_max is at most 2**22): an entry that
    # leaked past the finally could never aim a later kill at a real process.
    stand_in = 2**30 + 42
    cancellation.record_tool_pid(stand_in)
    try:
        cancellation._kill_recorded_groups()
    finally:
        cancellation.discard_tool_pid(stand_in)

    assert sent == [(stand_in, signal.SIGINT)], sent
    assert killed_groups == [], killed_groups


def test_a_refused_pid_kill_does_not_raise(monkeypatch):
    """A pid already gone, or one the kernel refuses, is left to its end:
    the same OSError pass as the group kill, because a raise here would
    replace the default kill with a traceback."""

    def _refuse(pid: int, sig: int) -> None:
        raise OSError("gone")

    monkeypatch.setattr("os.kill", _refuse)
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", ())
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", (), raising=False)
    stand_in = 2**30 + 43  # above the kernel's pid space
    cancellation.record_tool_pid(stand_in)
    try:
        cancellation._kill_recorded_groups()
    finally:
        cancellation.discard_tool_pid(stand_in)


def test_recording_a_pid_twice_keeps_one_entry(monkeypatch):
    """The record/discard pair keeps the same idempotence contract as the
    group pair, so a retried spawn does not double a kill target."""
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", (), raising=False)
    stand_in = 2**30 + 44  # above the kernel's pid space
    cancellation.record_tool_pid(stand_in)
    cancellation.record_tool_pid(stand_in)
    assert cancellation._TOOL_PIDS == (stand_in,)
    cancellation.discard_tool_pid(stand_in)
    assert cancellation._TOOL_PIDS == ()
