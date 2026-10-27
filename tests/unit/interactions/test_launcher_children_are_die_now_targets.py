# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The launchers' group-less children are die-now targets while they run.

The CLI's second-signal branches SIGKILL the recorded tool groups and
interrupt the recorded launcher children (core/cancellation._TOOL_PIDS). The container
runtime and the Nix shell share this process's group, so the group kill
cannot name them: each is recorded by pid right after its spawn, and
forgotten the moment its exit is OBSERVED -- before the reap, because a
reaped pid can be reused at once, and a record that outlives the reap aims
the die-now SIGINT at whatever process holds the pid next. ``os.waitid``
with ``WNOWAIT`` is the observation that leaves the child reapable.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - cells spawn the running interpreter, fixed argv
import sys
from typing import List, Tuple

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.skipif(
    # By the build, not the platform: these cells call os.waitid themselves,
    # and CPython leaves it out on some POSIX systems (macOS), where the
    # observation falls back to the reap-then-discard poll arm these cells
    # cannot pin.
    not hasattr(os, "waitid"),
    reason="the observe-before-reap order needs os.waitid",
)

#: ("record", pid, was-in-the-mirror) and ("discard", pid, was-still-reapable).
_Calls = List[Tuple[str, int, bool]]


@pytest.fixture
def pid_mirror(monkeypatch) -> None:
    """The die-now mirrors start empty, as sigterm_state's comment explains."""
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", ())


def _spy_on_discard(monkeypatch) -> _Calls:
    """Record each discard with whether the child was still reapable then.

    ``waitid`` with ``WNOWAIT`` raises for a child already reaped, so a False
    third field is exactly the ordering defect: the record outlived the reap.
    """
    calls: _Calls = []
    real_discard = subprocess_utils.discard_tool_pid

    def spy_discard(pid: int) -> None:
        reapable = True
        try:
            os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except OSError:
            reapable = False
        calls.append(("discard", pid, reapable))
        real_discard(pid)

    monkeypatch.setattr(subprocess_utils, "discard_tool_pid", spy_discard)
    return calls


def _spy_on_record(monkeypatch, module, calls: _Calls) -> None:
    real_record = module.record_tool_pid

    def spy_record(pid: int) -> None:
        real_record(pid)
        calls.append(("record", pid, pid in cancellation._TOOL_PIDS))

    monkeypatch.setattr(module, "record_tool_pid", spy_record)


def _one_recorded_then_discarded(calls: _Calls) -> None:
    records = [call for call in calls if call[0] == "record"]
    assert len(records) == 1 and records[0][2], (
        "the launcher's child was not recorded in the die-now pid mirror at "
        f"its spawn: {calls}"
    )
    pid = records[0][1]
    assert ("discard", pid, True) in calls, (
        "the record was not discarded while the child was still reapable, so "
        f"it outlived the reap: {calls}"
    )
    assert pid not in cancellation._TOOL_PIDS, (
        "the record is still in the mirror after the run"
    )


def test_the_container_runtimes_child_is_recorded_until_its_exit(
    pid_mirror, monkeypatch
):
    """run_cmd_direct records its child at the spawn and forgets it at the
    observed exit, so a second signal mid-run interrupts it and a signal after the
    run cannot aim at a reused pid."""
    from automated_security_helper.interactions import run_ash_container

    calls = _spy_on_discard(monkeypatch)
    _spy_on_record(monkeypatch, run_ash_container, calls)

    result = run_ash_container.run_cmd_direct([sys.executable, "-c", "print('ran')"])

    assert result.returncode == 0, result
    _one_recorded_then_discarded(calls)


def test_the_nix_shells_child_is_recorded_until_its_exit(pid_mirror, monkeypatch):
    """_enter_shell records and forgets its child the same way."""
    from automated_security_helper.interactions import run_ash_nix

    calls = _spy_on_discard(monkeypatch)
    _spy_on_record(monkeypatch, run_ash_nix, calls)

    result = run_ash_nix._enter_shell(
        [sys.executable, "-c", "print('ran')"], env=dict(os.environ)
    )

    assert result.returncode == 0, result
    _one_recorded_then_discarded(calls)


def test_the_stop_path_discards_a_record_before_reaping(pid_mirror, monkeypatch):
    """stop_after_interrupt's grace wait ends with the observed exit, so the
    discard comes before its reap."""
    calls = _spy_on_discard(monkeypatch)
    child = subprocess.Popen(  # nosec B603 - the running interpreter, fixed argv
        [sys.executable, "-c", "pass"],
        stdin=subprocess.DEVNULL,
    )
    cancellation.record_tool_pid(child.pid)

    subprocess_utils.stop_after_interrupt(child, child_got_the_interrupt=True)

    assert ("discard", child.pid, True) in calls, (
        f"the stop path did not discard before the reap: {calls}"
    )
    assert child.pid not in cancellation._TOOL_PIDS
    assert child.returncode is not None, "the stop path left the child unreaped"


def test_the_stop_paths_kill_arm_discards_a_record_before_reaping(
    pid_mirror, monkeypatch
):
    """A child that outlives the grace is killed; the discard still comes
    between the observed death and the reap."""
    calls = _spy_on_discard(monkeypatch)
    child = subprocess.Popen(  # nosec B603 - the running interpreter, fixed argv
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
    )
    cancellation.record_tool_pid(child.pid)

    try:
        subprocess_utils.stop_after_interrupt(child, 0.2, child_got_the_interrupt=True)

        assert ("discard", child.pid, True) in calls, (
            f"the kill arm did not discard before the reap: {calls}"
        )
        assert child.pid not in cancellation._TOOL_PIDS
        assert child.returncode is not None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
