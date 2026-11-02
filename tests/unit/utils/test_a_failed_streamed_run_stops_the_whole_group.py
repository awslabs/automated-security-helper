# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A streamed run that fails after the tool started stops the tool's whole group.

The streamed runner's cleanup killed the child by its pid alone. A child the
spawn plan puts in a process group of its own (start_new_session, or a tool that
called setsid) can have started members of its own; killed alone, it left them
running and holding the output directory the plan's cleanup sweeps next. The
cleanup now stops the whole group when the child leads one, as the cancel path
and the cancellable runner do, and kills a child in ASH's own group alone, as
before.

No process is started and no signal is sent: Popen, the group probe and the
group signal are stood in for.
"""

import os
import signal
import subprocess  # nosec B404 - the module under test wraps subprocess
from typing import Any, List

import pytest

from automated_security_helper.utils import subprocess_utils as spu

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="process groups are the POSIX arm"),
]

#: Above the kernel's pid space, so no live process shares it.
_PID = 2**30 + 7171


class _ReadFailsPopen:
    """A child whose output pipe fails to read after one line, so the runner
    reaches its cleanup with the child still running."""

    instances: List["_ReadFailsPopen"] = []

    def __init__(self, args, **kwargs):
        self.pid = _PID
        self.args = list(args)
        self.returncode = None
        self.calls: List[Any] = []
        self.stdin = self.stderr = None
        self.stdout = self
        _ReadFailsPopen.instances.append(self)

    def __iter__(self):
        yield "line one\n"
        raise OSError(5, "read failed")

    def close(self):
        self.calls.append("close")

    def poll(self):
        return self.returncode

    def kill(self):
        self.calls.append("kill")
        self.returncode = -9

    def ended_by_the_group_signal(self, signum):
        # Into the same record as the waits, so the order of the two is what a
        # case can assert, not only that both happened.
        self.calls.append(("group_signal", signum))
        self.returncode = -9

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.args, timeout or 0)
        return self.returncode


@pytest.fixture
def streamed_run(monkeypatch):
    """The runner with Popen, the spawn plan and the resolution stood in for, and
    the group signal recorded; the stand-in ends the child when its group is
    signalled."""
    _ReadFailsPopen.instances.clear()
    monkeypatch.setattr(spu.subprocess, "Popen", _ReadFailsPopen)
    monkeypatch.setattr(spu, "_resolved_or_refused", lambda *a: None)
    monkeypatch.setattr(spu, "_prepare_spawn", lambda *a, **k: None)
    monkeypatch.setattr(spu, "_pid_names_a_live_process", lambda pid: False)
    monkeypatch.setattr(spu, "_KILLED_GROUP_SETTLE_SECONDS", 0.01)
    sent: List[Any] = []

    def signal_group(pgid, signum):
        sent.append((pgid, signum))
        for child in _ReadFailsPopen.instances:
            child.ended_by_the_group_signal(signum)
        return True

    monkeypatch.setattr(spu, "_signal_group", signal_group)
    # The group is there while the child runs, and gone once it was signalled.
    monkeypatch.setattr(
        spu,
        "_group_survives",
        lambda pgid: any(c.returncode is None for c in _ReadFailsPopen.instances),
    )
    return sent


def test_the_cleanup_of_a_failed_run_stops_the_group_the_child_leads(
    monkeypatch, streamed_run
):
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda process: True)

    code = spu.run_command_stream_output(["ash-u26-no-such-tool"])

    (child,) = _ReadFailsPopen.instances
    assert code == spu.UNRECORDED_RUN_RETURNCODE
    assert streamed_run == [(_PID, signal.SIGKILL)], streamed_run
    assert "kill" not in child.calls, "the child was killed alone, its group left"
    assert child.returncode == -9, "the child was not reaped after the group kill"
    # The group signal ends the stand-in by itself (it sets the code), so the
    # code proves nothing about the reap. The bounded wait is what reaps, and it
    # must come after the signal: a cleanup that signalled the group and left the
    # child unwaited would pass the checks above and leave a zombie.
    group_signalled = child.calls.index(("group_signal", signal.SIGKILL))
    reaped = child.calls.index(("wait", spu._REAP_SECONDS))
    assert group_signalled < reaped, child.calls
    assert "close" in child.calls


def test_a_group_signal_the_kernel_refuses_is_logged_and_the_run_is_unrecorded(
    monkeypatch, streamed_run, caplog
):
    """EPERM on the group kill (a member the server may not signal): the error
    is not raised out of the run, the code says ASH could not record it, the
    refusal is on the log, and the pipe is still closed."""
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda process: True)

    def refused(pgid, signum):
        streamed_run.append((pgid, signum))
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(spu, "_signal_group", refused)
    with caplog.at_level("ERROR"):
        code = spu.run_command_stream_output(["ash-u26-no-such-tool"])

    (child,) = _ReadFailsPopen.instances
    assert code == spu.UNRECORDED_RUN_RETURNCODE
    assert streamed_run == [(_PID, signal.SIGKILL)], streamed_run
    messages = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert any("Operation not permitted" in m for m in messages), messages
    assert any("was not reaped" in m for m in messages), messages
    assert "close" in child.calls


class _LeaderExitedUnreaped(_ReadFailsPopen):
    """A group leader that has exited and is not reaped yet, as a tool's leader is
    when it ends while members it started run on: until something polls it,
    its returncode is unset, and the poll reaps it as Popen.poll does."""

    def poll(self):
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


def test_a_leader_that_exited_with_members_still_running_has_its_group_ended(
    monkeypatch, streamed_run
):
    """The read for a group of its own is made before the poll that reaps the
    leader: a reaped child answers False, and the members it started were left
    running (and holding the directory the plan's cleanup sweeps)."""
    monkeypatch.setattr(spu.subprocess, "Popen", _LeaderExitedUnreaped)
    # What the real probe answers: True for a leader not reaped, False once it is.
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda p: p.returncode is None)
    # The members run until the group is signalled, whatever the leader did.
    monkeypatch.setattr(
        spu, "_group_survives", lambda pgid: (pgid, signal.SIGKILL) not in streamed_run
    )

    code = spu.run_command_stream_output(["ash-u26-no-such-tool"])

    (child,) = _ReadFailsPopen.instances
    assert code == spu.UNRECORDED_RUN_RETURNCODE
    assert streamed_run == [(_PID, signal.SIGKILL)], streamed_run
    assert "close" in child.calls


def test_the_control_a_leader_in_ashs_own_group_that_exited_is_left_alone(
    monkeypatch, streamed_run
):
    """The same exited leader, but in ASH's own group: nothing of its own to end,
    no group signalled and no kill, as before."""
    monkeypatch.setattr(spu.subprocess, "Popen", _LeaderExitedUnreaped)
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda process: False)

    code = spu.run_command_stream_output(["ash-u26-no-such-tool"])

    (child,) = _ReadFailsPopen.instances
    assert code == spu.UNRECORDED_RUN_RETURNCODE
    assert streamed_run == []
    assert "kill" not in child.calls


def test_the_control_a_child_in_ashs_own_group_is_killed_alone(
    monkeypatch, streamed_run
):
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda process: False)

    code = spu.run_command_stream_output(["ash-u26-no-such-tool"])

    (child,) = _ReadFailsPopen.instances
    assert code == spu.UNRECORDED_RUN_RETURNCODE
    assert streamed_run == [], "a child in ASH's own group had its group signalled"
    assert "kill" in child.calls
    assert ("wait", None) in child.calls
