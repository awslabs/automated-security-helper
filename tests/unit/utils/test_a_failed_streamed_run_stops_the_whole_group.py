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

    def ended_by_the_group_signal(self):
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
            child.ended_by_the_group_signal()
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
    assert "close" in child.calls


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
