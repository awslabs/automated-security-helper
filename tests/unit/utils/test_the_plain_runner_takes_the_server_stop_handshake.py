# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The plain runner takes the server-stop handshake for a child in its own group.

A child the plain runner puts in its own group (a timeout, or a caller's
start_new_session) is registered for kill_running_groups, the server's last
stop. It was registered straight after Popen, outside the count-and-record
handshake the cancellable runner takes: a server stopping between Popen and
the registration read the count as settled and missed the child, and a server
already stopping still started one. The runner now counts the spawn before
Popen (_begin_spawn, which refuses it once the server stops) and records the
child once started (_record_spawn, which kills a child the server began
stopping under), and such a spawn ends as a ScanCancelled, as a cancellable one
does. A child in ASH's own group is never registered and takes no part.

No process is started and no signal is sent: Popen is stood in for, the server's
kill is a recorder, and the module's count and registry are this test's own.
"""

import os
import signal
import subprocess  # nosec B404 - the module under test wraps subprocess
from typing import List

import pytest

from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.utils import subprocess_utils as spu

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="the group registry is POSIX"),
]


class _Child:
    """A recorded stand-in for a started child. It has no process behind it."""

    pid = 2**30 + 7007
    returncode = None
    args = ["tool"]
    stdin = None
    stdout = None
    stderr = None

    def __init__(self) -> None:
        self.calls: List[str] = []

    def poll(self):
        return self.returncode

    def kill(self) -> None:
        self.calls.append("kill")

    def wait(self, timeout=None):
        self.calls.append("wait")
        self.returncode = 0
        return 0

    def communicate(self, *args, **kwargs):
        self.calls.append("communicate")
        self.returncode = 0
        return None, None


@pytest.fixture
def registry(monkeypatch):
    """The module's count, flag and registry as this test's own, the die-now
    mirror and the reap as recorders, and the stops recorded."""
    monkeypatch.setattr(spu, "_STOPPING", False)
    monkeypatch.setattr(spu, "_SPAWNS_STARTING", 0)
    monkeypatch.setattr(spu, "_RUNNING_GROUPS", {})
    monkeypatch.setattr(spu, "_SERVER_KILLED", set())
    mirrored: List[int] = []
    monkeypatch.setattr(spu, "record_tool_group", mirrored.append)
    monkeypatch.setattr(spu, "_reap", lambda args, process: None)
    stops: List[str] = []
    monkeypatch.setattr(
        spu,
        "_stop_child",
        lambda args, process, stop, grace, prompt: stops.append(stop.__name__),
    )
    return {"mirrored": mirrored, "stops": stops}


def _popen(monkeypatch, child: _Child, *, then_stopping: bool = False) -> List[str]:
    """Popen stood in for: returns ``child`` and, when asked, lands the server's
    stop in the window after the child exists and before it is recorded."""
    started: List[str] = []

    def popen(args, **kwargs):
        started.append(list(args)[0])
        if then_stopping:
            spu._STOPPING = True
        return child

    monkeypatch.setattr(spu.subprocess, "Popen", popen)
    return started


def test_a_server_already_stopping_refuses_the_spawn_before_popen(
    monkeypatch, registry
):
    spu._STOPPING = True
    started = _popen(monkeypatch, _Child())

    with pytest.raises(
        ScanCancelled, match="the server is stopping, so tool was not started"
    ):
        spu._run_plain(["tool"], timeout=5)

    assert started == [], "the child was started under a stopping server"
    assert spu._SPAWNS_STARTING == 0
    assert registry["stops"] == []


def test_a_server_stopping_after_popen_kills_the_child_and_cancels(
    monkeypatch, registry
):
    child = _Child()
    _popen(monkeypatch, child, then_stopping=True)
    killed: List[_Child] = []

    def kill_group(process):
        killed.append(process)
        return True

    monkeypatch.setattr(spu, "_kill_group", kill_group)

    with pytest.raises(
        ScanCancelled, match="the server is stopping, so tool was stopped"
    ):
        spu._run_plain(["tool"], timeout=5)

    assert killed == [child], "the record's kill did not reach the child"
    assert "communicate" not in child.calls, "the child was waited for past the stop"
    assert registry["stops"] == [], "the child was stopped a second time"
    assert registry["mirrored"] == [child.pid], "the child was not recorded"
    assert spu._SPAWNS_STARTING == 0, "the count was not given up exactly once"


def test_a_kill_the_kernel_refuses_at_the_servers_stop_says_so(monkeypatch, registry):
    child = _Child()
    _popen(monkeypatch, child, then_stopping=True)

    def refused(process):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(spu, "_kill_group", refused)

    with pytest.raises(ScanCancelled) as raised:
        spu._run_plain(["tool"], timeout=5)

    assert raised.value.could_not_stop == (("tool", child.pid),)
    assert str(raised.value).startswith("the server is stopping; ")
    assert spu.could_not_stop_sentence(f"tool (pid {child.pid})") in str(raised.value)
    assert registry["stops"] == [], "a refused kill was tried again"
    assert spu._SPAWNS_STARTING == 0


def test_a_popen_that_raises_gives_the_count_back(monkeypatch, registry):
    def popen(args, **kwargs):
        raise OSError("no such program")

    monkeypatch.setattr(spu.subprocess, "Popen", popen)

    with pytest.raises(OSError):
        spu._run_plain(["tool"], timeout=5)

    assert spu._SPAWNS_STARTING == 0, "a spawn that started nothing stayed counted"


def test_a_child_in_ashs_own_group_takes_no_part(monkeypatch, registry):
    """No timeout and no session flag: the child shares ASH's group, so the
    server's last stop cannot reach it through the registry, and the handshake
    that feeds that registry is not taken."""
    spu._STOPPING = True
    child = _Child()
    started = _popen(monkeypatch, child)
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda process: False)

    completed = spu._run_plain(["tool"])

    assert started == ["tool"]
    assert completed.returncode == 0
    assert spu._SPAWNS_STARTING == 0
    assert registry["mirrored"] == []


class _ChildTheServerEnds(_Child):
    """A child that dies of SIGKILL while the runner waits on it, as one does when
    the server's last step signals it: that step sets its flag, and (when it
    signalled this child) records the pid it signalled."""

    def __init__(self, *, signalled_by_the_server: bool = True) -> None:
        super().__init__()
        self.signalled_by_the_server = signalled_by_the_server

    def communicate(self, *args, **kwargs):
        self.calls.append("communicate")
        spu._STOPPING = True
        if self.signalled_by_the_server:
            spu._SERVER_KILLED.add(self.pid)
        self.returncode = -signal.SIGKILL
        return None, None

    def wait(self, timeout=None):
        self.calls.append("wait")
        return self.returncode


@pytest.mark.parametrize("check", [False, True], ids=["unchecked", "check"])
def test_a_child_the_servers_last_step_killed_ends_the_run_as_a_cancel(
    check, monkeypatch, registry
):
    """The server began stopping while the tool ran and signalled the recorded
    child: the run ends as the cancel the cancellable runner raises, not as a
    completed run whose code is a SIGKILL ASH did not send, and not, with
    ``check``, as a CalledProcessError for a tool that did not fail."""
    child = _ChildTheServerEnds()
    _popen(monkeypatch, child)

    with pytest.raises(
        ScanCancelled, match="the server is stopping, so tool was stopped"
    ):
        spu._run_plain(["tool"], timeout=5, check=check)

    assert registry["stops"] == [], "a child the server ended was ended again"
    assert spu._SPAWNS_STARTING == 0


def test_a_sigkill_death_of_a_child_in_ashs_own_group_is_returned_as_it_is(
    monkeypatch, registry
):
    """The control: with no timeout the child shares ASH's group, is never
    recorded, and the server's last step cannot signal it. A SIGKILL death
    in the same seconds is the tool's own ending (the operator's kill, the
    kernel's), returned as a code, whether or not the server is stopping."""
    child = _ChildTheServerEnds(signalled_by_the_server=False)
    _popen(monkeypatch, child)
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda process: False)

    completed = spu._run_plain(["tool"])

    assert completed.returncode == -signal.SIGKILL
    assert isinstance(completed, subprocess.CompletedProcess)
