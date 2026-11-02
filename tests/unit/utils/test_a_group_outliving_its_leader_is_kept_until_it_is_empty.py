# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool group that outlives its leader stays recorded until the group is empty.

_forget_exited_groups runs under the registry lock on every cancellable spawn
and at the start of kill_running_groups. It used to drop a child the moment
poll() reaped it, in the registry and in the SIGTERM handler's die-now mirror
both. A sandbox wrapper is such a child: it calls setsid, starts the tool, and
can exit while the tool runs on in the group it led. Once the entry was gone a
cancel or a timeout had nothing to signal but the dead leader's pid, and
kill_running_groups reported the group killed while its members ran on.

The kernel keeps a group id in use while any member holds it, so killpg with
signal 0 tells an emptied group from one that still runs. The tests drive the
reap path with a reaped fake leader and the group calls recorded: the entry is
kept while the group answers, dropped once it is gone, and kill_running_groups
still SIGKILLs the group of a leader that was reaped before it ran. A group the
kernel refuses to probe (EPERM: a member now runs as another user) exists, so
the entry is kept and nothing is raised out of the spawn that ran the reap. The
probe is the module's _group_survives, which reaps the zombie orphans this
process inherited as PID 1 before asking, so a group left with nothing but
zombies is forgotten rather than kept for as long as they sit. A reaped leader
whose pid a live process holds again has had it reused: the group that answers
may be a stranger's, so the entry is dropped before anything could aim at it.
"""

from __future__ import annotations

import signal
import sys
from typing import List, Tuple

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.utils import subprocess_utils

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32",
        reason="the registry records nothing on Windows: see _RUNNING_GROUPS",
    ),
]

#: Outside any real pid range this test could collide with.
_FAKE_PGID = 2**30 + 43


class _ReapedLeader:
    """The group leader already reaped: poll answers its exit status."""

    pid = _FAKE_PGID
    returncode = 0

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def kill(self):
        raise AssertionError("a reaped leader is never signalled by pid")


class _GroupCalls:
    """Every killpg aimed at the fake group, answering as the kernel would."""

    def __init__(self) -> None:
        self.calls: List[Tuple[int, int]] = []
        self.alive = True
        self.refused = False

    def killpg(self, pgid: int, signum: int) -> None:
        self.calls.append((pgid, signum))
        if pgid != _FAKE_PGID or not self.alive:
            raise ProcessLookupError(f"group {pgid} is gone")
        if self.refused:
            raise PermissionError(f"group {pgid} holds another user's process")
        if signum == signal.SIGKILL:
            # The kernel ends the group; its id is released from here on.
            self.alive = False


def _no_process_holds(pid: int, signum: int) -> None:
    """kill(pid, 0) for a pid nobody holds: the reaped leader's pid is not reused."""
    raise ProcessLookupError(f"no process holds pid {pid}")


@pytest.fixture
def group(monkeypatch) -> _GroupCalls:
    calls = _GroupCalls()
    monkeypatch.setattr(subprocess_utils.os, "killpg", calls.killpg)
    monkeypatch.setattr(subprocess_utils.os, "kill", _no_process_holds)
    return calls


@pytest.fixture
def registered_leader():
    """A reaped fake leader registered the way a cancellable spawn's child is,
    forgotten again after the test whatever the product left behind."""
    leader = _ReapedLeader()
    subprocess_utils._register_group(leader)
    try:
        yield leader
    finally:
        with subprocess_utils._RUNNING_GROUPS_LOCK:
            if subprocess_utils._RUNNING_GROUPS.get(leader.pid) is leader:
                del subprocess_utils._RUNNING_GROUPS[leader.pid]
            subprocess_utils._STOPPING = False
        cancellation.discard_tool_group(leader.pid)


def test_a_reaped_leader_whose_group_still_runs_stays_recorded(
    group, registered_leader
):
    with subprocess_utils._RUNNING_GROUPS_LOCK:
        subprocess_utils._forget_exited_groups()
    assert subprocess_utils._RUNNING_GROUPS.get(_FAKE_PGID) is registered_leader, (
        "the leader was reaped but its group still answers killpg: forgetting "
        "it leaves the running tool with no entry a cancel or a timeout can signal"
    )
    assert _FAKE_PGID in cancellation._TOOL_GROUPS, (
        "the die-now mirror dropped a group that still runs; the SIGTERM "
        "handler would leave its members behind"
    )
    assert (_FAKE_PGID, 0) in group.calls, (
        "the reap path never asked the kernel whether the group is empty"
    )


def test_a_reaped_leader_whose_group_is_gone_is_forgotten(group, registered_leader):
    """The control: an emptied group is dropped from the registry and the mirror,
    so its released id is never signalled again."""
    group.alive = False
    with subprocess_utils._RUNNING_GROUPS_LOCK:
        subprocess_utils._forget_exited_groups()
    assert _FAKE_PGID not in subprocess_utils._RUNNING_GROUPS
    assert _FAKE_PGID not in cancellation._TOOL_GROUPS


def test_a_group_the_kernel_refuses_to_probe_is_kept_and_raises_nothing(
    group, registered_leader
):
    """EPERM on the probe means a member exists as another user: the group is
    kept, and the refusal never escapes the spawn that ran the reap."""
    group.refused = True
    with subprocess_utils._RUNNING_GROUPS_LOCK:
        subprocess_utils._forget_exited_groups()
    assert subprocess_utils._RUNNING_GROUPS.get(_FAKE_PGID) is registered_leader, (
        "a group this process may not signal still exists; forgetting it "
        "leaves its members with no entry"
    )
    assert _FAKE_PGID in cancellation._TOOL_GROUPS


def test_the_reap_asks_whether_the_group_survives(monkeypatch, registered_leader):
    """The probe is _group_survives, which reaps PID-1 zombie orphans first,
    rather than a bare existence read that a zombie-only group satisfies."""
    asked: List[int] = []

    def survives(pgid: int) -> bool:
        asked.append(pgid)
        return True

    monkeypatch.setattr(subprocess_utils, "_group_survives", survives)
    with subprocess_utils._RUNNING_GROUPS_LOCK:
        subprocess_utils._forget_exited_groups()
    assert asked == [_FAKE_PGID], (
        "the reap did not route its existence probe through _group_survives; "
        f"asked: {asked}"
    )
    assert subprocess_utils._RUNNING_GROUPS.get(_FAKE_PGID) is registered_leader


def test_a_reaped_leader_whose_pid_was_reused_is_forgotten(
    group, registered_leader, monkeypatch
):
    """A live process holds the reaped leader's pid again, so the group that still
    answers killpg may be a stranger's: the entry and the mirror are dropped, and
    nothing is ever aimed at that group."""
    monkeypatch.setattr(subprocess_utils, "_pid_names_a_live_process", lambda pid: True)
    with subprocess_utils._RUNNING_GROUPS_LOCK:
        subprocess_utils._forget_exited_groups()
    assert _FAKE_PGID not in subprocess_utils._RUNNING_GROUPS, (
        "the leader's pid is held by another live process, so its group id may "
        "be a stranger's; keeping the entry aims a later kill at that stranger"
    )
    assert _FAKE_PGID not in cancellation._TOOL_GROUPS
    killed = subprocess_utils.kill_running_groups()
    assert (_FAKE_PGID, signal.SIGKILL) not in group.calls, (
        f"a stranger's group was signalled: {group.calls}"
    )
    assert killed == 0


def test_kill_running_groups_signals_the_group_of_a_reaped_leader(
    group, registered_leader
):
    killed = subprocess_utils.kill_running_groups()
    assert (_FAKE_PGID, signal.SIGKILL) in group.calls, (
        "the server stop reaped the leader and then never signalled its "
        f"still-populated group; sent: {group.calls}"
    )
    assert killed == 1, f"the stop signalled the group but did not count it: {killed}"
