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
still SIGKILLs the group of a leader that was reaped before it ran.
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

    def killpg(self, pgid: int, signum: int) -> None:
        self.calls.append((pgid, signum))
        if pgid != _FAKE_PGID or not self.alive:
            raise ProcessLookupError(f"group {pgid} is gone")
        if signum == signal.SIGKILL:
            # The kernel ends the group; its id is released from here on.
            self.alive = False


@pytest.fixture
def group(monkeypatch) -> _GroupCalls:
    calls = _GroupCalls()
    monkeypatch.setattr(subprocess_utils.os, "killpg", calls.killpg)
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


def test_kill_running_groups_signals_the_group_of_a_reaped_leader(
    group, registered_leader
):
    killed = subprocess_utils.kill_running_groups()
    assert (_FAKE_PGID, signal.SIGKILL) in group.calls, (
        "the server stop reaped the leader and then never signalled its "
        f"still-populated group; sent: {group.calls}"
    )
    assert killed == 1, f"the stop signalled the group but did not count it: {killed}"
