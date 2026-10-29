# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A group that vanished before the SIGTERM is not killed at its released id.

_stop_tree reads the group once, SIGTERMs it, waits out the grace, and
SIGKILLs what is left. The group can vanish between that first read and the
SIGTERM -- the leader reaped earlier, its last member just reaped by init --
and the kernel then raises ESRCH and releases the id, which a new process
group can hold. The SIGKILL that follows would be aimed at whoever got the
id next, and the survivor check after it would read that stranger's group as
a stop that failed. When the SIGTERM finds the group gone and the child is
reaped, nothing of ours is left to kill or to read, so the stop ends there.

A gone group with the child NOT reaped is different: our own unreaped child
keeps the id ours (a zombie leader holds its group), so the kernel does not
hand it out, and the kill path must still run rather than leave the tree to
its grace.

The cells drive _stop_tree with the group calls recorded and the vanish
planted between the existence read and the SIGTERM, the window itself.
"""

from __future__ import annotations

import signal
import sys
from typing import List, Tuple

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32",
        reason="_stop_tree stops a Windows tree with taskkill, not process groups",
    ),
]

#: Outside any real pid range this test could collide with.
_FAKE_PGID = 2**30 + 41


class _ExitedChild:
    """The leader already reaped: poll answers its exit status."""

    pid = _FAKE_PGID

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0


class _UnreapedChild:
    """The leader still ours: poll answers None, a wait reaps nothing here."""

    pid = _FAKE_PGID

    def poll(self):
        return None

    def wait(self, timeout=None):
        return None


@pytest.fixture
def group_calls(monkeypatch) -> List[Tuple[int, int]]:
    """Every killpg aimed at the group, with the vanish planted after the
    first existence read: the read succeeds, everything after raises the
    kernel's gone-group answer."""
    calls: List[Tuple[int, int]] = []

    def killpg(pgid: int, signum: int) -> None:
        calls.append((pgid, signum))
        if len(calls) > 1:
            raise ProcessLookupError(f"group {pgid} is gone")

    monkeypatch.setattr(subprocess_utils.os, "killpg", killpg)
    return calls


def test_a_reaped_child_whose_group_vanished_is_not_group_killed(group_calls):
    subprocess_utils._stop_tree(_ExitedChild(), grace=1.0)
    signals = [signum for _, signum in group_calls]
    assert signal.SIGKILL not in signals, (
        "the SIGTERM found the group gone and the child reaped: the id is "
        "released, so this SIGKILL is aimed at whoever holds it next"
    )
    assert signals == [0, signal.SIGTERM], (
        "nothing of ours is left to kill or to read once the SIGTERM "
        f"found the group gone; sent: {signals}"
    )


def test_an_unreaped_child_still_reaches_the_kill_path(group_calls):
    """Our own unreaped child keeps the id ours, so the kill still runs."""
    subprocess_utils._stop_tree(_UnreapedChild(), grace=1.0)
    signals = [signum for _, signum in group_calls]
    assert signal.SIGKILL in signals, (
        "a gone-group SIGTERM with the child not reaped must still take the "
        f"kill path rather than leave the tree to its grace; sent: {signals}"
    )
