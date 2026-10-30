"""As PID 1, a group of zombies ends a tree stop's waits, not only its survivor read.

The survivor read after the SIGKILL in _stop_tree reaps the exited children this
process inherited as its container's init (_group_survives), so a group made only
of those reads as gone. The reads before it did not: the group read before the
SIGTERM, the grace wait and the settle after the kill still asked the kernel
alone, which keeps a group in existence while any zombie member remains. Every
graceful stop of a tool that had children therefore waited out the whole grace
(ten seconds for a sandboxed spawn) with nothing left to wait for.
"""

import contextlib
import os
import signal
import subprocess  # nosec B404 - the module under test wraps subprocess
import time
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt", reason="process groups are the POSIX arm of _stop_tree"
    ),
]

#: Outside any real pid range this test could collide with.
_NO_SUCH_PGID = 2**30 + 4242
#: A grace long enough that a wait running it out is told from one that ended.
_GRACE = 2.0


def _reaped_child(pid: int) -> MagicMock:
    process = MagicMock(spec=subprocess.Popen)
    process.pid = pid
    process.returncode = -9
    process.poll.return_value = -9
    return process


class _GroupOfZombies:
    """A group whose only members are exited children of this process."""

    def __init__(self, *pids: int) -> None:
        self.zombies = set(pids)
        self.sent = []

    def signal_group(self, pgid, signum):
        self.sent.append(signum)
        # The kernel keeps the group while any zombie remains.
        return bool(self.zombies)

    def orphans(self, pgid):
        return sorted(self.zombies)

    def reap(self, pid, options):
        self.zombies.discard(pid)
        return (pid, 9)

    def installed(self, stack: contextlib.ExitStack) -> None:
        """This process as PID 1 over this group, with no real signal sent."""
        for patcher in (
            patch.object(
                subprocess_utils, "_signal_group", side_effect=self.signal_group
            ),
            patch.object(subprocess_utils, "_this_process_is_init", return_value=True),
            patch.object(
                subprocess_utils, "_zombie_orphans_of_group", side_effect=self.orphans
            ),
            patch.object(subprocess_utils.os, "waitpid", side_effect=self.reap),
            patch.object(
                subprocess_utils, "_pid_names_a_live_process", return_value=False
            ),
        ):
            stack.enter_context(patcher)


def test_the_grace_wait_ends_once_the_group_holds_zombies_only():
    group = _GroupOfZombies(777)
    process = _reaped_child(_NO_SUCH_PGID)
    began = time.monotonic()
    with contextlib.ExitStack() as stack:
        group.installed(stack)
        subprocess_utils._wait_out_grace(process, _NO_SUCH_PGID, _GRACE)
    took = time.monotonic() - began
    assert group.zombies == set(), "the orphans were reaped by the wait's read"
    assert took < _GRACE / 2, f"the wait ran {took:.2f}s on a group of zombies"


def test_a_refused_stop_on_a_group_of_zombies_marks_nothing():
    """The mark after a refused stop is skipped when the child has exited and
    its group is gone; as PID 1 a group of zombies is gone too."""
    group = _GroupOfZombies(777)
    process = _reaped_child(_NO_SUCH_PGID)
    started = subprocess_utils._StartedChild()
    with contextlib.ExitStack() as stack:
        group.installed(stack)
        stack.enter_context(
            patch.object(subprocess_utils, "_has_exited", return_value=True)
        )
        with started.recording():
            started.process = process
            subprocess_utils._note_stop_refused(process)
    assert group.zombies == set()
    assert started.stop_refused is False


def test_a_refused_stop_on_a_group_with_a_live_member_marks_the_record():
    """The control for the test above: the same record and the same reads, with
    a member of the group still running, so the mark is set. Without it a
    False could as well mean the record was never found."""
    group = _GroupOfZombies()
    process = _reaped_child(_NO_SUCH_PGID)
    started = subprocess_utils._StartedChild()
    with contextlib.ExitStack() as stack:
        group.installed(stack)
        stack.enter_context(
            patch.object(subprocess_utils, "_has_exited", return_value=True)
        )
        # No orphan to reap and a group that still exists: a member lives.
        stack.enter_context(
            patch.object(subprocess_utils, "_group_exists", return_value=True)
        )
        with started.recording():
            started.process = process
            subprocess_utils._note_stop_refused(process)
    assert started.stop_refused is True


def test_the_servers_last_stop_settles_at_once_on_groups_of_zombies():
    """kill_running_groups waits for the groups it signalled to be gone; as PID 1
    a group left with nothing but zombies is gone once they are reaped."""
    group = _GroupOfZombies(777)
    process = MagicMock(spec=subprocess.Popen)
    process.pid = _NO_SUCH_PGID
    process.returncode = None
    process.poll.return_value = None
    began = time.monotonic()
    with contextlib.ExitStack() as stack:
        group.installed(stack)
        stack.enter_context(
            patch.object(subprocess_utils, "_RUNNING_GROUPS", {process.pid: process})
        )
        # The server's stop flag is set by the call; put back on the way out so
        # no later spawn reads the server as stopping. No spawn is starting:
        # the count is this test's, not whatever an earlier test left.
        stack.enter_context(patch.object(subprocess_utils, "_STOPPING", False))
        stack.enter_context(patch.object(subprocess_utils, "_SPAWNS_STARTING", 0))
        stack.enter_context(
            patch.object(subprocess_utils, "_leads_its_own_group", return_value=True)
        )
        stack.enter_context(
            patch.object(subprocess_utils, "_KILLED_GROUP_SETTLE_SECONDS", _GRACE)
        )
        signalled = subprocess_utils.kill_running_groups()
    took = time.monotonic() - began
    assert signalled == 1
    assert group.zombies == set()
    assert took < _GRACE / 2, f"the settle ran {took:.2f}s on a group of zombies"


def test_a_group_of_zombies_is_not_signalled_or_waited_out_before_the_kill():
    """The read before the SIGTERM already sees the group gone: nothing of ours is
    running, so no signal is sent and no grace is waited out."""
    group = _GroupOfZombies(777, 778)
    process = _reaped_child(_NO_SUCH_PGID)
    began = time.monotonic()
    with contextlib.ExitStack() as stack:
        group.installed(stack)
        refused = stack.enter_context(
            patch.object(subprocess_utils, "_note_stop_refused")
        )
        subprocess_utils._stop_tree(process, grace=_GRACE)
    took = time.monotonic() - began
    assert group.zombies == set()
    assert signal.SIGTERM not in group.sent, group.sent
    assert signal.SIGKILL not in group.sent, group.sent
    refused.assert_not_called()
    assert took < _GRACE / 2, f"the stop ran {took:.2f}s on a group of zombies"
