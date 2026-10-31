"""_stop_tree reads a child's exit status with a default, never by polling it.

The reused-pid check at the top of _stop_tree read ``process.returncode`` as an
attribute. The file's stand-in children carry ``poll`` and ``wait`` and nothing
else, as the rest of _stop_tree asks of them, so every tree stop of such a
stand-in raised AttributeError. A poll would be no replacement: it reaps a leader
whose exit was not yet observed, and the group its pid names would then read as
a stranger's while its orphans still run.

Every group read and wait that ending a tree makes is replaced here, as in the
sibling test modules, so nothing reads the host's process table and the branch
taken does not depend on what the host happens to be running.
"""

import os
import signal

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="process groups are the POSIX arm"),
]

#: Outside any real pid range this test could collide with.
_FAKE_PGID = 2**30 + 43


class _ChildWithPollAndWaitOnly:
    """A stand-in with the two reads the stop paths make, and no exit attribute."""

    pid = _FAKE_PGID

    def poll(self):
        return None

    def wait(self, timeout=None):
        return None


class _ChildAPollWouldReap(_ChildWithPollAndWaitOnly):
    """A leader whose exit a poll would observe, with no exit attribute recorded.

    ``poll`` answers an exit code and records it, as ``Popen.poll`` does for a
    child whose exit the kernel holds and nothing has reaped yet. Until then the
    recorded exit status is absent, so a check that reads the attribute sees no
    exit, while one that polls, first or just before it reads the attribute,
    sees one, and the two can be told apart by whether the pid is probed."""

    def poll(self):
        self.returncode = 0
        return self.returncode


@pytest.fixture
def group_signals(monkeypatch):
    """The group signal, the group read and the wait after a kill replaced.

    Returns the ``(pgid, signum)`` pairs sent. The group reads as present until
    the SIGKILL has been sent and as gone after it, so the answer follows what
    was done to the group instead of a fixed count of reads."""
    sent = []

    def signal_group(pgid, signum):
        sent.append((pgid, signum))
        return True

    monkeypatch.setattr(subprocess_utils, "_signal_group", signal_group)
    monkeypatch.setattr(
        subprocess_utils,
        "_group_survives",
        lambda pgid: (pgid, signal.SIGKILL) not in sent,
    )
    monkeypatch.setattr(subprocess_utils, "_wait_after_kill", lambda process: None)
    monkeypatch.setattr(subprocess_utils, "_KILLED_GROUP_SETTLE_SECONDS", 0.0)
    return sent


def test_a_stand_in_without_the_exit_attribute_is_stopped_as_a_group(group_signals):
    child = _ChildWithPollAndWaitOnly()

    subprocess_utils._stop_tree(child, grace=0.0)

    assert (_FAKE_PGID, signal.SIGKILL) in group_signals, group_signals


def test_the_reused_pid_check_does_not_poll_the_child(monkeypatch, group_signals):
    """The exit status is read as recorded: a poll would reap an unobserved
    leader before the group read that depends on it.

    The stand-in's poll answers an exit, and records it, while its recorded
    status is absent. A check that went back to polling would read the exit,
    probe the pid for reuse, and fail here, whether it polled in place of the
    attribute read or just ahead of it; a stand-in whose poll answered None, the
    same value an unreaped child gives, could not tell the two reads apart. The
    group is still signalled: SIGKILL reached the fake group id."""
    probed = []
    monkeypatch.setattr(
        subprocess_utils,
        "_pid_names_a_live_process",
        lambda pid: probed.append(pid) or False,
    )
    child = _ChildAPollWouldReap()

    subprocess_utils._stop_tree(child, grace=0.0)

    assert probed == [], "a child whose exit is not recorded is not probed for reuse"
    assert not hasattr(child, "returncode"), "the child was polled"
    assert (_FAKE_PGID, signal.SIGKILL) in group_signals, group_signals
