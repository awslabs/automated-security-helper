"""_stop_tree reads a child's exit status with a default, never by polling it.

The reused-pid check at the top of _stop_tree read ``process.returncode`` as an
attribute. The file's stand-in children carry ``poll`` and ``wait`` and nothing
else, as the rest of _stop_tree asks of them, so every tree stop of such a
stand-in raised AttributeError. A poll would be no replacement: it reaps a leader
whose exit was not yet observed, and the group its pid names would then read as
a stranger's while its orphans still run.
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

    ``poll`` answers an exit code, as it does for a child whose exit the kernel
    holds and nothing has reaped yet. The recorded exit status is still absent,
    so a check that reads the attribute sees no exit, while one that polls sees
    one, and the two can be told apart by whether the pid is probed."""

    def poll(self):
        return 0


def test_a_stand_in_without_the_exit_attribute_is_stopped_as_a_group(monkeypatch):
    sent = []

    def killpg(pgid, signum):
        sent.append(signum)

    monkeypatch.setattr(subprocess_utils.os, "killpg", killpg)
    monkeypatch.setattr(subprocess_utils, "_KILLED_GROUP_SETTLE_SECONDS", 0.0)
    child = _ChildWithPollAndWaitOnly()

    subprocess_utils._stop_tree(child, grace=0.0)

    assert signal.SIGKILL in sent, sent


def test_the_reused_pid_check_does_not_poll_the_child(monkeypatch):
    """The exit status is read as recorded: a poll would reap an unobserved
    leader before the group read that depends on it.

    The stand-in's poll answers an exit while its recorded status is absent, so
    a check that went back to polling would read the exit, probe the pid for
    reuse, and fail here; a stand-in whose poll answered None, the same value an
    unreaped child gives, could not tell the two reads apart."""
    monkeypatch.setattr(subprocess_utils.os, "killpg", lambda pgid, signum: None)
    monkeypatch.setattr(subprocess_utils, "_KILLED_GROUP_SETTLE_SECONDS", 0.0)
    probed = []
    monkeypatch.setattr(
        subprocess_utils,
        "_pid_names_a_live_process",
        lambda pid: probed.append(pid) or False,
    )
    child = _ChildAPollWouldReap()

    subprocess_utils._stop_tree(child, grace=0.0)

    assert probed == [], "a child whose exit is not recorded is not probed for reuse"
