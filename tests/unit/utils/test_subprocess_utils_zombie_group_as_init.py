"""A killed tool whose children fell to ASH as unreaped zombies is not a survivor.

``killpg(pgid, 0)`` succeeds while any member of the group exists, a zombie
included. When ASH is PID 1 in its own container, a killed tool's children are
re-parented to it and nothing else reaps them, so the survivor read after the
SIGKILL in _stop_tree kept seeing the group and recorded every stop of a tool
that had children as one ASH could not stop.
"""

import os
import signal
import subprocess  # nosec B404 - the module under test wraps subprocess
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

skip_on_windows = pytest.mark.skipif(
    os.name == "nt", reason="process groups are the POSIX arm of _stop_tree"
)

#: Outside any real pid range: _stop_tree probes the child's pid for reuse with
#: a real kill(pid, 0), and a small number can name a process on the test host.
_NO_SUCH_PID = 2**30 + 4242


def _reaped_child(pid: int) -> MagicMock:
    process = MagicMock(spec=subprocess.Popen)
    process.pid = pid
    process.returncode = -9
    process.poll.return_value = -9
    return process


@skip_on_windows
def test_as_init_the_zombie_orphans_of_the_group_are_reaped_by_pid():
    zombies = {777, 778}

    def exists(pgid):
        return bool(zombies)

    def reap(pid, options):
        zombies.discard(pid)
        return (pid, 9)

    with (
        patch.object(subprocess_utils, "_this_process_is_init", return_value=True),
        patch.object(
            subprocess_utils, "_zombie_orphans_of_group", return_value=[777, 778]
        ) as orphans,
        patch.object(subprocess_utils, "_group_exists", side_effect=exists),
        patch.object(subprocess_utils.os, "waitpid", side_effect=reap) as waitpid,
    ):
        assert subprocess_utils._group_survives(_NO_SUCH_PID) is False
    orphans.assert_called_once_with(_NO_SUCH_PID)
    assert waitpid.call_count == 2
    waitpid.assert_any_call(777, os.WNOHANG)
    waitpid.assert_any_call(778, os.WNOHANG)


@skip_on_windows
def test_a_zombie_another_thread_reaped_first_leaves_the_others_to_be_reaped():
    """Something else (a SIGCHLD handler, another thread's wait) reaps orphan 777
    between the scan of /proc and this call, so the waitpid for it raises
    ChildProcessError. The race is handled: the next orphan is still reaped, and
    the answer is the group read's own."""
    zombies = {777, 778}

    def exists(pgid):
        return bool(zombies)

    def reap(pid, options):
        zombies.discard(pid)
        if pid == 777:
            raise ChildProcessError(10, "No child processes")
        return (pid, 9)

    with (
        patch.object(subprocess_utils, "_this_process_is_init", return_value=True),
        patch.object(
            subprocess_utils, "_zombie_orphans_of_group", return_value=[777, 778]
        ),
        patch.object(subprocess_utils, "_group_exists", side_effect=exists),
        patch.object(subprocess_utils.os, "waitpid", side_effect=reap) as waitpid,
    ):
        assert subprocess_utils._group_survives(_NO_SUCH_PID) is False
    waitpid.assert_any_call(777, os.WNOHANG)
    waitpid.assert_any_call(778, os.WNOHANG)
    assert zombies == set(), "the orphan after the raced one was not reaped"


@skip_on_windows
def test_not_as_init_nothing_is_reaped_and_the_group_read_stands():
    with (
        patch.object(subprocess_utils, "_this_process_is_init", return_value=False),
        patch.object(subprocess_utils, "_zombie_orphans_of_group") as orphans,
        patch.object(subprocess_utils, "_group_exists", return_value=True),
        patch.object(subprocess_utils.os, "waitpid") as waitpid,
    ):
        assert subprocess_utils._group_survives(_NO_SUCH_PID) is True
    orphans.assert_not_called()
    waitpid.assert_not_called()


@skip_on_windows
def test_a_killed_group_of_zombies_is_not_recorded_as_a_refused_stop():
    """At the base the group of zombies kept existing and _note_stop_refused ran.

    A member is still running when the stop begins, so the read before the
    kill finds the group and the SIGKILL is sent; the kill leaves behind the
    exited child this process, as init, has yet to reap, and it is that
    survivor read after the kill that this test exercises."""
    process = _reaped_child(_NO_SUCH_PID)
    zombies: set = set()
    alive = [True]
    sent = []

    def group_signal(pgid, signum):
        if signum == signal.SIGKILL:
            # The kill ends the live member; what it leaves is a zombie child
            # of this process until something reaps it.
            sent.append(signum)
            alive[0] = False
            zombies.add(777)
            return True
        if signum != 0:
            sent.append(signum)
        # The existence probe (signal 0) sees the group while a member lives
        # or an exited one is unreaped.
        return alive[0] or bool(zombies)

    def reap(pid, options):
        zombies.discard(pid)
        return (pid, 9)

    with (
        patch.object(subprocess_utils, "_signal_group", side_effect=group_signal),
        patch.object(subprocess_utils, "_wait_after_kill"),
        patch.object(subprocess_utils, "_this_process_is_init", return_value=True),
        patch.object(
            subprocess_utils,
            "_zombie_orphans_of_group",
            side_effect=lambda pgid: sorted(zombies),
        ),
        patch.object(subprocess_utils.os, "waitpid", side_effect=reap),
        patch.object(subprocess_utils, "_note_stop_refused") as refused,
    ):
        subprocess_utils._stop_tree(process, grace=0)
    assert sent == [signal.SIGKILL], sent
    refused.assert_not_called()
    assert zombies == set(), "the survivor read after the kill reaped the orphan"


@skip_on_windows
def test_a_live_member_after_the_kill_is_still_recorded_as_a_refused_stop():
    process = _reaped_child(_NO_SUCH_PID)
    with (
        patch.object(subprocess_utils, "_signal_group", return_value=True),
        patch.object(subprocess_utils, "_wait_after_kill"),
        patch.object(subprocess_utils, "_this_process_is_init", return_value=True),
        patch.object(subprocess_utils, "_zombie_orphans_of_group", return_value=[]),
        patch.object(subprocess_utils, "_KILLED_GROUP_SETTLE_SECONDS", 0.0),
        patch.object(subprocess_utils, "_note_stop_refused") as refused,
    ):
        subprocess_utils._stop_tree(process, grace=0)
    refused.assert_called_once_with(process)


@skip_on_windows
def test_zombie_orphans_are_read_from_proc_stat_after_the_command_name(tmp_path):
    me = os.getpid()
    proc = tmp_path / "proc"
    for pid, stat in {
        "777": f"777 (a (tool) name) Z {me} 4242 4242 0 -1 0 0 0\n",
        "778": f"778 (sleeping) S {me} 4242 4242 0 -1 0 0 0\n",
        "779": f"779 (other parent) Z {me + 1} 4242 4242 0 -1 0 0 0\n",
        "780": f"780 (other group) Z {me} 4243 4243 0 -1 0 0 0\n",
        # The leader: our own exited child, whose status belongs to its Popen.
        "4242": f"4242 (the tool) Z {me} 4242 4242 0 -1 0 0 0\n",
    }.items():
        (proc / pid).mkdir(parents=True)
        (proc / pid / "stat").write_text(stat)
    (proc / "self").mkdir()
    real_listdir = os.listdir
    real_open = open

    def listdir(path):
        return real_listdir(proc) if path == "/proc" else real_listdir(path)

    def open_under_tmp(path, *args, **kwargs):
        if isinstance(path, str) and path.startswith("/proc/"):
            path = str(proc / path[len("/proc/") :])
        return real_open(path, *args, **kwargs)

    with (
        patch.object(subprocess_utils.os, "listdir", side_effect=listdir),
        patch("builtins.open", side_effect=open_under_tmp),
    ):
        assert subprocess_utils._zombie_orphans_of_group(4242) == [777]
