# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tree stop of a reaped child never signals a group whose id another process took.

_stop_tree signals the process group named by the child's pid. An own_group
spawn reaches it with the child already reaped when the wait ended after
communicate returned, and the group that pid names can by then belong to a
stranger who got the id once the child's own group was gone. POSIX keeps a pid
from reuse only while it names a live group, so a live process holding the pid
of a reaped child means the id was reused.

Every group read in _stop_tree goes through the zombie-aware ``_group_survives``,
so every test here patches that seam and ``_wait_after_kill``: nothing reads the
host's own process table, whatever pid 4242 is on the machine the tests run on.
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


def _child(returncode):
    process = MagicMock(spec=subprocess.Popen)
    process.pid = 4242
    process.returncode = returncode
    process.poll.return_value = returncode
    return process


@skip_on_windows
def test_a_reaped_child_whose_pid_a_live_process_holds_is_not_signalled():
    """The pid was consulted, found live, and the group it names was left alone:
    no signal, and no "could not stop" note either, since nothing of ours is
    running under that id."""
    process = _child(0)
    with (
        patch.object(
            subprocess_utils, "_pid_names_a_live_process", return_value=True
        ) as live,
        patch.object(subprocess_utils, "_group_survives", return_value=True),
        patch.object(subprocess_utils, "_wait_after_kill"),
        patch.object(subprocess_utils, "_signal_group") as signal_group,
        patch.object(subprocess_utils, "_note_stop_refused") as refused,
    ):
        subprocess_utils._stop_tree(process, grace=0)
    live.assert_called_once_with(4242)
    signal_group.assert_not_called()
    refused.assert_not_called()


@skip_on_windows
def test_a_reaped_child_whose_group_outlives_it_is_still_stopped():
    """No process holds the pid, so the group that exists is the child's own orphans.

    The first ``_group_survives`` read, before the kill, finds the orphans' group;
    the read after the kill finds it gone. A group read as gone before the kill is
    nothing to signal.
    """
    process = _child(0)
    with (
        patch.object(subprocess_utils, "_pid_names_a_live_process", return_value=False),
        patch.object(subprocess_utils, "_signal_group", return_value=False) as sg,
        patch.object(subprocess_utils, "_wait_after_kill"),
        patch.object(subprocess_utils, "_group_survives", side_effect=[True, False]),
    ):
        subprocess_utils._stop_tree(process, grace=0)
    sg.assert_called_once_with(4242, signal.SIGKILL)


@skip_on_windows
def test_an_unreaped_child_is_stopped_without_asking_about_its_pid():
    """An unreaped child still holds its pid, so the group it names is its own: the
    pre-kill ``_group_survives`` read finds it, the post-kill read finds it gone."""
    process = _child(None)
    with (
        patch.object(subprocess_utils, "_pid_names_a_live_process") as live,
        patch.object(subprocess_utils, "_signal_group", return_value=False) as sg,
        patch.object(subprocess_utils, "_wait_after_kill"),
        patch.object(subprocess_utils, "_group_survives", side_effect=[True, False]),
    ):
        subprocess_utils._stop_tree(process, grace=0)
    live.assert_not_called()
    sg.assert_called_once_with(4242, signal.SIGKILL)


@skip_on_windows
def test_pid_liveness_reads_kill_zero():
    """The liveness read is ``kill(pid, 0)`` and nothing else: a read that sent a
    real signal would signal the stranger this module exists to protect, and the
    three answers below would still come back the same."""
    with patch.object(
        subprocess_utils.os, "kill", side_effect=ProcessLookupError
    ) as kill:
        assert subprocess_utils._pid_names_a_live_process(4242) is False
    kill.assert_called_once_with(4242, 0)
    with patch.object(subprocess_utils.os, "kill", side_effect=PermissionError) as kill:
        assert subprocess_utils._pid_names_a_live_process(4242) is True
    kill.assert_called_once_with(4242, 0)
    with patch.object(subprocess_utils.os, "kill", return_value=None) as kill:
        assert subprocess_utils._pid_names_a_live_process(4242) is True
    kill.assert_called_once_with(4242, 0)
