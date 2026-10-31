# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A Ctrl-C during a tree stop's grace reads the group before the kill it brings.

The grace arm of _stop_tree sends a SIGKILL to the group when an interrupt ends
the wait, so the tool is not left SIGTERMed only. The wait polls the leader on
every pass, so the leader can be reaped and its group emptied during a sleep;
the id is then the kernel's to reuse, and a kill aimed at it would reach whoever
holds the id next. The arm now reads the group before the kill, as the guard
below the wait does, and a group gone with its leader reaped is not signalled.
The interrupt is re-raised either way, and through _stop_child, whose OSError
arm would read a refusal raised in its place as a stop that worked.

No process is started and no signal is sent: the group signal, the group reads
and the wait are stood in for.
"""

import os
import signal
import subprocess  # nosec B404 - the module under test wraps subprocess
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="process groups are the POSIX arm"),
]

#: Outside any real pid range this test could collide with.
_NO_SUCH_PID = 2**30 + 4345


def _running_child() -> MagicMock:
    process = MagicMock(spec=subprocess.Popen)
    process.pid = _NO_SUCH_PID
    process.returncode = None
    process.poll.return_value = None
    # Set on a real Popen in __init__, not on the class, so a spec'd mock lacks
    # it; the refusal's WARNING names the program through it.
    process.args = ["tool"]
    return process


def _interrupt_ends_the_wait(*args, **kwargs):
    raise KeyboardInterrupt


def test_a_group_emptied_during_the_wait_gets_no_kill_at_the_interrupt():
    """The wait reaped the leader and its last member went before the Ctrl-C:
    the id is the kernel's to reuse, so nothing is aimed at it."""
    process = _running_child()
    sent: List[int] = []
    # The group's membership is its own state, not the leader's: the wait below
    # reaps the leader and empties the group, and every read answers from that
    # state however many the code makes. An iterator of two answers tied the
    # test to exactly two reads, and a third raised StopIteration inside the
    # code under test.
    group = {"has_members": True}

    def wait_reaps_then_the_interrupt_lands(*args, **kwargs):
        process.returncode = 0
        process.poll.return_value = 0
        group["has_members"] = False
        raise KeyboardInterrupt

    with (
        patch.object(
            subprocess_utils,
            "_group_survives",
            side_effect=lambda pgid: group["has_members"],
        ),
        patch.object(
            subprocess_utils,
            "_signal_group",
            side_effect=lambda pgid, signum: sent.append(signum) or True,
        ),
        patch.object(
            subprocess_utils,
            "_wait_out_grace",
            side_effect=wait_reaps_then_the_interrupt_lands,
        ),
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._stop_tree(process, grace=1.0)
    assert sent == [signal.SIGTERM], sent


def test_the_control_a_group_still_there_at_the_interrupt_is_killed():
    """A leader not reaped, or a group with members left: the kill is sent, and
    a kill the kernel accepts marks nothing."""
    process = _running_child()
    sent: List[int] = []
    with (
        patch.object(subprocess_utils, "_group_survives", return_value=True),
        patch.object(
            subprocess_utils,
            "_signal_group",
            side_effect=lambda pgid, signum: sent.append(signum) or True,
        ),
        patch.object(
            subprocess_utils, "_wait_out_grace", side_effect=_interrupt_ends_the_wait
        ),
        patch.object(subprocess_utils, "_note_stop_refused") as refused,
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._stop_tree(process, grace=1.0)
    assert sent == [signal.SIGTERM, signal.SIGKILL], sent
    refused.assert_not_called()


def test_a_reaped_leader_whose_group_survives_is_still_killed_at_the_interrupt():
    """The wait reaped the leader, but members it started are still there: the
    group id is still ours, and the kill reaches them."""
    process = _running_child()
    sent: List[int] = []

    def wait_reaps_then_the_interrupt_lands(*args, **kwargs):
        process.returncode = 0
        process.poll.return_value = 0
        raise KeyboardInterrupt

    with (
        patch.object(subprocess_utils, "_group_survives", return_value=True),
        patch.object(
            subprocess_utils,
            "_signal_group",
            side_effect=lambda pgid, signum: sent.append(signum) or True,
        ),
        patch.object(
            subprocess_utils,
            "_wait_out_grace",
            side_effect=wait_reaps_then_the_interrupt_lands,
        ),
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._stop_tree(process, grace=1.0)
    assert sent == [signal.SIGTERM, signal.SIGKILL], sent


def test_through_stop_child_the_interrupt_is_not_read_as_a_stop_that_worked():
    """The caller's arm: _stop_child catches OSError and returns, so a
    PermissionError raised in the interrupt's place read as a finished stop.
    The refused kill is noted and the interrupt is what reaches the caller."""
    process = _running_child()
    process.kill.side_effect = PermissionError(1, "Operation not permitted")
    with (
        patch.object(
            subprocess_utils, "_wait_out_grace", side_effect=_interrupt_ends_the_wait
        ),
        patch.object(subprocess_utils, "_note_stop_refused") as refused,
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._stop_child(
                ["tool"], process, subprocess_utils._stop, 1.0, None
            )
    refused.assert_called_once_with(process)
