# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancel whose stop the kernel refused says so, with the pid as data.

The container and Nix launchers stop their child through
``stop_after_interrupt`` when the scan's cancel event is set mid-wait. That
function answers False when the grace ran out and the kill was refused (EPERM:
a setuid program the tool became), so the child may still run. The cancel each
launcher raises then carries the ``(tool, pid)`` pair in ``could_not_stop``,
the data the exit line names survivors from, records the pair on the scan's
event, and ends its text with the one could-not-stop sentence. A stop that was
accepted keeps the plain cancel: no record, no sentence.

The stop is stood in for: a refused kill cannot be produced on purpose without
a setuid child. The stand-in ends the child itself so nothing outlives the
test, and answers as the real function would have after a refusal.

The cancel has to arrive while the child runs. Both launchers refuse to start
a child for a scan that is already cancelled (``raise_if_cancelled`` before
the spawn), so an event set before the call never reaches the stop at all. The
event is set from the launcher's own ``record_tool_pid`` call instead, which
runs the moment the child exists and before the wait that reads the event.
"""

from __future__ import annotations

import subprocess  # nosec B404 - the children are this test's own interpreter
import sys
from types import ModuleType

import pytest

import automated_security_helper.interactions.run_ash_container as container_launcher
import automated_security_helper.interactions.run_ash_nix as nix_launcher
from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
)
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

_SLEEPING_CHILD = [sys.executable, "-c", "import time; time.sleep(20.0)"]


def _cancelled_once_the_child_is_recorded(
    launcher: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> CancelEvent:
    """A cancel event that ``launcher`` sets itself when it records its child.

    The launcher's ``record_tool_pid`` still records the pid, so the stand-in
    stop's own discard finds the record it expects; the event is set right
    after, while the child runs and before the launcher's wait first reads it.
    """
    event = CancelEvent()
    record = launcher.record_tool_pid

    def record_then_cancel(pid: int) -> None:
        record(pid)
        event.set()

    monkeypatch.setattr(launcher, "record_tool_pid", record_then_cancel)
    return event


class _StandInStop:
    """Ends the child as a stop would, then answers ``stopped`` for it.

    Records the pid it was handed, so the assertions name the real child.
    """

    def __init__(self, stopped: bool) -> None:
        self.stopped = stopped
        self.pids: list[int] = []

    def __call__(self, process: "subprocess.Popen[str]", *args, **kwargs) -> bool:
        self.pids.append(process.pid)
        process.kill()
        process.wait()
        subprocess_utils.discard_tool_pid_once_exited(process)
        return self.stopped


def _sentence_for(referent: str, pid: int) -> str:
    return subprocess_utils.could_not_stop_sentence(f"{referent} (pid {pid})")


class TestTheContainerRuntimeCancel:
    def test_a_refused_kill_is_carried_and_recorded(self, monkeypatch):
        stop = _StandInStop(stopped=False)
        monkeypatch.setattr(container_launcher, "_stop_after_interrupt", stop)
        event = _cancelled_once_the_child_is_recorded(container_launcher, monkeypatch)

        with cancel_scope(event):
            with pytest.raises(ScanCancelled) as raised:
                container_launcher.run_cmd_direct(list(_SLEEPING_CHILD), check=False)

        (pid,) = stop.pids
        assert raised.value.could_not_stop == (("container runtime", pid),)
        assert event.could_not_stop_records() == (("container runtime", pid),)
        assert str(raised.value).endswith(_sentence_for("the container runtime", pid))

    def test_an_accepted_stop_keeps_the_plain_cancel(self, monkeypatch):
        """Control: the stop answered True, so nothing is carried or recorded."""
        stop = _StandInStop(stopped=True)
        monkeypatch.setattr(container_launcher, "_stop_after_interrupt", stop)
        event = _cancelled_once_the_child_is_recorded(container_launcher, monkeypatch)

        with cancel_scope(event):
            with pytest.raises(ScanCancelled) as raised:
                container_launcher.run_cmd_direct(list(_SLEEPING_CHILD), check=False)

        assert len(stop.pids) == 1
        assert raised.value.could_not_stop == ()
        assert event.could_not_stop_records() == ()
        assert str(raised.value) == (
            "the scan was cancelled while the container runtime ran"
        )


class TestTheNixShellCancel:
    def test_a_refused_kill_is_carried_and_recorded(self, monkeypatch):
        stop = _StandInStop(stopped=False)
        monkeypatch.setattr(nix_launcher, "stop_after_interrupt", stop)
        event = _cancelled_once_the_child_is_recorded(nix_launcher, monkeypatch)

        with cancel_scope(event):
            with pytest.raises(ScanCancelled) as raised:
                nix_launcher._enter_shell(list(_SLEEPING_CHILD), env={})

        (pid,) = stop.pids
        assert raised.value.could_not_stop == (("nix", pid),)
        assert event.could_not_stop_records() == (("nix", pid),)
        assert str(raised.value).endswith(_sentence_for("the Nix shell", pid))

    def test_an_accepted_stop_keeps_the_plain_cancel(self, monkeypatch):
        """Control: the stop answered True, so nothing is carried or recorded."""
        stop = _StandInStop(stopped=True)
        monkeypatch.setattr(nix_launcher, "stop_after_interrupt", stop)
        event = _cancelled_once_the_child_is_recorded(nix_launcher, monkeypatch)

        with cancel_scope(event):
            with pytest.raises(ScanCancelled) as raised:
                nix_launcher._enter_shell(list(_SLEEPING_CHILD), env={})

        assert len(stop.pids) == 1
        assert raised.value.could_not_stop == ()
        assert event.could_not_stop_records() == ()
        assert str(raised.value) == "the scan was cancelled while the Nix shell ran"
