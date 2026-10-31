"""The plain runner holds a Ctrl-C while its child starts, as the other runners do.

A KeyboardInterrupt raised inside Popen, after the child exists and before Popen
returns it, left the plain runner no process to stop. With a timeout the child
leads a session of its own, so the terminal's Ctrl-C never reached it either: it
ran on, orphaned. The sandboxed and cancellable runners start their child inside
a HeldInterrupt block and release the hold once the start is noted, inside the
handling that stops the child; the plain runner now does the same.

No process is started and no signal is sent: the stand-in for Popen delivers the
Ctrl-C the way the interpreter does, by calling the handler installed at that
moment, and the stop is replaced by a recorder.
"""

import os
import signal
import subprocess  # nosec B404 - the module under test wraps subprocess
from typing import List, Tuple

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="a SIGINT handler is POSIX"),
]


@pytest.fixture
def default_sigint():
    """SIGINT handled as Python handles it by default, then put back as it was."""
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    yield
    signal.signal(signal.SIGINT, previous)


class _Child:
    """A recorded stand-in for a started child. It has no process behind it."""

    pid = 2**30 + 1002
    returncode = None
    args = ["tool"]
    stdin = None
    stdout = None
    stderr = None

    def __init__(self) -> None:
        self.calls: List[str] = []

    def poll(self):
        return None

    def kill(self) -> None:
        self.calls.append("kill")

    def wait(self, timeout=None):
        self.calls.append("wait")
        return 0

    def communicate(self, *args, **kwargs):
        self.calls.append("communicate")
        return None, None


@pytest.fixture
def stops(monkeypatch) -> List[Tuple[str, object]]:
    """The runner's stop replaced by a recorder, and a group registry of its own.

    The registration itself runs: the Ctrl-C-during-Popen path is where a
    record could be left behind for a later shutdown sweep to signal, so each
    case reads the registry afterwards. The registry is this test's, so no
    other test's record is met and none of ours is left for one. So is the
    count of spawns still starting: a Ctrl-C path that kept its count would
    otherwise leave it raised for every later test, and the case reads it."""
    recorded: List[Tuple[str, object]] = []
    monkeypatch.setattr(subprocess_utils, "_SPAWNS_STARTING", 0)
    monkeypatch.setattr(
        subprocess_utils,
        "_stop_child",
        lambda args, process, stop, grace, prompt: recorded.append(
            (stop.__name__, process)
        ),
    )
    monkeypatch.setattr(subprocess_utils, "_RUNNING_GROUPS", {})
    return recorded


def _ctrl_c_arrives() -> None:
    """A Ctrl-C delivered as the interpreter delivers one: the handler installed
    now is called. Held, that handler records it; unheld, it raises."""
    signal.getsignal(signal.SIGINT)(signal.SIGINT, None)


def _popen_that_starts(monkeypatch, child: _Child, *, ctrl_c: bool) -> None:
    def started(*args, **kwargs):
        if ctrl_c:
            _ctrl_c_arrives()
        return child

    monkeypatch.setattr(subprocess, "Popen", started)


def test_a_ctrl_c_during_popen_stops_the_child_the_timeout_put_in_its_own_group(
    monkeypatch, default_sigint, stops
):
    child = _Child()
    _popen_that_starts(monkeypatch, child, ctrl_c=True)

    with pytest.raises(KeyboardInterrupt):
        subprocess_utils._run_plain(["tool"], timeout=5)

    assert stops == [("_stop_tree", child)], stops
    assert "communicate" not in child.calls, "the Ctrl-C was raised after the wait"
    # The group the timeout registered is forgotten by the reap: nothing is
    # left for the server's last stop to signal under this pid.
    assert subprocess_utils._RUNNING_GROUPS == {}
    assert subprocess_utils._SPAWNS_STARTING == 0, "the start count was kept"
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


def test_a_ctrl_c_during_popen_kills_a_child_in_the_runners_own_group(
    monkeypatch, default_sigint, stops
):
    """Without a timeout the child shares the session; it is still stopped by
    the failure handling instead of being left behind by a raise inside Popen."""
    child = _Child()
    _popen_that_starts(monkeypatch, child, ctrl_c=True)
    monkeypatch.setattr(subprocess_utils, "_leads_its_own_group", lambda p: False)

    with pytest.raises(KeyboardInterrupt):
        subprocess_utils._run_plain(["tool"])

    assert stops == [("_kill", child)], stops
    assert "communicate" not in child.calls
    assert subprocess_utils._RUNNING_GROUPS == {}, "no group to register, none kept"
    assert subprocess_utils._SPAWNS_STARTING == 0, "a spawn outside a group was counted"


def test_without_a_ctrl_c_the_handler_is_put_back_and_nothing_is_stopped(
    monkeypatch, default_sigint, stops
):
    child = _Child()
    _popen_that_starts(monkeypatch, child, ctrl_c=False)

    subprocess_utils._run_plain(["tool"], timeout=5)

    assert stops == []
    assert "communicate" in child.calls
    assert subprocess_utils._RUNNING_GROUPS == {}, "the reap forgets the group"
    assert subprocess_utils._SPAWNS_STARTING == 0, "the record gave the count up"
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
