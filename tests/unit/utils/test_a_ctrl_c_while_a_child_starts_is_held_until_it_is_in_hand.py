# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A Ctrl-C that lands while a child starts is held until the spawn has the child.

A KeyboardInterrupt raised inside Popen, after the child exists and before Popen
returns it, left the spawn no process to stop: the child ran on with nobody to end
it. The sandboxed and cancellable runners start their child inside a
``HeldInterrupt`` block (``subprocess_utils.HeldInterrupt``), which records the
Ctrl-C and hands it to the previous handler from inside the handling that stops
the child, so the child is stopped by the path any other failure after the start
takes.

These cells read what each runner does with the child; no process is started and
no signal is sent. The stand-in for Popen delivers the Ctrl-C the way the
interpreter does, by calling the handler installed at that moment, and returns a
recorded stand-in child. The runners' stops are replaced by recorders. Four tests
read the hold itself: a release that cannot put the handler back leaves nothing
held, and hands a Ctrl-C that was held to the previous handler; leaving the
``with`` block puts the handler back after such a release, and after a body that
raised before any release.
"""

import os
import signal
import subprocess
import threading
from typing import Dict, List, Tuple

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

    pid = 2**30 + 1001
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

    def terminate(self) -> None:
        self.calls.append("terminate")

    def wait(self, timeout=None):
        self.calls.append("wait")
        return 0

    def communicate(self, *args, **kwargs):
        self.calls.append("communicate")
        return None, None


class _Stops:
    """What the runners' stops were asked to end, in order."""

    def __init__(self) -> None:
        self.stopped: List[Tuple[str, object]] = []
        #: The group registry as it stood each time the child was to be ended:
        #: after the reap it reads empty whether the group was recorded and
        #: forgotten or never recorded, so only this read tells the two apart.
        self.registered: List[Dict[int, object]] = []


@pytest.fixture
def stops(monkeypatch):
    """The stop of the paths under test replaced by a recorder, and a registry of
    their own, so no signal is sent and no other test's record is met. The count
    of spawns still starting is their own too, at zero: the cases compare it with
    its value at their start, and a path that kept its count would otherwise
    leave it raised for every later test."""
    recorded = _Stops()
    monkeypatch.setattr(subprocess_utils, "_RUNNING_GROUPS", {})
    monkeypatch.setattr(subprocess_utils, "_SPAWNS_STARTING", 0)

    def record_the_ending(args, process, how, grace, prompt) -> None:
        recorded.stopped.append((how.__name__, process))
        recorded.registered.append(dict(subprocess_utils._RUNNING_GROUPS))

    monkeypatch.setattr(subprocess_utils, "_stop_child", record_the_ending)
    # The stand-in child has no process, so the real question (os.getpgid on its
    # pid) could only fail, and a failure reads as "end the group as well"; the
    # path without a group of its own is pinned on a child that leads none.
    monkeypatch.setattr(subprocess_utils, "_leads_its_own_group", lambda process: False)
    return recorded


def _ctrl_c_arrives() -> None:
    """A Ctrl-C delivered as the interpreter delivers one: the handler installed
    now is called. Held, that handler records it; unheld, it raises."""
    signal.getsignal(signal.SIGINT)(signal.SIGINT, None)


def _popen_that_starts(monkeypatch, child: _Child, *, ctrl_c: bool) -> None:
    """Popen replaced by a stand-in that makes ``child``, with the Ctrl-C arriving
    after the child exists and before the stand-in returns it."""

    def started(*args, **kwargs):
        if ctrl_c:
            _ctrl_c_arrives()
        return child

    monkeypatch.setattr(subprocess, "Popen", started)


def test_run_stoppable_stops_a_child_whose_start_a_ctrl_c_interrupted(
    monkeypatch, default_sigint, stops
):
    child = _Child()
    _popen_that_starts(monkeypatch, child, ctrl_c=True)

    with pytest.raises(KeyboardInterrupt):
        subprocess_utils._run_stoppable(["tool"])

    assert child.calls[0] == "terminate", child.calls
    assert "communicate" not in child.calls, "the Ctrl-C was raised after the wait"
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


def test_run_cancellable_stops_a_child_whose_start_a_ctrl_c_interrupted(
    monkeypatch, default_sigint, stops
):
    child = _Child()
    _popen_that_starts(monkeypatch, child, ctrl_c=True)
    starting = subprocess_utils._SPAWNS_STARTING

    with pytest.raises(KeyboardInterrupt):
        subprocess_utils._run_cancellable(
            ["tool"],
            cancel_event=threading.Event(),
            graceful_timeout=False,
            own_group=True,
        )

    # The whole group, by the tree stop; the record the child was given before
    # the release is dropped by the reap.
    assert stops.stopped == [("_stop_tree", child)]
    assert stops.registered == [{child.pid: child}], "the group was not recorded"
    assert "communicate" not in child.calls, "the Ctrl-C was raised after the wait"
    assert subprocess_utils._RUNNING_GROUPS == {}
    assert subprocess_utils._SPAWNS_STARTING == starting, "the start count was kept"
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


def _run_cancellable_path():
    return subprocess_utils._run_cancellable(
        ["tool"],
        cancel_event=threading.Event(),
        graceful_timeout=False,
        own_group=True,
    )


#: The paths that start their child inside a HeldInterrupt block, each called the
#: way the cells above call it.
_PATHS = [
    pytest.param(lambda: subprocess_utils._run_stoppable(["tool"]), id="run_stoppable"),
    pytest.param(_run_cancellable_path, id="run_cancellable"),
]


@pytest.fixture
def records_the_spawn(monkeypatch):
    """The registry's record of the child replaced by one that keeps the count the
    way the real one does and sends no signal, for the paths that end normally."""

    def record(process):
        subprocess_utils._end_spawn()
        return subprocess_utils._SpawnRecord.GOES_ON

    monkeypatch.setattr(subprocess_utils, "_record_spawn", record)


@pytest.fixture
def restore_fails_once(monkeypatch):
    """``signal.signal`` as a recorded double: the first call that puts the
    previous handler back (``signal.default_int_handler``, the handler
    ``default_sigint`` installed) raises, every other call goes through, so a
    path that gains another ``signal.signal`` call before the restore still
    fails on the restore itself. Returns the record of the raise; the cells
    assert it fired. It sets only this test's own handler stack; no signal is
    sent to any process."""
    real_signal = signal.signal
    fired: List[object] = []

    def signal_failing_on_restore(signum, handler):
        if (
            signum == signal.SIGINT
            and handler is signal.default_int_handler
            and not fired
        ):
            fired.append(handler)
            raise OSError("the handler could not be set")
        return real_signal(signum, handler)

    monkeypatch.setattr(subprocess_utils.signal, "signal", signal_failing_on_restore)
    return fired


def test_a_release_that_cannot_put_the_handler_back_leaves_no_ctrl_c_held(
    default_sigint, restore_fails_once
):
    """A release whose restore fails raises with the recording handler still
    installed. Nothing after it may leave the hold, so a Ctrl-C that comes later
    has to reach the previous handler (here Python's own, which raises), the way
    it does after the ``with`` form is left (HeldInterrupt)."""
    held = subprocess_utils.HeldInterrupt().__enter__()

    with pytest.raises(OSError, match="could not be set"):
        held.release()

    assert restore_fails_once, "the failing restore was never reached"
    with pytest.raises(KeyboardInterrupt):
        _ctrl_c_arrives()


def test_a_release_that_cannot_put_the_handler_back_hands_over_a_held_ctrl_c(
    default_sigint, restore_fails_once
):
    """A Ctrl-C held before a failing release is not dropped with the restore: the
    previous handler gets it, and what it raises is chained from the failure. A
    Ctrl-C after that goes to the previous handler at once."""
    held = subprocess_utils.HeldInterrupt().__enter__()
    _ctrl_c_arrives()

    with pytest.raises(KeyboardInterrupt) as raised:
        held.release()

    assert isinstance(raised.value.__cause__, OSError)
    assert "could not be set" in str(raised.value.__cause__)
    assert restore_fails_once, "the failing restore was never reached"
    with pytest.raises(KeyboardInterrupt):
        _ctrl_c_arrives()


def test_a_handler_that_failed_to_go_back_is_put_back_on_leaving(
    default_sigint, restore_fails_once
):
    """The hold forgot it held the signal before putting the handler back, so a
    failure there left the recording handler in place, and every later Ctrl-C was
    swallowed. Leaving the ``with`` block puts it back: ``HeldInterrupt.__exit__``
    restores again after a release whose restore failed, and raises the failure."""
    with pytest.raises(OSError, match="could not be set"):
        with subprocess_utils.HeldInterrupt() as held:
            held.release()

    assert restore_fails_once, "the failing restore was never reached"
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
    with pytest.raises(KeyboardInterrupt):
        _ctrl_c_arrives()


def test_a_ctrl_c_after_the_block_whose_handler_did_not_go_back_is_not_lost(
    default_sigint, restore_fails_once
):
    """The block raised before release, and putting the handler back on leaving
    failed, so the recording handler stayed installed and every later Ctrl-C was
    recorded for a block that was over. Once the block is left, a Ctrl-C goes to
    the handler that was held."""
    with pytest.raises(OSError, match="could not be set"):
        with subprocess_utils.HeldInterrupt():
            raise FileNotFoundError("runtime")

    assert restore_fails_once, "the failing restore was never reached"
    with pytest.raises(KeyboardInterrupt):
        _ctrl_c_arrives()


def _stopped_by_terminate(child: _Child, stops: _Stops) -> None:
    assert "terminate" in child.calls, child.calls


def _stopped_as_a_group(child: _Child, stops: _Stops) -> None:
    assert stops.stopped == [("_stop_tree", child)]


def _stopped_alone(child: _Child, stops: _Stops) -> None:
    assert stops.stopped == [("_stop", child)]


def _run_cancellable_without_a_group():
    """The cancellable runner as a sandboxed spawn calls it: the child is not put
    in a group of its own (its wrapper calls setsid itself), and a child that leads
    none is stopped alone."""
    return subprocess_utils._run_cancellable(
        ["tool"],
        cancel_event=threading.Event(),
        graceful_timeout=False,
        own_group=False,
    )


#: Each path with the stop its failure handling owes the child, read the way the
#: Ctrl-C tests above read it. The hold and its release are the same block of
#: _run_cancellable with or without a group of the child's own; what own_group
#: changes is how the child is started and which ending it gets.
_PATHS_WITH_STOPS = [
    pytest.param(
        lambda: subprocess_utils._run_stoppable(["tool"]),
        _stopped_by_terminate,
        id="run_stoppable",
    ),
    pytest.param(_run_cancellable_path, _stopped_as_a_group, id="run_cancellable"),
    pytest.param(
        _run_cancellable_without_a_group,
        _stopped_alone,
        id="run_cancellable_without_a_group",
    ),
]


@pytest.mark.parametrize("path, stopped_the_child", _PATHS_WITH_STOPS)
def test_a_path_whose_release_fails_leaves_no_ctrl_c_held(
    path, stopped_the_child, default_sigint, monkeypatch, stops, restore_fails_once
):
    """Each path stops the child when its release fails and raises the failure.
    The previous handler is back on the way out (the hold is left even though
    its own restore failed), so a Ctrl-C after that is not held for a start that
    is over."""
    child = _Child()
    _popen_that_starts(monkeypatch, child, ctrl_c=False)

    with pytest.raises(OSError, match="could not be set"):
        path()

    assert restore_fails_once, "the failing restore was never reached"
    stopped_the_child(child, stops)

    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
    with pytest.raises(KeyboardInterrupt):
        _ctrl_c_arrives()


@pytest.mark.parametrize("path, stopped_the_child", _PATHS_WITH_STOPS)
def test_a_ctrl_c_held_while_a_release_fails_is_handed_over(
    path, stopped_the_child, default_sigint, monkeypatch, stops, restore_fails_once
):
    """A Ctrl-C held during Popen is not dropped when the release's restore
    fails: each path stops the child and raises KeyboardInterrupt, chained from
    the restore failure, the way a start with a working restore raises it."""
    child = _Child()
    _popen_that_starts(monkeypatch, child, ctrl_c=True)

    with pytest.raises(KeyboardInterrupt) as raised:
        path()

    assert isinstance(raised.value.__cause__, OSError)
    assert "could not be set" in str(raised.value.__cause__)
    assert restore_fails_once, "the failing restore was never reached"
    stopped_the_child(child, stops)


@pytest.mark.parametrize("path", _PATHS)
def test_a_path_without_a_ctrl_c_puts_the_handler_back_and_stops_nothing(
    path, default_sigint, monkeypatch, stops, records_the_spawn
):
    """The control for the cells above: the same stand-ins and no Ctrl-C. The child
    is not stopped, the start count is kept and the handler is back as it was."""
    child = _Child()
    _popen_that_starts(monkeypatch, child, ctrl_c=False)
    starting = subprocess_utils._SPAWNS_STARTING

    path()

    assert stops.stopped == []
    assert "kill" not in child.calls
    assert "terminate" not in child.calls
    assert "communicate" in child.calls
    assert subprocess_utils._SPAWNS_STARTING == starting, "the start count was kept"
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
