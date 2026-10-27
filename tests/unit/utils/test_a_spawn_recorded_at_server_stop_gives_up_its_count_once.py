# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancellable spawn gives up its starting count exactly once, and a kill the
kernel refuses at the server's stop stays a cancel.

kill_running_groups waits for ``_SPAWNS_STARTING`` to reach 0 before it reads
the recorded groups. _record_spawn gives the count up under its lock and, when
the server is stopping, kills the child itself; the kernel can refuse that kill
(EPERM on a setuid child, say). A refusal that escaped as the raw error gave
the count up a second time in the failure handling -- the counter went
negative, and a kill_running_groups running concurrently could stop waiting
while another spawn was still starting -- and ended the spawn as a bare
PermissionError instead of the ScanCancelled the module promises for a child
killed at the server's stop. The refusal is handled where it happens: logged,
and the spawn ends as the cancel, with the child left recorded for
kill_running_groups. The one window left is an exception delivered at the
record's call itself, which can only leave the count held, never give it up
twice.
"""

import contextlib
import logging
import os
import signal
import subprocess
import sys
import threading

import pytest

from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.utils import subprocess_utils


pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="EPERM on a group kill is POSIX's case"
)

#: Exits by itself, so a child the refused kill left is not waited on for long.
_SLEEPS_BRIEFLY = (sys.executable, "-c", "import time; time.sleep(5)")


def _the_server_stops_after_popen(monkeypatch):
    """The server's stop lands in the window between _begin_spawn's check and
    _record_spawn's read: kill_running_groups's own plain store, set once the
    child exists."""
    real_popen = subprocess.Popen

    def popen_after_which_the_server_is_stopping(args, **kwargs):
        process = real_popen(args, **kwargs)
        subprocess_utils._STOPPING = True
        return process

    monkeypatch.setattr(subprocess, "Popen", popen_after_which_the_server_is_stopping)


def _the_kernel_refuses_the_first_kill(monkeypatch):
    real_signal_group = subprocess_utils._signal_group
    refused = []

    def refusing(pgid, signum):
        if not refused and signum == signal.SIGKILL:
            refused.append(pgid)
            raise PermissionError(1, "Operation not permitted")
        return real_signal_group(pgid, signum)

    monkeypatch.setattr(subprocess_utils, "_signal_group", refusing)
    return refused


def test_a_kill_refused_at_the_servers_stop_is_a_cancel_counted_once(
    monkeypatch, caplog
):
    """The server starts stopping between _begin_spawn and _record_spawn, and the
    kernel refuses _record_spawn's own kill. The refusal is handled where it
    happens, as the stops handle it: logged, and the spawn ends as the
    ScanCancelled a child killed at the server's stop is promised, never as the
    kernel's raw error -- which also gave the starting count up a second time
    and sent the counter negative, where kill_running_groups' settle wait can
    end while another spawn is still starting."""
    count_before = subprocess_utils._SPAWNS_STARTING
    # The refused kill waits out the bounded reap; cut it so the cell does not
    # spend the full production wait on a child it is about to give back.
    monkeypatch.setattr(subprocess_utils, "_REAP_SECONDS", 0.2)
    _the_server_stops_after_popen(monkeypatch)
    refused = _the_kernel_refuses_the_first_kill(monkeypatch)

    count_after = None
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(ScanCancelled, match="the server is stopping"):
                subprocess_utils._run_cancellable(
                    list(_SLEEPS_BRIEFLY),
                    cancel_event=threading.Event(),
                    graceful_timeout=False,
                    own_group=True,
                    capture_output=True,
                )
        count_after = subprocess_utils._SPAWNS_STARTING
    finally:
        subprocess_utils._STOPPING = False
        subprocess_utils._SPAWNS_STARTING = count_before

    assert refused, "the cell shows nothing: _record_spawn's kill was never refused"
    assert count_after == count_before, (
        "the spawn's count was not given up exactly once: "
        f"{count_after!r} after, {count_before!r} before"
    )
    naming = [
        r.getMessage() for r in caplog.records if "Could not kill" in r.getMessage()
    ]
    assert naming, "the refused kill was never logged"


def test_a_raise_at_the_records_entry_never_gives_the_count_up_twice(monkeypatch):
    """An async exception (an interrupt, say) can land at _record_spawn's call
    itself. The failure handling must not give the count up twice: the counter
    never goes below where it started, since a negative count can end
    kill_running_groups' settle wait while another spawn is still starting. The
    count may stay held (+1) in this one window; that costs a later stop its
    settle wait and nothing worse, the direction already accepted for the
    in-lock flag ordering."""
    count_before = subprocess_utils._SPAWNS_STARTING

    def record_never_entered(process, *args, **kwargs):
        raise KeyboardInterrupt("delivered at the record's entry")

    monkeypatch.setattr(subprocess_utils, "_record_spawn", record_never_entered)

    count_after = None
    try:
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._run_cancellable(
                list(_SLEEPS_BRIEFLY),
                cancel_event=threading.Event(),
                graceful_timeout=False,
                own_group=True,
                capture_output=True,
            )
        count_after = subprocess_utils._SPAWNS_STARTING
    finally:
        subprocess_utils._SPAWNS_STARTING = count_before

    assert count_after is not None and count_after >= count_before, (
        "the spawn's count was given up twice at the record's entry: "
        f"{count_after!r} after, {count_before!r} before"
    )


def _a_spawn_whose_kill_at_the_stop_is_refused(
    monkeypatch, argv, record=None, children=None
):
    """One cancellable spawn the server's stop catches after Popen, whose
    _record_spawn kill the kernel refuses. Returns the cancel, the child, and
    whether the child was still recorded and running once the spawn ended.
    ``record``, when given, is held around the spawn as run_command holds one;
    ``children``, when given, collects the child as soon as it is recorded, so
    the caller can stop it whatever this helper raises."""
    _the_server_stops_after_popen(monkeypatch)
    refused = _the_kernel_refuses_the_first_kill(monkeypatch)
    children = [] if children is None else children
    real_record = subprocess_utils._record_spawn

    def recording(process):
        children.append(process)
        return real_record(process)

    monkeypatch.setattr(subprocess_utils, "_record_spawn", recording)
    holding = record.recording() if record is not None else contextlib.nullcontext()
    try:
        with holding, pytest.raises(ScanCancelled) as cancelled:
            subprocess_utils._run_cancellable(
                list(argv),
                cancel_event=threading.Event(),
                graceful_timeout=False,
                own_group=True,
                capture_output=True,
            )
        assert refused, "the cell shows nothing: _record_spawn's kill was never refused"
        (child,) = children
        recorded = subprocess_utils._RUNNING_GROUPS.get(child.pid) is child
        running = child.poll() is None
    finally:
        subprocess_utils._STOPPING = False
    return cancelled.value, child, recorded, running


def test_the_cancel_after_a_refused_kill_does_not_say_the_tool_was_stopped(
    monkeypatch,
):
    """The kernel refused _record_spawn's kill, so the tool was not stopped and
    may still run. The cancel says so, as a cancel whose stop did not end the
    tool does, rather than the "was stopped" of a kill that worked."""
    monkeypatch.setattr(subprocess_utils, "_REAP_SECONDS", 0.2)
    error, child, _recorded, _running = _a_spawn_whose_kill_at_the_stop_is_refused(
        monkeypatch, _SLEEPS_BRIEFLY
    )

    assert "was stopped" not in str(error), str(error)
    assert f"could not stop {child.args[0]} (pid {child.pid})" in str(error), str(error)
    assert "may still be running" in str(error), str(error)


def test_the_cancel_after_a_refused_kill_ends_with_the_one_sentence(monkeypatch):
    """The cancel's words are the server's stop, then the sentence every
    could-not-stop report composes (could_not_stop_sentence), so a change to the
    ending reaches this cancel with the rest."""
    monkeypatch.setattr(subprocess_utils, "_REAP_SECONDS", 0.2)
    error, child, _recorded, _running = _a_spawn_whose_kill_at_the_stop_is_refused(
        monkeypatch, _SLEEPS_BRIEFLY
    )

    sentence = subprocess_utils.could_not_stop_sentence(
        f"{child.args[0]} (pid {child.pid})"
    )
    assert str(error) == f"the server is stopping; {sentence}", str(error)


def test_the_cancel_after_a_refused_kill_carries_the_tool_as_data(monkeypatch):
    """The exit line names survivors from ScanCancelled.could_not_stop, never
    from the cancel's text, so a refused kill whose cancel says "could not
    stop" in words alone is a sentence the operator never reads: the cancel
    carries the (tool, pid) record the stop path's cancel carries."""
    monkeypatch.setattr(subprocess_utils, "_REAP_SECONDS", 0.2)
    error, child, _recorded, _running = _a_spawn_whose_kill_at_the_stop_is_refused(
        monkeypatch, _SLEEPS_BRIEFLY
    )

    records = getattr(error, "could_not_stop", ())
    assert records == ((child.args[0], child.pid),), (
        "the refused kill's cancel does not carry the tool as data, so the "
        f"exit line cannot name it: {records!r}"
    )


def test_a_kill_refused_at_the_servers_stop_is_recorded_as_one_that_failed(
    monkeypatch,
):
    """The spawn's record says the stop failed, as a stop the kernel refused in
    _stop_child records it: anything reading the record the cancel carries
    finds a tool ASH could not stop, with its pid, not a stop that worked."""
    monkeypatch.setattr(subprocess_utils, "_REAP_SECONDS", 0.2)
    record = subprocess_utils._StartedChild()

    _error, child, _recorded, _running = _a_spawn_whose_kill_at_the_stop_is_refused(
        monkeypatch, _SLEEPS_BRIEFLY, record
    )

    assert record.process is child, "the record never took the spawn's child"
    assert record.stop_refused is True, "the refused kill left the record unmarked"
    assert f"(pid {child.pid})" in (record.not_stopped() or ""), record.not_stopped()


def test_a_kill_that_worked_at_the_stop_ends_as_was_stopped(monkeypatch):
    """The KILLED ending reads as one the spawn does not go on from: the kill
    _record_spawn sends works, and the spawn ends as the "was stopped" cancel
    without waiting on the child it just killed. The cell records whether
    _run_cancellable reached communicate() after the record, which an ending
    read as "goes on" would do."""
    real_popen = subprocess.Popen
    waited = []

    class _Watched(real_popen):
        def communicate(self, *args, **kwargs):
            waited.append(self.pid)
            return super().communicate(*args, **kwargs)

    def popen_then_stopping(args, **kwargs):
        process = _Watched(args, **kwargs)
        subprocess_utils._STOPPING = True
        return process

    monkeypatch.setattr(subprocess, "Popen", popen_then_stopping)
    try:
        with pytest.raises(ScanCancelled) as cancelled:
            subprocess_utils._run_cancellable(
                list(_SLEEPS_BRIEFLY),
                cancel_event=threading.Event(),
                graceful_timeout=False,
                own_group=True,
                capture_output=True,
            )
    finally:
        subprocess_utils._STOPPING = False

    assert "was stopped" in str(cancelled.value), str(cancelled.value)
    assert waited == [], f"the spawn waited on the child it killed: {waited}"


#: Runs well past the bounded reap, as a child whose kill the kernel refused does.
_OUTLIVES_THE_REAP = (sys.executable, "-c", "import time; time.sleep(30)")


def test_a_child_whose_kill_was_refused_stays_recorded(monkeypatch, caplog):
    """The refusal is caught, and the child must not be dropped with it:
    kill_running_groups finds and names it only while it is in
    _RUNNING_GROUPS. The child outlives the bounded reap (_REAP_SECONDS cut to
    0.2 s here), as one whose kill the kernel refused would; it is still running
    when the record is read, and the cell stops it itself afterwards. The
    control is an except arm that also drops the record."""
    monkeypatch.setattr(subprocess_utils, "_REAP_SECONDS", 0.2)
    children: list = []
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            _error, child, recorded, running = (
                _a_spawn_whose_kill_at_the_stop_is_refused(
                    monkeypatch, _OUTLIVES_THE_REAP, children=children
                )
            )

        assert running, "the cell shows nothing: the child already exited"
        assert recorded, (child.pid, sorted(subprocess_utils._RUNNING_GROUPS))
        assert any(
            f"Could not stop {sys.executable} (pid {child.pid})" in r.getMessage()
            for r in caplog.records
        ), [r.getMessage() for r in caplog.records]
    finally:
        for process in children:
            process.kill()
            process.wait(timeout=10)
            subprocess_utils._unregister_group(process)
