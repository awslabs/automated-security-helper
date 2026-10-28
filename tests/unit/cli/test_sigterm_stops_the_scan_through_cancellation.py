# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CLI's SIGTERM handler stops a scan through the cancellation it already has.

Without a handler, a SIGTERM to the ASH process is the default kill: no
``raise_if_cancelled`` fires, so no executor stop runs and the scanner's tool is
left to its own end. The handler (core/cancellation.py, "SIGTERM on the CLI")
only latches and cancels the registered scan events; the scan unwinds through
the same checks a timeout uses, and ``ash scan`` exits ASH_EXIT_TERMINATED.

Every cell here invokes the handler directly with a synthetic frame, or runs
the command layer in process; nothing signals the test runner. The end-to-end
child-process cell is test_a_sigterm_to_ash_stops_the_scan_end_to_end.py.
"""

from __future__ import annotations

import signal
import subprocess  # nosec B404 - the import-side-effect cell runs a fixed argv
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple

import pytest
import typer
from typer.testing import CliRunner

from automated_security_helper.core import cancellation
from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    current_cancel_event,
    raise_if_cancelled,
)
from automated_security_helper.core.constants import (
    ASH_EXIT_INTERRUPTED,
    ASH_EXIT_TERMINATED,
)
from tests.utils.helpers import checkout_env

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the installer is deliberately a no-op on Windows: TerminateProcess "
    "ends a process without running Python signal handlers",
)


@pytest.fixture
def sigterm_state(monkeypatch):
    """The handler's module state fresh, and the process's SIGTERM put back."""
    previous = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(cancellation, "_SIGTERM_SEEN", False)
    # Both latches: either handler's die-now check reads the other's latch,
    # so one left set by an earlier test would turn a first signal here into
    # a die-now.
    monkeypatch.setattr(cancellation, "_SIGINT_SEEN", False, raising=False)
    monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", ())
    monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)
    monkeypatch.setattr(cancellation, "_PREVIOUS_SIGTERM", None)
    # The die-now cells here run the handler's real killpg over this mirror,
    # so it starts empty: an entry an earlier test in the worker recorded and
    # reaped would be a SIGKILL at a possibly reused pid.
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", ())
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())
    try:
        yield cancellation
    finally:
        signal.signal(signal.SIGTERM, previous)


@pytest.fixture
def raised_signals(monkeypatch) -> List[int]:
    """Each signal the handler re-raises, recorded instead of delivered."""
    raised: List[int] = []
    monkeypatch.setattr(signal, "raise_signal", raised.append)
    return raised


@pytest.fixture
def sigint_state(monkeypatch):
    """The SIGINT handler's module state fresh, and the process's SIGINT put back."""
    previous = signal.getsignal(signal.SIGINT)
    monkeypatch.setattr(cancellation, "_SIGINT_SEEN", False, raising=False)
    # Both latches, for the reason sigterm_state resets both.
    monkeypatch.setattr(cancellation, "_SIGTERM_SEEN", False)
    monkeypatch.setattr(cancellation, "_PREVIOUS_SIGINT", None, raising=False)
    monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", ())
    monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)
    # The die-now cells run the handler's real kills over these mirrors, so
    # they start empty, as sigterm_state's comment explains.
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", ())
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())
    try:
        yield cancellation
    finally:
        signal.signal(signal.SIGINT, previous)


def _installed_handler():
    handler = signal.getsignal(signal.SIGTERM)
    assert handler is cancellation._handle_sigterm, "the handler is not installed"
    return handler


def _installed_sigint_handler():
    handler = signal.getsignal(signal.SIGINT)
    assert handler is cancellation._handle_sigint, "the handler is not installed"
    return handler


def test_a_sigterm_cancels_the_registered_scan_event(sigterm_state):
    sigterm_state.install_sigterm_shutdown()
    event = CancelEvent()
    with sigterm_state.shutdown_cancels(event):
        _installed_handler()(signal.SIGTERM, None)
        assert event.is_set(), "the handler did not cancel the registered scan"
        assert event.stop_promptly, (
            "the process is going away, so the running tool must get the short "
            "grace a stdio shutdown gets"
        )
        assert sigterm_state.shutdown_requested()


# The two cells that drive the handler's real die-now branch (no killpg
# recorder) live in test_the_sigterm_default_kill_runs_in_a_fresh_process.py:
# that branch SIGKILLs every pid in the process-wide mirror, so it runs in a
# fresh interpreter whose mirror can hold only what the cell put there.


def test_shutdown_cancels_refuses_a_plain_event(sigterm_state):
    """Registration takes only a CancelEvent. The handler and the die-now
    walk read CancelEvent's own state (stop_promptly, the latch), so a plain
    threading.Event would register, satisfy nothing the handler sets, and
    silently miss the shutdown's cancellation mechanics."""
    with pytest.raises(TypeError):
        with sigterm_state.shutdown_cancels(threading.Event()):
            pass

    assert sigterm_state._SHUTDOWN_SCOPES == (), (
        "a refused registration must leave nothing registered"
    )


def test_a_second_sigterm_takes_the_recorded_tool_groups_along(
    sigterm_state, raised_signals, monkeypatch
):
    """The die-now branches must not orphan the tools the first stop spared.

    The default kill ends this process alone, and each scanner tool leads a
    session and group of its own, so a second SIGTERM that only re-raises
    leaves the tool the cooperative stop was still waiting out running with
    nobody left to stop it. The handler SIGKILLs the recorded groups first:
    os.killpg is one syscall and the tuple one reference load, both safe in
    the signal frame where the registry's lock is not.
    """
    killed: List[Tuple[int, int]] = []
    monkeypatch.setattr(
        cancellation.os, "killpg", lambda pgid, sig: killed.append((pgid, sig))
    )
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (4242,), raising=False)
    sigterm_state.install_sigterm_shutdown()
    event = CancelEvent()
    with sigterm_state.shutdown_cancels(event):
        handler = _installed_handler()
        handler(signal.SIGTERM, None)
        assert killed == [], (
            "the first SIGTERM is cooperative: the stop path owns the tools"
        )
        handler(signal.SIGTERM, None)
    assert killed == [(4242, signal.SIGKILL)], (
        "the second SIGTERM must take the recorded tool groups along before "
        "the default kill, or the tool outlives the process that was "
        "stopping it"
    )
    assert raised_signals == [signal.SIGTERM]


def test_a_sigterm_with_no_scan_still_takes_the_tool_groups_along(
    sigterm_state, raised_signals, monkeypatch
):
    """The no-scan default-kill branch covers a recorded tool the same way."""
    killed: List[Tuple[int, int]] = []
    monkeypatch.setattr(
        cancellation.os, "killpg", lambda pgid, sig: killed.append((pgid, sig))
    )
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (515,), raising=False)
    sigterm_state.install_sigterm_shutdown()
    _installed_handler()(signal.SIGTERM, None)
    assert killed == [(515, signal.SIGKILL)]
    assert raised_signals == [signal.SIGTERM]


def test_a_gone_tool_group_does_not_break_the_default_kill(
    sigterm_state, raised_signals, monkeypatch
):
    """A group that died on its own must not turn the kill into a traceback.

    Both the group kill and its by-pid fallback are refused here, so the
    branch has nothing left to try and must still deliver the default kill.
    The stand-in id is above 2**30, past the kernel's pid space, so nothing
    real could be signalled even unpatched.
    """

    def refuse(pid: int, sig: int) -> None:
        raise ProcessLookupError(pid)

    monkeypatch.setattr(cancellation.os, "killpg", refuse)
    monkeypatch.setattr(cancellation.os, "kill", refuse)
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (2**30 + 99,), raising=False)
    sigterm_state.install_sigterm_shutdown()
    _installed_handler()(signal.SIGTERM, None)
    assert raised_signals == [signal.SIGTERM], (
        "a gone group must be left to its end, not replace the default kill "
        "with an exception out of the handler"
    )


def test_a_group_kill_the_kernel_refuses_falls_back_to_the_pid(
    sigterm_state, raised_signals, monkeypatch
):
    """A child recorded before its setsid leads no group of its own.

    ``killpg`` at such a child's pid is ESRCH while the child lives, so the
    die-now branch sends one ``os.kill`` at the recorded id, as the
    subprocess layer's _kill_group falls back for the same child. Still one
    syscall per entry, nothing new in the signal frame.
    """
    killed: List[Tuple[int, int]] = []

    def refuse(pgid: int, sig: int) -> None:
        raise ProcessLookupError(pgid)

    monkeypatch.setattr(cancellation.os, "killpg", refuse)
    monkeypatch.setattr(
        cancellation.os, "kill", lambda pid, sig: killed.append((pid, sig))
    )
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (2**30 + 41,), raising=False)
    sigterm_state.install_sigterm_shutdown()
    _installed_handler()(signal.SIGTERM, None)
    assert killed == [(2**30 + 41, signal.SIGKILL)], (
        "a refused group kill must fall back to one os.kill at the recorded "
        f"pid, or the groupless child outlives the process stopping it: {killed}"
    )
    assert raised_signals == [signal.SIGTERM]


def test_a_first_sigint_latches_the_scopes_and_keeps_the_interrupt(sigint_state):
    """A Ctrl-C must stay an interrupt and still reach the scan's pollers.

    The chained default handler raises KeyboardInterrupt, which drives the
    command's own interrupt arm; the latch is the handler's own work, so a
    cancellable spawn polling in another thread stops within its poll
    interval instead of waiting for that arm to unwind to its set calls.
    """
    sigint_state.install_sigint_shutdown()
    event = CancelEvent()
    with sigint_state.shutdown_cancels(event):
        with pytest.raises(KeyboardInterrupt):
            _installed_sigint_handler()(signal.SIGINT, None)
        assert event.is_set(), "the handler did not latch the registered scan"
        assert event.stop_promptly, (
            "the operator asked for a stop, so the running tool must get the "
            "short grace a stdio shutdown gets"
        )
        assert sigint_state.shutdown_requested()


def test_a_pool_projects_chained_event_sees_the_first_sigint(sigint_state):
    """A workspace pool's project event must see the operator's first Ctrl-C.

    The pool's per-project events are built off-scope and chained to the
    scan-wide one (link_parent); ``is_set`` walks that chain, so the pool
    worker's polling stops on the first interrupt rather than surviving to a
    third one.
    """
    sigint_state.install_sigint_shutdown()
    scan_event = CancelEvent()
    project_event = CancelEvent()
    cancellation.link_parent(project_event, scan_event)
    with sigint_state.shutdown_cancels(scan_event):
        with pytest.raises(KeyboardInterrupt):
            _installed_sigint_handler()(signal.SIGINT, None)
        assert project_event.is_set(), (
            "the chained project event did not see the latch, so the pool "
            "worker keeps running a scan the operator interrupted"
        )
        assert project_event.stop_promptly


def test_a_second_sigint_takes_the_recorded_tool_groups_along(
    sigint_state, raised_signals, monkeypatch
):
    """A second Ctrl-C must not orphan the tool the first stop spared.

    The scanner tool leads a session and group of its own, so a second
    interrupt that only aborts the grace wait leaves the tool running with
    nobody left to stop it. The die-now branch SIGKILLs the recorded groups
    first, then dies as an interrupted process does -- by SIGINT, the 130 a
    shell reports.
    """
    killed: List[Tuple[int, int]] = []
    monkeypatch.setattr(
        cancellation.os, "killpg", lambda pgid, sig: killed.append((pgid, sig))
    )
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (4243,), raising=False)
    sigint_state.install_sigint_shutdown()
    event = CancelEvent()
    with sigint_state.shutdown_cancels(event):
        handler = _installed_sigint_handler()
        with pytest.raises(KeyboardInterrupt):
            handler(signal.SIGINT, None)
        assert killed == [], (
            "the first Ctrl-C is cooperative: the stop path owns the tools"
        )
        handler(signal.SIGINT, None)
    assert killed == [(4243, signal.SIGKILL)], (
        "the second SIGINT must take the recorded tool groups along before "
        "dying, or the tool outlives the process that was stopping it"
    )
    assert raised_signals == [signal.SIGINT]
    assert signal.getsignal(signal.SIGINT) == signal.SIG_DFL


def test_a_second_sigint_takes_the_recorded_launcher_children_along(
    sigint_state, raised_signals, monkeypatch
):
    """The launcher children that lead no group of their own go along too.

    The direct and shell launchers' children share this process's group, so
    the group kill cannot name them; they are recorded by pid and killed one
    ``os.kill`` at a time, as the SIGTERM die-now branch kills them.
    """
    killed: List[Tuple[int, int]] = []
    monkeypatch.setattr(
        cancellation.os, "kill", lambda pid, sig: killed.append((pid, sig))
    )
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", (777,), raising=False)
    sigint_state.install_sigint_shutdown()
    event = CancelEvent()
    with sigint_state.shutdown_cancels(event):
        handler = _installed_sigint_handler()
        with pytest.raises(KeyboardInterrupt):
            handler(signal.SIGINT, None)
        assert killed == []
        handler(signal.SIGINT, None)
    assert killed == [(777, signal.SIGINT)], (
        "the second SIGINT must interrupt the recorded launcher children, "
        "or a direct launcher's tool outlives the process stopping it"
    )
    assert raised_signals == [signal.SIGINT]


def test_a_sigterm_then_a_ctrl_c_takes_the_recorded_tool_groups_along(
    sigterm_state, sigint_state, raised_signals, monkeypatch
):
    """The second shutdown signal escalates whatever kind the first one was.

    A SIGTERM starts the cooperative stop; a Ctrl-C inside that stop's grace
    is the operator's second ask, and a KeyboardInterrupt there would land in
    the main thread's grace wait and abort the stop before its own escalation
    -- the SIGTERM-ignoring tool then outlives the 130 exit. So the mixed
    pair takes the die-now branch exactly as a second signal of the same
    kind does: recorded groups SIGKILLed, then the default disposition.
    """
    killed: List[Tuple[int, int]] = []
    monkeypatch.setattr(
        cancellation.os, "killpg", lambda pgid, sig: killed.append((pgid, sig))
    )
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (4244,), raising=False)
    sigterm_state.install_sigterm_shutdown()
    sigint_state.install_sigint_shutdown()
    event = CancelEvent()
    with sigterm_state.shutdown_cancels(event):
        _installed_handler()(signal.SIGTERM, None)
        assert killed == [], (
            "the first SIGTERM is cooperative: the stop path owns the tools"
        )
        # The die-now branch dies by the default disposition instead of
        # chaining the interrupt into the grace wait. Caught rather than
        # expected, so the broken shape fails this cell's own assertions
        # instead of aborting the whole run.
        interrupted = False
        try:
            _installed_sigint_handler()(signal.SIGINT, None)
        except KeyboardInterrupt:
            interrupted = True
    assert not interrupted, (
        "a Ctrl-C after a SIGTERM must not raise KeyboardInterrupt: it lands "
        "in the main thread's grace wait and aborts the stop before its own "
        "escalation"
    )
    assert killed == [(4244, signal.SIGKILL)], (
        "a Ctrl-C after a SIGTERM is the operator's second shutdown signal "
        "and must take the recorded tool groups along, or a SIGTERM-ignoring "
        "tool outlives the 130 exit"
    )
    assert raised_signals == [signal.SIGINT]
    assert signal.getsignal(signal.SIGINT) == signal.SIG_DFL


def test_a_ctrl_c_then_a_sigterm_takes_the_recorded_tool_groups_along(
    sigterm_state, sigint_state, raised_signals, monkeypatch
):
    """The other mixed pair escalates the same way: one shared view of "the
    operator already asked once", whichever handler saw the first ask."""
    killed: List[Tuple[int, int]] = []
    monkeypatch.setattr(
        cancellation.os, "killpg", lambda pgid, sig: killed.append((pgid, sig))
    )
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (4245,), raising=False)
    sigterm_state.install_sigterm_shutdown()
    sigint_state.install_sigint_shutdown()
    event = CancelEvent()
    with sigterm_state.shutdown_cancels(event):
        with pytest.raises(KeyboardInterrupt):
            _installed_sigint_handler()(signal.SIGINT, None)
        assert killed == [], (
            "the first Ctrl-C is cooperative: the stop path owns the tools"
        )
        _installed_handler()(signal.SIGTERM, None)
    assert killed == [(4245, signal.SIGKILL)], (
        "a SIGTERM after a Ctrl-C is the operator's second shutdown signal "
        "and must take the recorded tool groups along"
    )
    assert raised_signals == [signal.SIGTERM]
    assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL


def test_a_first_sigint_with_no_scan_stays_an_interrupt(
    sigint_state, raised_signals, monkeypatch
):
    """Unlike SIGTERM, whose kill semantics the no-scan branch keeps, a first
    Ctrl-C is an interrupt with or without a scan: KeyboardInterrupt drives
    the command's own unwinding and cleanup, so nothing is killed here."""
    killed: List[Tuple[int, int]] = []
    monkeypatch.setattr(
        cancellation.os, "killpg", lambda pgid, sig: killed.append((pgid, sig))
    )
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (99,), raising=False)
    sigint_state.install_sigint_shutdown()
    with pytest.raises(KeyboardInterrupt):
        _installed_sigint_handler()(signal.SIGINT, None)
    assert killed == []
    assert raised_signals == []


def test_install_leaves_an_ignored_sigint_ignored(sigint_state):
    """A process started with SIGINT ignored (a shell's background job) keeps
    it ignored, for the reason cli.SIGINT_IGNORED_AT_START documents."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    sigint_state.install_sigint_shutdown()
    assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN


def test_the_subprocess_registry_mirrors_groups_for_the_handler(
    sigterm_state, monkeypatch
):
    """The registry's record and forget both reach the handler's tuple.

    The subprocess layer's own registry is lock-guarded, which the handler
    cannot read, so every path that records or forgets a child there mirrors
    its group into the lock-free tuple: the plain registration, the spawn
    record, the identity-checked forget, and the reaped-child sweep.
    """
    from types import SimpleNamespace

    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (), raising=False)
    # Stand-in pids above the kernel's pid space (pid_max is at most 2**22):
    # an entry that leaked past a finally could never aim a later die-now
    # kill at a real process group.
    pid_a, pid_b, pid_c, pid_d = (2**30 + n for n in (51, 52, 53, 54))
    child = SimpleNamespace(pid=pid_a, poll=lambda: None)
    subprocess_utils._register_group(child)
    try:
        assert pid_a in cancellation._TOOL_GROUPS, (
            "a registered child's group never reached the handler's tuple"
        )
    finally:
        subprocess_utils._unregister_group(child)
    assert pid_a not in cancellation._TOOL_GROUPS, (
        "a forgotten child's group must leave the tuple with it"
    )

    subprocess_utils._begin_spawn(["tool"])
    recorded = SimpleNamespace(pid=pid_b, poll=lambda: None)
    assert subprocess_utils._record_spawn(recorded)
    try:
        assert pid_b in cancellation._TOOL_GROUPS, (
            "a recorded spawn's group never reached the handler's tuple"
        )
    finally:
        subprocess_utils._unregister_group(recorded)
    assert pid_b not in cancellation._TOOL_GROUPS

    exited = SimpleNamespace(pid=pid_c, poll=lambda: 0)
    subprocess_utils._register_group(exited)
    later = SimpleNamespace(pid=pid_d, poll=lambda: None)
    subprocess_utils._register_group(later)
    try:
        assert pid_c not in cancellation._TOOL_GROUPS, (
            "a reaped child's pid can be reused: the sweep that forgets it "
            "from the registry must forget its group too"
        )
    finally:
        subprocess_utils._unregister_group(exited)
        subprocess_utils._unregister_group(later)


def test_the_handler_chains_to_the_previous_python_handler(sigterm_state):
    chained: List[Tuple[int, object]] = []
    signal.signal(signal.SIGTERM, lambda signum, frame: chained.append((signum, frame)))
    sigterm_state.install_sigterm_shutdown()
    event = CancelEvent()
    with sigterm_state.shutdown_cancels(event):
        _installed_handler()(signal.SIGTERM, None)
    assert event.is_set()
    assert [signum for signum, _ in chained] == [signal.SIGTERM], (
        "a handler someone installed before ASH's must still run, once"
    )


def test_install_leaves_an_ignored_sigterm_ignored(sigterm_state):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    sigterm_state.install_sigterm_shutdown()
    assert signal.getsignal(signal.SIGTERM) == signal.SIG_IGN, (
        "a process started with SIGTERM ignored keeps it ignored, as "
        "SIGINT_IGNORED_AT_START keeps SIGINT"
    )


def test_install_twice_does_not_chain_to_itself(sigterm_state):
    sigterm_state.install_sigterm_shutdown()
    sigterm_state.install_sigterm_shutdown()
    assert signal.getsignal(signal.SIGTERM) is cancellation._handle_sigterm
    assert cancellation._PREVIOUS_SIGTERM is not cancellation._handle_sigterm, (
        "a second install must not make the handler its own previous handler"
    )


def test_a_scope_registered_after_the_signal_is_cancelled_at_once(sigterm_state):
    sigterm_state.install_sigterm_shutdown()
    first = CancelEvent()
    with sigterm_state.shutdown_cancels(first):
        _installed_handler()(signal.SIGTERM, None)
        late = CancelEvent()
        with sigterm_state.shutdown_cancels(late):
            assert late.is_set() and late.stop_promptly, (
                "a scan that registers while the shutdown is in progress must "
                "not run as a scan nobody can stop again"
            )


def test_a_sigterm_inside_the_grace_waits_lock_window_still_returns(tmp_path):
    """The handler must take no event lock, or the stop stops the stopper.

    The grace wait blocks the main thread in the prompt's ``Event.wait``
    (utils/subprocess_utils._wait_out_grace), which holds that event's own
    condition lock while it reads the flag. A handler that answers the signal
    with ``set`` acquires the same non-reentrant lock under the interrupted
    frame, and the process deadlocks with no error. The probe forces the
    window: a trace function raises SIGTERM at the second traced line of
    ``threading.Event.wait``, after the ``with self._cond:`` acquire, so the
    handler runs at the next bytecode boundary with the lock held. Measured
    in a child interpreter because the failure mode is a hang -- in process
    it would hang the test runner, not fail the test.
    """
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import signal\n"
        "import sys\n"
        "import threading\n"
        "from automated_security_helper.core import cancellation\n"
        "from automated_security_helper.core.cancellation import CancelEvent\n"
        "cancellation.install_sigterm_shutdown()\n"
        "event = CancelEvent()\n"
        "wait_code = threading.Event.wait.__code__\n"
        "state = {'lines': 0, 'fired': False}\n"
        "def tracer(frame, what, arg):\n"
        "    if frame.f_code is wait_code and what == 'line' and not state['fired']:\n"
        "        state['lines'] += 1\n"
        "        if state['lines'] == 2:\n"
        "            state['fired'] = True\n"
        "            signal.raise_signal(signal.SIGTERM)\n"
        "    return tracer\n"
        "with cancellation.shutdown_cancels(event):\n"
        "    sys.settrace(tracer)\n"
        "    try:\n"
        "        event.prompt.wait(5.0)\n"
        "    finally:\n"
        "        sys.settrace(None)\n"
        "assert state['fired'], 'the trace never reached the lock-held window'\n"
        "assert event.is_set(), 'the handler did not cancel the scan'\n"
        "assert event.stop_promptly, 'the tool must get the short grace'\n"
        "assert cancellation.shutdown_requested()\n"
        "print('returned')\n"
    )
    result = subprocess.run(  # nosec B603 - fixed argv, the running interpreter
        [sys.executable, str(probe)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        cwd=Path(__file__).resolve().parents[3],
        env=checkout_env(),
    )
    assert result.returncode == 0, (
        "the probe did not return: a handler that takes an event lock "
        "deadlocks under the wait it interrupted.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "returned" in result.stdout


def test_a_parents_cancel_ends_a_childs_wait_within_a_slice():
    """``wait`` must see every state ``is_set`` reports, not the local flag only.

    A workspace project's event chains to the run's (link_parent), and the
    project's checks poll ``is_set``, which answers for the ancestors. A
    blocking ``wait`` on the child that reads only its own flag sleeps out
    its whole timeout oblivious to the run's cancel, so any caller that
    blocks instead of polling waits on an event that is, by the module's own
    reading, already set.
    """
    parent = CancelEvent()
    child = CancelEvent(parent=parent)
    setter = threading.Timer(0.2, parent.set)
    setter.start()
    try:
        begin = time.monotonic()
        woke = child.wait(10.0)
        elapsed = time.monotonic() - begin
    finally:
        setter.cancel()
    assert woke is True, "the wait returned unaware of the parent's cancel"
    assert elapsed < 5.0, (
        f"the wait slept out its own timeout past the parent's cancel: {elapsed:.1f}s"
    )


def test_a_handler_latched_stop_wakes_a_blocked_prompt_wait(sigterm_state):
    """A grace wait already blocked when the SIGTERM lands must still end.

    The grace wait sits in ``prompt.wait`` between its per-tick checks; the
    handler's cancel must end that wait promptly, whatever form the latch
    takes, or the stop is delayed by the full step the wait was given.
    """
    sigterm_state.install_sigterm_shutdown()
    event = CancelEvent()
    record = {}

    def waiter() -> None:
        begin = time.monotonic()
        record["woke"] = event.prompt.wait(10.0)
        record["elapsed"] = time.monotonic() - begin

    with sigterm_state.shutdown_cancels(event):
        thread = threading.Thread(target=waiter)
        thread.start()
        time.sleep(0.1)
        _installed_handler()(signal.SIGTERM, None)
        thread.join(timeout=8.0)
    assert not thread.is_alive(), "the prompt wait never woke"
    assert record["woke"] is True
    assert record["elapsed"] < 5.0


def test_importing_the_library_installs_no_handler(tmp_path):
    """The install happens in the CLI entry point, never at import time.

    Measured in a child interpreter so this cell cannot be satisfied by the
    runner's own pristine state: the child imports the cancellation module and
    the scan command module, then reads the SIGTERM disposition.
    """
    probe = (
        "import signal\n"
        "import automated_security_helper.core.cancellation\n"
        "import automated_security_helper.cli.scan\n"
        "assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL, 'installed'\n"
        "assert signal.getsignal(signal.SIGINT) is signal.default_int_handler, (\n"
        "    'installed'\n"
        ")\n"
        "print('no handler')\n"
    )
    result = subprocess.run(  # nosec B603 - fixed argv, the running interpreter
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=Path(__file__).resolve().parents[3],
        env=checkout_env(),
    )
    assert result.returncode == 0, result.stderr
    assert "no handler" in result.stdout


def _scan_command_app() -> typer.Typer:
    from automated_security_helper.cli.scan import run_ash_scan_cli_command

    app = typer.Typer()
    app.command(name="scan")(run_ash_scan_cli_command)
    return app


def test_the_scan_command_exits_terminated_when_a_sigterm_stops_the_scan(
    sigterm_state, monkeypatch, tmp_path
):
    """The command layer end to end in process: real handler, real check, real exit.

    The stand-in scan delivers a real SIGTERM to this process -- whose handler
    is the installed one -- and then runs the same ``raise_if_cancelled`` the
    phases run, so what reaches the command's except arm is exactly what a
    stopped scan raises. The registration is asserted before the raise,
    because the no-scan branch answers an unregistered SIGTERM with the
    default kill: without the check, a command that lost its registration
    would not fail this cell, it would kill the test runner.
    """
    sigterm_state.install_sigterm_shutdown()

    def stand_in_scan(**kwargs):
        event = current_cancel_event()
        assert isinstance(event, CancelEvent), (
            "the command must run the scan inside a cancel scope of its own"
        )
        assert cancellation._SHUTDOWN_SCOPES, (
            "the scan's scope is not registered with the shutdown handler: a "
            "real SIGTERM now would take the default-kill branch and end the "
            "test runner, so the cell stops here instead"
        )
        signal.raise_signal(signal.SIGTERM)
        # The Python-level handler runs at a bytecode boundary after the raise;
        # spin until it has, bounded, so the check below cannot outrun it.
        deadline = time.monotonic() + 10
        while not cancellation.shutdown_requested() and time.monotonic() < deadline:
            pass
        raise_if_cancelled()
        pytest.fail("the SIGTERM did not cancel the scan's scope")

    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan", stand_in_scan
    )
    result = CliRunner().invoke(
        _scan_command_app(),
        ["--source-dir", str(tmp_path), "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == ASH_EXIT_TERMINATED, result.output
    assert "stopped by SIGTERM" in result.output


def test_a_keyboard_interrupt_cancels_the_scans_scope_before_exit(
    monkeypatch, tmp_path
):
    """The Ctrl-C arm must cancel the scan's event, not only exit 130.

    The interrupt lands as KeyboardInterrupt in one frame; a workspace pool's
    project events chain to the scan-wide one (link_parent), and a cancellable
    spawn still running in another thread polls it. An arm that only prints
    and exits leaves those pollers running under a scan the operator already
    stopped. The arm runs on a normal thread frame, so the real set calls are
    safe here where the signal handler's are not.
    """
    seen = {}

    def stand_in_scan(**kwargs):
        seen["event"] = current_cancel_event()
        raise KeyboardInterrupt

    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan", stand_in_scan
    )
    result = CliRunner().invoke(
        _scan_command_app(),
        ["--source-dir", str(tmp_path), "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == ASH_EXIT_INTERRUPTED, result.output
    event = seen["event"]
    assert isinstance(event, CancelEvent)
    assert event.is_set(), (
        "the interrupt arm exited without cancelling the scan's scope, so the "
        "scan's other threads keep running a scan the operator stopped"
    )
    assert event.stop_promptly, (
        "the operator is gone, so a tool still running gets the short grace a "
        "stdio shutdown gets"
    )


def test_an_unstopped_tools_shutdown_line_says_the_tool_may_still_run(
    sigterm_state, monkeypatch, tmp_path
):
    """The operator's one line must carry the stop's one failure that matters.

    The real cancel, end to end: a real child under the command's scope, a
    real SIGTERM, and a kernel that refuses the stop (EPERM). The cancel that
    unwinds carries the tool and pid as data (ScanCancelled.could_not_stop),
    and the exit line -- the only word the operator gets -- names them:
    without that, the ending reads as a clean stop and the surviving tool
    goes unlooked-for.
    """
    from automated_security_helper.utils import subprocess_utils

    sigterm_state.install_sigterm_shutdown()

    def refuse(pgid: int, sig: int) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(subprocess_utils.os, "killpg", refuse)

    def stand_in_scan(**kwargs):
        assert cancellation._SHUTDOWN_SCOPES, (
            "the scan's scope is not registered with the shutdown handler: a "
            "real SIGTERM now would take the default-kill branch and end the "
            "test runner, so the cell stops here instead"
        )
        # Delivered while the child runs, so the cancellable wait's own stop
        # path -- not a hand-built exception -- produces the cancel the CLI
        # reports.
        timer = threading.Timer(0.3, signal.raise_signal, [signal.SIGTERM])
        timer.start()
        try:
            subprocess_utils.run_ended_with_the_server(
                [sys.executable, "-c", "import time; time.sleep(5)"]
            )
        finally:
            timer.cancel()
        pytest.fail("the cancelled wait returned instead of raising")

    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan", stand_in_scan
    )
    result = CliRunner().invoke(
        _scan_command_app(),
        ["--source-dir", str(tmp_path), "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == ASH_EXIT_TERMINATED, result.output
    assert "stopped by SIGTERM" in result.output
    assert "may still be running" in result.output, (
        "the stop could not end the tool and the exit line does not say so"
    )
    assert sys.executable in result.output, (
        "the exit line does not name the tool the stop could not end"
    )
    assert "(pid " in result.output, result.output


def test_a_clean_shutdown_line_does_not_warn_about_a_surviving_tool(
    sigterm_state, monkeypatch, tmp_path
):
    """The warning is for a failed stop only: a clean stop must not cry wolf."""
    sigterm_state.install_sigterm_shutdown()

    def stand_in_scan(**kwargs):
        signal.raise_signal(signal.SIGTERM)
        deadline = time.monotonic() + 10
        while not cancellation.shutdown_requested() and time.monotonic() < deadline:
            pass
        raise_if_cancelled()

    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan", stand_in_scan
    )
    result = CliRunner().invoke(
        _scan_command_app(),
        ["--source-dir", str(tmp_path), "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == ASH_EXIT_TERMINATED, result.output
    assert "may still be running" not in result.output


def test_an_unexplained_cancel_is_not_dressed_up_as_a_shutdown(
    sigterm_state, monkeypatch, tmp_path
):
    """A ScanCancelled nothing here caused is a defect to report, not exit 143."""
    sigterm_state.install_sigterm_shutdown()

    def stand_in_scan(**kwargs):
        raise ScanCancelled("the scan was cancelled")

    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan", stand_in_scan
    )
    with pytest.raises(ScanCancelled):
        CliRunner().invoke(
            _scan_command_app(),
            ["--source-dir", str(tmp_path), "--output-dir", str(tmp_path / "out")],
            catch_exceptions=False,
        )


def test_the_commands_scope_is_registered_with_the_shutdown_handler(
    sigterm_state, monkeypatch, tmp_path
):
    seen: List[Optional[threading.Event]] = []

    def stand_in_scan(**kwargs):
        event = current_cancel_event()
        seen.append(event)
        assert event in cancellation._SHUTDOWN_SCOPES, (
            "the scan's scope must be the one a SIGTERM cancels"
        )

    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan", stand_in_scan
    )
    result = CliRunner().invoke(
        _scan_command_app(),
        ["--source-dir", str(tmp_path), "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == 0, result.output
    assert len(seen) == 1 and isinstance(seen[0], CancelEvent)
    assert cancellation._SHUTDOWN_SCOPES == (), (
        "the registration must not outlive the command"
    )
