# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancel is seen by the real engine and the real scanner executor.

The cancel tests for the MCP server replace run_ash_scan, or the engine's
execute_phases, wholesale, so nothing they check passes through the checks a
cancel relies on inside a scan: before each phase
(``ScanExecutionEngine.execute_phases``), before each scanner
(``ScannerExecutor._safe_execute_scanner`` and the scan phase's own), before the
scan phase writes ash_aggregated_results.json, and the context copy that lets a
scanner on a pool thread see the scan's cancel event
(``ScannerExecutor.run_parallel``). Each of those could be removed with every
test still passing. The tests here drive the real objects, with only the
scanners themselves (or the phases next to the one under test) replaced.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.cancellation import ScanCancelled, cancel_scope
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from tests.utils.processes import process_running
from tests.utils.tool_guard import stub_tool_probes

CHILD = (
    "import os, pathlib, sys, time; "
    "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(10)"
)


def _alive(pid: int) -> bool:
    return process_running(pid)


def _tasks(tmp_path: Path, count: int):
    return [
        (f"s{i}", MagicMock(), [{"path": str(tmp_path), "type": "source"}])
        for i in range(count)
    ]


def _executor(tasks) -> ScannerExecutor:
    return ScannerExecutor(
        plugin_context=MagicMock(),
        progress_display=MagicMock(),
        scanner_tasks=tasks,
        max_workers=len(tasks),
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process check")
@pytest.mark.integration
def test_the_parallel_pool_scanners_are_stopped_by_a_cancel(tmp_path, monkeypatch):
    """A pool thread sees the scan's cancel event only through the context copy."""
    from automated_security_helper.utils.subprocess_utils import run_command

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        run_command(
            [sys.executable, "-c", CHILD, str(tmp_path / f"{scanner_name}.pid")]
        )
        return []

    executor = _executor(_tasks(tmp_path, 3))
    monkeypatch.setattr(executor, "_execute_scanner", fake_execute)
    event = threading.Event()
    timer = threading.Timer(1.5, event.set)
    timer.start()
    started = time.monotonic()
    outcome = "returned"
    try:
        with cancel_scope(event):
            try:
                executor.run_parallel(MagicMock())
            except ScanCancelled:
                outcome = "cancelled"
    finally:
        timer.cancel()
    took = time.monotonic() - started
    pids = [int(p.read_text()) for p in tmp_path.glob("*.pid")]
    alive = [p for p in pids if _alive(p)]
    for pid in alive:
        os.kill(pid, 9)
    assert outcome == "cancelled", outcome
    assert took < 5, took
    assert pids and not alive, (pids, alive)


@pytest.mark.unit
def test_a_scanner_finishing_during_the_cancels_wait_is_recorded(tmp_path, monkeypatch):
    """The cancel drains the pool before the final sweep, so a scanner that
    finishes while the pool is drained is recorded like one that finished
    before the cancel. The pool's own exit waits for running futures either
    way; swept BEFORE that wait, a scanner finishing during it returned
    results that were thrown away, against the stated contract that a scanner
    that had finished stays recorded. The observation point is the pool's
    shutdown itself: the moment it is entered, the running scanner is released
    and finishes, so wherever the wait happens, the finish lands inside it."""
    from concurrent.futures import ThreadPoolExecutor

    cancel_came = threading.Event()
    may_finish = threading.Event()
    s1_started = threading.Event()
    recorded: list = []

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        if scanner_name == "s0":
            # The premise is a scanner RUNNING at the cancel. Raising before
            # s1 has started leaves s1 in the queue, where the cancel removes
            # it instead -- on an interpreter whose workers dequeue later
            # (3.12), that was every run, and the cell measured nothing.
            assert s1_started.wait(timeout=30), "s1 never started"
            cancel_came.set()
            raise ScanCancelled("the scan was cancelled while s0 was running")
        s1_started.set()
        cancel_came.wait(timeout=30)
        assert may_finish.wait(timeout=30), "the pool never began shutting down"
        return [f"late-{scanner_name}"], True

    executor = _executor(_tasks(tmp_path, 2))
    monkeypatch.setattr(executor, "_execute_scanner", fake_execute)

    def recording(*args):
        recorded.extend(args)
        return args[-1]

    monkeypatch.setattr(executor, "_process_results_fn", recording, raising=False)

    real_shutdown = ThreadPoolExecutor.shutdown

    def shutdown_releases_the_runner(self, *args, **kwargs):
        may_finish.set()
        return real_shutdown(self, *args, **kwargs)

    monkeypatch.setattr(ThreadPoolExecutor, "shutdown", shutdown_releases_the_runner)

    with pytest.raises(ScanCancelled):
        executor.run_parallel(MagicMock())

    assert any(arg == "late-s1" or arg == ["late-s1"] for arg in recorded), (
        f"a scanner that finished during the cancel's wait was thrown away: {recorded}"
    )


def _a_cancel_with_a_finished_siblings_result_in_hand(tmp_path, monkeypatch):
    """Two scanners at the cancel: s1 finished FIRST, and the cancel (s0) is
    handed to the recording loop before s1 is -- an interleaving as_completed
    is free to produce, pinned here by an ordering wrapper so the cell is
    deterministic. At the loop's break, s1's finished result is in hand but
    not yet handed over: exactly the state the drain ordering decides.
    Returns (executor, recorded, order, pool_cls); ``order`` logs s1's
    recording and the drain's entry."""
    import concurrent.futures
    from concurrent.futures import ThreadPoolExecutor

    from automated_security_helper.core.phases import scanner_executor as module

    s1_returned = threading.Event()
    recorded: list = []
    order: list = []

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        if scanner_name == "s0":
            assert s1_returned.wait(timeout=30), "s1 never returned"
            raise ScanCancelled("the scan was cancelled while s0 was running")
        s1_returned.set()
        return ["done-s1"], True

    executor = _executor(_tasks(tmp_path, 2))
    monkeypatch.setattr(executor, "_execute_scanner", fake_execute)

    real_as_completed = module.as_completed

    def the_cancel_is_handed_first(futures, *args, **kwargs):
        # Deliver s0's future first, then the rest in completion order. Both
        # orders are legal for as_completed when completions race; this pins
        # the one where a finished sibling is still unhanded at the break.
        futures = list(futures)
        # Settle the premise "s1 finished first" before handing anything
        # over: s1's event fires before its future completes, so without
        # this wait a descheduled completion can leave s1 un-done at the
        # break and the cell orders nothing. s0 raises once s1's event is
        # set, so both futures complete promptly.
        concurrent.futures.wait(futures)
        cancel_future = next(
            f for f in futures if getattr(f, "scanner_name", "") == "s0"
        )
        yield from real_as_completed([cancel_future], *args, **kwargs)
        yield from real_as_completed(
            [f for f in futures if f is not cancel_future], *args, **kwargs
        )

    monkeypatch.setattr(module, "as_completed", the_cancel_is_handed_first)

    def recording(*args):
        recorded.extend(args)
        for arg in args:
            if arg == ["done-s1"]:
                order.append("recorded-s1")
        return args[-1]

    monkeypatch.setattr(executor, "_process_results_fn", recording, raising=False)
    return executor, recorded, order, ThreadPoolExecutor


@pytest.mark.unit
def test_a_result_in_hand_is_recorded_before_the_drain(tmp_path, monkeypatch):
    """A result already in hand at the cancel is recorded BEFORE the pool is
    drained: the drain waits for every running scanner, and one that cannot
    see the cancel event (busy in pure Python) runs out its own time, so a
    finished scanner's results must not sit behind it. Drained first, they
    did -- and anything interrupting the drain threw them away."""
    executor, recorded, order, pool_cls = (
        _a_cancel_with_a_finished_siblings_result_in_hand(tmp_path, monkeypatch)
    )
    real_shutdown = pool_cls.shutdown

    def shutdown_logs_the_drain(self, *args, **kwargs):
        # The drain is the WAITING shutdown. The cancel's own queue-shutdown
        # (wait=False, cancel_futures=True) precedes the sweep by design and
        # waits for nothing, so it is not the drain this cell orders against.
        waits = args[0] if args else kwargs.get("wait", True)
        if waits and "drain" not in order:
            order.append("drain")
        return real_shutdown(self, *args, **kwargs)

    monkeypatch.setattr(pool_cls, "shutdown", shutdown_logs_the_drain)

    with pytest.raises(ScanCancelled):
        executor.run_parallel(MagicMock())

    assert "recorded-s1" in order, order
    assert order.index("recorded-s1") < order.index("drain"), (
        f"a result in hand waited for the drain: {order}"
    )


@pytest.mark.unit
def test_an_interrupt_during_the_drain_keeps_the_results_in_hand(tmp_path, monkeypatch):
    """A KeyboardInterrupt while the drain waits (the operator interrupting a
    scanner that cannot see the cancel) must not lose the results already in
    hand: recorded before the drain, they survive; swept only after it, the
    interrupt threw them away."""
    executor, recorded, _order, pool_cls = (
        _a_cancel_with_a_finished_siblings_result_in_hand(tmp_path, monkeypatch)
    )
    real_shutdown = pool_cls.shutdown
    interrupted: list = []

    def shutdown_interrupts_once(self, *args, **kwargs):
        # The interrupt lands in the drain -- the WAITING shutdown -- not in
        # the cancel's own queue-shutdown (wait=False), which waits for
        # nothing an operator would interrupt.
        waits = args[0] if args else kwargs.get("wait", True)
        if waits and not interrupted:
            interrupted.append(True)
            raise KeyboardInterrupt("interrupted while the drain waited")
        return real_shutdown(self, *args, **kwargs)

    monkeypatch.setattr(pool_cls, "shutdown", shutdown_interrupts_once)

    with pytest.raises(KeyboardInterrupt):
        executor.run_parallel(MagicMock())

    assert interrupted, "the cell shows nothing: the drain was never entered"
    assert any(arg == ["done-s1"] for arg in recorded), (
        f"an interrupt during the drain lost the results in hand: {recorded}"
    )


@pytest.mark.unit
def test_a_queued_scanner_is_not_started_after_the_cancel(tmp_path, monkeypatch):
    """Three scanners on two workers: s0 carries the cancel, s1 has finished,
    s2 is still queued. Once the cancel is in hand, the queued scanner must be
    cancelled before anything records -- a worker freed while the first sweep's
    recording runs dequeues the next queued scanner otherwise, and the drain
    then waits on a scan the cancel had already ended, against the contract
    that nothing starts after a cancel. The pool queue's worker-side reads are
    gated so the freed workers' next dequeue lands exactly inside the first
    sweep's recording: the window the cancel's queue-shutdown has to have
    closed. Reads from the thread driving the scan (the cancel's own queue
    drain) are not gated."""
    import concurrent.futures
    import queue
    from concurrent.futures import ThreadPoolExecutor

    from automated_security_helper.core.phases import scanner_executor as module

    s1_returned = threading.Event()
    may_dequeue = threading.Event()
    a_gated_dequeue_returned = threading.Event()
    ran: list = []
    recorded: list = []
    takes_lock = threading.Lock()
    worker_takes = [0]

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        ran.append(scanner_name)
        if scanner_name == "s0":
            assert s1_returned.wait(timeout=30), "s1 never returned"
            raise ScanCancelled("the scan was cancelled while s0 was running")
        if scanner_name == "s1":
            s1_returned.set()
            return ["done-s1"], True
        return ["done-s2"], True

    executor = ScannerExecutor(
        plugin_context=MagicMock(),
        progress_display=MagicMock(),
        scanner_tasks=_tasks(tmp_path, 3),
        max_workers=2,
    )
    monkeypatch.setattr(executor, "_execute_scanner", fake_execute)

    class _GatedQueue:
        """The pool's work queue, with the workers' reads after the initial
        two takes (one per worker) held until the sweep's recording is
        underway. A worker reads with get_nowait first and falls back to a
        blocking get, so both are gated; reads from the driving thread (the
        cancel's own queue drain) pass straight through."""

        def __init__(self, inner):
            self._inner = inner
            self._driver = threading.current_thread()

        def _taken_so_far(self) -> int:
            with takes_lock:
                return worker_takes[0]

        def _count_take(self) -> None:
            with takes_lock:
                worker_takes[0] += 1

        def get_nowait(self):
            if threading.current_thread() is self._driver:
                return self._inner.get_nowait()
            if self._taken_so_far() >= 2:
                # Send the worker to the blocking get, where the gate waits.
                raise queue.Empty
            item = self._inner.get_nowait()
            self._count_take()
            return item

        def get(self, *args, **kwargs):
            if threading.current_thread() is self._driver:
                return self._inner.get(*args, **kwargs)
            if self._taken_so_far() >= 2:
                assert may_dequeue.wait(timeout=30), "recording never began"
                item = self._inner.get(*args, **kwargs)
                a_gated_dequeue_returned.set()
                return item
            item = self._inner.get(*args, **kwargs)
            self._count_take()
            return item

        def __getattr__(self, name):
            return getattr(self._inner, name)

    real_init = ThreadPoolExecutor.__init__

    def init_gates_the_queue(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        self._work_queue = _GatedQueue(self._work_queue)

    monkeypatch.setattr(ThreadPoolExecutor, "__init__", init_gates_the_queue)

    real_as_completed = module.as_completed

    def the_cancel_is_handed_first(futures, *args, **kwargs):
        futures = list(futures)
        # Settle the premise before handing anything over: s0 and s1 have
        # completed (s2 cannot have -- its dequeue is gated), so the first
        # sweep deterministically has s1's finished result in hand.
        concurrent.futures.wait(
            [f for f in futures if getattr(f, "scanner_name", "") in ("s0", "s1")]
        )
        cancel_future = next(
            f for f in futures if getattr(f, "scanner_name", "") == "s0"
        )
        yield cancel_future
        yield from real_as_completed(
            [f for f in futures if f is not cancel_future], *args, **kwargs
        )

    monkeypatch.setattr(module, "as_completed", the_cancel_is_handed_first)

    def recording(*args):
        recorded.extend(args)
        if any(arg == "done-s1" or arg == ["done-s1"] for arg in args):
            may_dequeue.set()
            assert a_gated_dequeue_returned.wait(timeout=30), (
                "the cell shows nothing: no freed worker reached the queue"
            )
        return args[-1]

    monkeypatch.setattr(executor, "_process_results_fn", recording, raising=False)

    with pytest.raises(ScanCancelled):
        executor.run_parallel(MagicMock())

    assert "s2" not in ran, (
        f"a queued scanner was dequeued and run after the cancel: {ran}"
    )
    assert not any(arg == "done-s2" or arg == ["done-s2"] for arg in recorded), (
        f"a scanner started after the cancel had its results recorded: {recorded}"
    )


@pytest.mark.unit
def test_a_scan_cancelled_by_one_scanner_starts_no_queued_scanner(
    tmp_path, monkeypatch
):
    """A scanner can raise ScanCancelled while the scan's cancel event is
    unset -- a stop that reaches one scanner directly. The contract that a
    cancelled scan starts nothing new holds there too: a worker that dequeues
    the next queued scanner before the queue-shutdown can cancel it must find
    the earlier ScanCancelled at the start check itself. The shutdown is held,
    bounded, until the worker has entered the start check for s1, so the race
    the contract decides is pinned on every interpreter -- a worker whose
    dequeue comes later (3.12's blocking get) otherwise loses it to the
    queue-shutdown and the cell measures nothing."""
    from concurrent.futures import ThreadPoolExecutor

    ran: list = []
    s1_reached_the_start_check = threading.Event()

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        ran.append(scanner_name)
        if scanner_name == "s0":
            raise ScanCancelled("the scan was cancelled while s0 was running")
        return [f"done-{scanner_name}"], True

    executor = ScannerExecutor(
        plugin_context=MagicMock(),
        progress_display=MagicMock(),
        scanner_tasks=_tasks(tmp_path, 2),
        max_workers=1,
    )
    monkeypatch.setattr(executor, "_execute_scanner", fake_execute)

    real_safe = ScannerExecutor._safe_execute_scanner

    def noting_the_start_check(self, scanner_name, scanner_plugin, scan_targets):
        if scanner_name == "s1":
            s1_reached_the_start_check.set()
        return real_safe(self, scanner_name, scanner_plugin, scan_targets)

    monkeypatch.setattr(
        ScannerExecutor, "_safe_execute_scanner", noting_the_start_check
    )

    real_shutdown = ThreadPoolExecutor.shutdown

    def shutdown_after_the_dequeue(self, *args, **kwargs):
        assert s1_reached_the_start_check.wait(timeout=30), (
            "the cell shows nothing: the worker never reached s1's start check"
        )
        return real_shutdown(self, *args, **kwargs)

    monkeypatch.setattr(ThreadPoolExecutor, "shutdown", shutdown_after_the_dequeue)

    with pytest.raises(ScanCancelled):
        executor.run_parallel(MagicMock())

    # Independent of the patch: with the hold gone (a refactor that stops
    # going through ThreadPoolExecutor.shutdown, or a swallowed assert), the
    # worker can lose the dequeue to the queue-shutdown, s1 never reaches
    # the start check, and the assert below passes having pinned nothing.
    # Measured: 3.12's blocking get loses every time; on 3.14 the worker
    # almost always wins, and this assert catches the run in about 120
    # where it doesn't.
    assert s1_reached_the_start_check.is_set(), (
        "the cell shows nothing: run_parallel ended without the worker "
        "reaching s1's start check, so the race was never pinned"
    )
    late = [name for name in ran if name != "s0"]
    assert not late, f"a queued scanner started after the scan was cancelled: {late}"


@pytest.mark.unit
def test_a_parallel_run_starts_no_scanner_once_the_cancel_event_is_set(
    tmp_path, monkeypatch
):
    """With the scan's cancel event already set, no scanner starts: the
    pre-start check in _safe_execute_scanner is what raises, before any
    scanner's own code runs. None of the scanners here raises on its own,
    so without that check every one of them would run and the scan would
    return instead of raising."""
    started: list = []

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        started.append(scanner_name)
        return [], True

    executor = _executor(_tasks(tmp_path, 3))
    monkeypatch.setattr(executor, "_execute_scanner", fake_execute)
    event = threading.Event()
    event.set()
    with cancel_scope(event):
        with pytest.raises(ScanCancelled):
            executor.run_parallel(MagicMock())
    assert started == [], started


@pytest.mark.unit
def test_a_cancels_own_future_is_not_a_completed_scanner(tmp_path, monkeypatch):
    """In a cancelled run, SCAN_COMPLETE's completed_count counts scanners
    that completed -- returned or failed -- not the cancel's own future.
    Two scanners, s0 carrying the cancel and s1 finished: s1's completion
    is the first and only one, so its SCAN_COMPLETE says 1 of 2."""
    from automated_security_helper.plugins.events import AshEventType

    executor, _recorded, _order, _pool_cls = (
        _a_cancel_with_a_finished_siblings_result_in_hand(tmp_path, monkeypatch)
    )
    events: list = []

    def notify_records(event_type, **kwargs):
        events.append((event_type, kwargs))

    monkeypatch.setattr(executor, "_notify", notify_records)

    with pytest.raises(ScanCancelled):
        executor.run_parallel(MagicMock())

    completions = [
        kwargs
        for event_type, kwargs in events
        if event_type == AshEventType.SCAN_COMPLETE and kwargs.get("scanner") == "s1"
    ]
    assert completions, "the cell shows nothing: s1 never completed"
    assert completions[0]["completed_count"] == 1, completions
    assert completions[0]["total_count"] == 2, completions


@pytest.mark.unit
def test_a_recorded_failure_counts_as_a_completion_in_a_cancelled_run(
    tmp_path, monkeypatch
):
    """A scanner whose results could not be processed is recorded as a failure,
    and that is a finished turn too: it is announced with its own SCAN_COMPLETE,
    ``succeeded`` False, and the next completed scanner's SCAN_COMPLETE counts
    it. Three scanners -- s1's processing fails, s2 completes, s0 carries the
    cancel -- so s1's payload says it did not succeed, s2's says 2 of 3, the
    failure counted and the cancel's own future not. (The failed turn used to
    send no event at all; every finished turn is announced now, so a subscriber
    that waits for the last turn sees it end.)"""
    import concurrent.futures

    from automated_security_helper.core.phases import scanner_executor as module
    from automated_security_helper.plugins.events import AshEventType

    siblings_done = {"s1": threading.Event(), "s2": threading.Event()}

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        if scanner_name == "s0":
            assert siblings_done["s1"].wait(timeout=30), "s1 never finished"
            assert siblings_done["s2"].wait(timeout=30), "s2 never finished"
            raise ScanCancelled("the scan was cancelled while s0 was running")
        try:
            return [f"done-{scanner_name}"], True
        finally:
            siblings_done[scanner_name].set()

    executor = _executor(_tasks(tmp_path, 3))
    monkeypatch.setattr(executor, "_execute_scanner", fake_execute)

    real_as_completed = module.as_completed

    def the_cancel_is_handed_first(futures, *args, **kwargs):
        futures = list(futures)
        concurrent.futures.wait(futures)
        cancel_future = next(
            f for f in futures if getattr(f, "scanner_name", "") == "s0"
        )
        yield cancel_future
        yield from real_as_completed(
            [f for f in futures if f is not cancel_future], *args, **kwargs
        )

    monkeypatch.setattr(module, "as_completed", the_cancel_is_handed_first)

    def processing_fails_s1(*args):
        if any(arg == "done-s1" or arg == ["done-s1"] for arg in args):
            raise ValueError("processing s1's results broke")
        return args[-1]

    monkeypatch.setattr(
        executor, "_process_results_fn", processing_fails_s1, raising=False
    )

    events: list = []

    def notify_records(event_type, **kwargs):
        events.append((event_type, kwargs))

    monkeypatch.setattr(executor, "_notify", notify_records)

    with pytest.raises(ScanCancelled):
        executor.run_parallel(MagicMock())

    completions = [
        kwargs
        for event_type, kwargs in events
        if event_type == AshEventType.SCAN_COMPLETE and kwargs.get("scanner") == "s2"
    ]
    assert completions, "the cell shows nothing: s2 never completed"
    failed_turns = [
        kwargs
        for event_type, kwargs in events
        if event_type == AshEventType.SCAN_COMPLETE and kwargs.get("scanner") == "s1"
    ]
    assert len(failed_turns) == 1, failed_turns
    assert failed_turns[0]["succeeded"] is False, (
        "the cell shows nothing: s1 was announced as a success instead of a failure"
    )
    assert completions[0]["succeeded"] is True, completions
    assert completions[0]["completed_count"] == 2, completions
    assert completions[0]["total_count"] == 3, completions


@pytest.mark.parametrize("method", ["run_parallel", "run_sequential"])
@pytest.mark.unit
def test_a_new_run_on_the_same_executor_starts_its_scanners(
    tmp_path, monkeypatch, method
):
    """The cancel memory is the run's, not the executor's: each run begins
    with a fresh event, so a cancelled first run does not refuse a later
    run's starts on the same executor."""

    def cancelling(scanner_name, scanner_plugin, scan_targets):
        raise ScanCancelled(f"the scan was cancelled while {scanner_name} ran")

    executor = _executor(_tasks(tmp_path, 2))
    monkeypatch.setattr(executor, "_execute_scanner", cancelling)
    with pytest.raises(ScanCancelled):
        getattr(executor, method)(MagicMock())

    started: list = []

    def succeeding(scanner_name, scanner_plugin, scan_targets):
        started.append(scanner_name)
        return [], True

    monkeypatch.setattr(executor, "_execute_scanner", succeeding)
    getattr(executor, method)(MagicMock())
    assert sorted(started) == ["s0", "s1"], started


@pytest.mark.unit
def test_a_sequential_run_starts_no_scanner_after_the_cancel(tmp_path, monkeypatch):
    started = []
    event = threading.Event()

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        started.append(scanner_name)
        event.set()  # the client cancels while the first scanner runs
        return []

    executor = _executor(_tasks(tmp_path, 3))
    monkeypatch.setattr(executor, "_execute_scanner", fake_execute)
    with cancel_scope(event):
        with pytest.raises(ScanCancelled):
            executor.run_sequential(MagicMock())

    assert started == ["s0"], started


@pytest.mark.unit
def test_the_scan_phases_own_scanner_runner_starts_none_after_a_cancel(tmp_path):
    """The scan phase's own check comes before anything is built.

    The phase is a bare instance with no plugin_context, so building the
    executor it delegates to would raise AttributeError: only the phase's
    own cancel check, ahead of that, gets ScanCancelled out of it. No scanner
    can start either way, since the executor would be the one to start it.
    """
    from automated_security_helper.core.phases.scan_phase import ScanPhase

    phase = ScanPhase.__new__(ScanPhase)
    event = threading.Event()
    event.set()
    with cancel_scope(event):
        with pytest.raises(ScanCancelled):
            ScanPhase._safe_execute_scanner(phase, "s0", MagicMock(), [])


def _with_its_tool(scanner_class):
    """The real scanner class with its dependency check answering True."""

    class _WithTool(scanner_class):
        def validate_plugin_dependencies(self) -> bool:
            return True

    _WithTool.__name__ = scanner_class.__name__
    _WithTool.__module__ = scanner_class.__module__
    return _WithTool


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
@pytest.mark.unit
def test_a_scanner_done_before_a_cancel_stays_in_the_phases_completions(
    tmp_path, parallel
):
    """The scan phase keeps the scanners that finished before a cancel.

    The cancel ends the executor's run by raising, and the phase synced the
    executor's completions back only after a normal return, so the phase was
    left with none. Driven through ScanPhase.execute with two real scanner
    classes; only the executor's per-scanner work is replaced. npm-audit
    finishes first; cfn-nag then sees the cancel. In parallel cfn-nag waits
    until npm-audit's results were processed, so the order is deterministic.
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.cancellation import raise_if_cancelled
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.core.phases.scan_phase import ScanPhase
    from automated_security_helper.core.phases.scan_result_processor import (
        ScanResultProcessor,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
        CfnNagScanner,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScanner,
    )

    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_with_its_tool(NpmAuditScanner), _with_its_tool(CfnNagScanner)],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    cancel = threading.Event()
    first_processed = threading.Event()
    ran = []

    def _process(processor, container, aggregated_results):
        first_processed.set()
        return aggregated_results

    def _execute(executor_self, scanner_name, scanner_plugin, scan_targets):
        ran.append(scanner_name)
        if not parallel:
            # The next scanner's start sees the cancel.
            cancel.set()
            return [
                ScanResultsContainer(
                    scanner_name=scanner_name, status=ScannerStatus.PASSED
                )
            ]
        if scanner_name == "npm-audit":
            return [
                ScanResultsContainer(
                    scanner_name=scanner_name, status=ScannerStatus.PASSED
                )
            ]
        assert first_processed.wait(10), "npm-audit was never processed"
        cancel.set()
        raise_if_cancelled()
        return []

    with (
        patch.object(
            ScannerExecutor, "_execute_scanner", autospec=True, side_effect=_execute
        ),
        patch.object(
            ScanResultProcessor,
            "process_container",
            autospec=True,
            side_effect=_process,
        ),
        cancel_scope(cancel),
    ):
        with pytest.raises(ScanCancelled):
            phase.execute(
                aggregated_results=aggregated, parallel=parallel, max_workers=2
            )

    expected = [ran[0]] if not parallel else ["npm-audit"]
    assert [plugin.config.name for plugin in phase._completed_scanners] == expected, ran


@pytest.mark.parametrize(
    "recorded", [True, False], ids=["after-a-completion", "before-any-record"]
)
@pytest.mark.parametrize("ending", ["cancel", "keyboard-interrupt"])
@pytest.mark.unit
def test_an_interrupted_run_sends_no_execution_complete(tmp_path, ending, recorded):
    """A cancelled run takes interrupted semantics, as Ctrl-C does.

    The engine sends no EXECUTION_COMPLETE (the run did not complete, and a
    subscriber reading that event as "the scan finished" would be told so by
    a cancel), stops the display as interrupted, and still carries the
    completions the scan phase recorded before the end. No shipped handler
    subscribes to EXECUTION_COMPLETE, and the MCP registry's transitions are
    direct calls on the scan task's own outcome, so nothing needs the event
    to reach its terminal state.

    The phase records its completions only once its own run starts, so an
    interrupt can arrive before the phase has any: the engine must still end
    with that interrupt, never with an error of its own from reading the
    phase's completions on the way out.
    """
    from automated_security_helper.core.cancellation import raise_if_cancelled
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.plugins import ash_plugin_manager
    from automated_security_helper.plugins.events import AshEventType

    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    orchestrator = ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        show_progress=False,
        show_summary=False,
    )
    engine = orchestrator.execution_engine
    # A recording display whose truthy `live` lets the engine's stop run.
    display = MagicMock()
    engine.progress_display = display
    event = threading.Event()
    completed_marker = MagicMock()
    sent = []
    real_notify = ash_plugin_manager.notify

    def record(event_type, *args, **kwargs):
        sent.append(event_type)
        return real_notify(event_type, *args, **kwargs)

    def scan(self, *args, **kwargs):
        if recorded:
            self._completed_scanners = [completed_marker]
        if ending == "cancel":
            event.set()
            raise_if_cancelled()
        raise KeyboardInterrupt

    with (
        patch(
            "automated_security_helper.core.execution_engine.ScanPhase.execute", scan
        ),
        patch.object(ash_plugin_manager, "notify", side_effect=record),
        cancel_scope(event),
    ):
        with pytest.raises(ScanCancelled if ending == "cancel" else KeyboardInterrupt):
            engine.execute_phases(phases=["scan"])

    assert AshEventType.EXECUTION_COMPLETE not in sent, sent
    assert [c is completed_marker for c in engine._completed_scanners] == (
        [True] if recorded else []
    )
    display.stop.assert_called_with(interrupted=True)


@pytest.mark.parametrize("raised", ["cancel", "error"])
@pytest.mark.unit
def test_a_scan_phase_start_handler_that_raises_ends_the_run_with_it(tmp_path, raised):
    """A SCAN_PHASE_START handler that raises ends the run with what it raised.

    The handler runs in ScanPhase.execute before the phase's own run starts, so
    the phase has recorded no completions yet. A cancel raised there takes
    interrupted semantics, as one raised by a scanner does: no
    EXECUTION_COMPLETE, and the display stops as interrupted. An ordinary error
    propagates as itself. Reading the phase's completions on the way out must
    replace neither with an AttributeError.

    ``ash_plugin_manager.notify`` calls each subscriber with no handler around
    the call, so a subscriber's exception leaves notify as it was raised. The
    recording notify here raises the same way, after the real subscribers ran.
    """
    from automated_security_helper.core.cancellation import raise_if_cancelled
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.plugins import ash_plugin_manager
    from automated_security_helper.plugins.events import AshEventType

    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    orchestrator = ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        show_progress=False,
        show_summary=False,
    )
    engine = orchestrator.execution_engine
    # A recording display whose truthy `live` lets the engine's stop run.
    display = MagicMock()
    engine.progress_display = display
    event = threading.Event()
    failure = RuntimeError("a SCAN_PHASE_START handler failed")
    sent = []
    real_notify = ash_plugin_manager.notify

    def record(event_type, *args, **kwargs):
        sent.append(event_type)
        handled = real_notify(event_type, *args, **kwargs)
        if event_type == AshEventType.SCAN_PHASE_START:
            if raised == "cancel":
                event.set()
                raise_if_cancelled()
            raise failure
        return handled

    expected = ScanCancelled if raised == "cancel" else RuntimeError
    with (
        patch.object(ash_plugin_manager, "notify", side_effect=record),
        cancel_scope(event),
    ):
        with pytest.raises(expected) as ended:
            engine.execute_phases(phases=["scan"])

    assert AshEventType.SCAN_PHASE_START in sent, sent
    assert engine._completed_scanners == []
    if raised == "cancel":
        assert AshEventType.EXECUTION_COMPLETE not in sent, sent
        display.stop.assert_called_with(interrupted=True)
    else:
        assert ended.value is failure, repr(ended.value)


@pytest.mark.unit
def test_a_scan_phase_has_no_completions_before_its_run(tmp_path):
    """A new ScanPhase has an empty completion list before any run of its own.

    Read by the engine when the phase ends, which can be before the phase's run
    starts, and by the delegating methods, which a caller can use without one.
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
    from automated_security_helper.core.phases.scan_phase import ScanPhase

    output = tmp_path / "output"
    phase = ScanPhase(
        plugin_context=PluginContext(
            source_dir=tmp_path,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=get_default_config(),
        )
    )

    assert phase._completed_scanners == []


@pytest.mark.unit
def test_the_engine_starts_no_phase_after_a_cancel(tmp_path):
    """A cancel during the convert phase: the scan and report phases never start."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    orchestrator = ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        show_progress=False,
        show_summary=False,
    )
    engine = orchestrator.execution_engine
    event = threading.Event()
    ran = []

    def convert(self, *args, **kwargs):
        ran.append("convert")
        event.set()
        return kwargs.get("aggregated_results")

    def later(name):
        def run(self, *args, **kwargs):
            ran.append(name)
            return kwargs.get("aggregated_results")

        return run

    with (
        patch(
            "automated_security_helper.core.execution_engine.ConvertPhase.execute",
            convert,
        ),
        patch(
            "automated_security_helper.core.execution_engine.ScanPhase.execute",
            later("scan"),
        ),
        patch(
            "automated_security_helper.core.execution_engine.ReportPhase.execute",
            later("report"),
        ),
        cancel_scope(event),
    ):
        ended = None
        try:
            engine.execute_phases(phases=["convert", "scan", "report"])
        except BaseException as error:
            ended = error

    assert ran == ["convert"], ran
    assert isinstance(ended, ScanCancelled), repr(ended)


@pytest.mark.parametrize("cancelled", [True, False], ids=["cancelled", "control"])
@pytest.mark.unit
def test_a_cancel_after_the_last_scanner_starts_writes_no_results_file(
    tmp_path, monkeypatch, cancelled
):
    """A scan cancelled after its last scanner started writes no results file.

    A scanner busy in Python, rather than waiting on a child process, does not
    stop at a cancel: it returns. When it was the last to start, no scanner start
    was left to check the cancel, and the scan phase went on to write
    ash_aggregated_results.json for a scan the client had been told was
    cancelled. With no previous results to put back, nothing removed it. The
    scan phase now checks for the cancel at its end and writes nothing itself:
    the orchestrator writes the results file once every phase has run, so the
    scan is driven through it here. The control, with no cancel, shows the run
    does reach that write.

    The scan phase checks each scanner's dependencies, which ran ``uv tool list``
    and ``uv tool run ... --version`` for bandit, checkov, detect-secrets and
    semgrep; the probes answer as a host without uv would (``stub_tool_probes``).
    """
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    stub_tool_probes(monkeypatch)
    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    orchestrator = ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=output,
        show_progress=False,
        show_summary=False,
    )
    event = threading.Event()

    def the_last_scanner_returns(self, aggregated_results):
        if cancelled:
            event.set()  # the client cancels while the last scanner runs
        return aggregated_results

    with (
        patch.object(ScannerExecutor, "run_parallel", the_last_scanner_returns),
        patch.object(ScannerExecutor, "run_sequential", the_last_scanner_returns),
        cancel_scope(event),
    ):
        ended = None
        try:
            orchestrator.execute_scan(phases=["scan"])
        except BaseException as error:
            ended = error

    written = (output / "ash_aggregated_results.json").exists()
    if cancelled:
        assert not written, "the scan wrote results after the cancel"
        assert isinstance(ended, ScanCancelled), repr(ended)
    else:
        assert ended is None, repr(ended)
        assert written, "the control did not reach the results write"
