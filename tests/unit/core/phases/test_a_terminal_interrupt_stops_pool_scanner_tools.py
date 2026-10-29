# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A terminal Ctrl-C stops the tools running in the scanner pool's workers.

A terminal SIGINT raises KeyboardInterrupt on the main thread only. A pool
worker's cancellable spawn watches the scan's cancel event between wait
slices, and nothing on the CLI path set that event on SIGINT -- only the
SIGTERM handler did -- so the interrupted main thread sat in the pool exit's
join while every worker's tool ran to its own end. The cell here pins the
missing link: a main-thread KeyboardInterrupt during the parallel run latches
the scan's cancel event BEFORE the pool join, so a worker waiting on that
event is released at once and a queued scanner never runs. The spawn side --
a set event stopping the child process -- is pinned by the launcher and
SIGTERM cells, so no cell here starts or signals a real process.

The sequential path has no gap: the interrupt lands inside the scanner's own
run on the main thread, and the spawn's handler is what stops the child. The
control cell pins that the sequential loop propagates the interrupt at once
and starts nothing after it.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.cancellation import (
    cancel_scope,
    current_cancel_event,
)
from automated_security_helper.core.phases import scanner_executor as module
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor

pytestmark = pytest.mark.unit

WAIT_BOUND_SECONDS = 5.0


def _tasks(tmp_path: Path, count: int):
    return [
        (f"s{i}", MagicMock(), [{"path": str(tmp_path), "type": "source"}])
        for i in range(count)
    ]


def test_a_main_thread_interrupt_latches_the_cancel_before_the_pool_join(
    tmp_path, monkeypatch
):
    """The interrupt's unwind sets the scan's cancel event before the pool's
    exit joins the workers. Three scanners on two workers: s0 and s1 are
    running when the interrupt lands, each waiting on the scan's cancel event
    as a cancellable spawn's wait loop does; s2 is still queued. Without the
    latch, the join waits out both workers' own time and the freed worker
    then dequeues and runs s2."""
    started = {"s0": threading.Event(), "s1": threading.Event()}
    ran: list = []
    saw_the_event: dict = {}

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        ran.append(scanner_name)
        if scanner_name in started:
            started[scanner_name].set()
        event = current_cancel_event()
        assert event is not None, "the pool worker lost the scan's cancel event"
        saw_the_event[scanner_name] = event.wait(timeout=WAIT_BOUND_SECONDS)
        return [], True

    executor = ScannerExecutor(
        plugin_context=MagicMock(),
        progress_display=MagicMock(),
        scanner_tasks=_tasks(tmp_path, 3),
        max_workers=2,
    )
    monkeypatch.setattr(executor, "_execute_scanner", fake_execute)

    def the_interrupt_lands_in_the_completion_wait(futures, *args, **kwargs):
        # The terminal Ctrl-C lands while the main thread waits on
        # completions, with both workers running their scanners.
        for event in started.values():
            assert event.wait(timeout=30), "a worker never started its scanner"
        raise KeyboardInterrupt("the operator pressed Ctrl-C")

    monkeypatch.setattr(
        module, "as_completed", the_interrupt_lands_in_the_completion_wait
    )

    scan_cancel = threading.Event()
    begun = time.monotonic()
    with cancel_scope(scan_cancel):
        with pytest.raises(KeyboardInterrupt):
            executor.run_parallel(MagicMock())
    took = time.monotonic() - begun

    assert scan_cancel.is_set(), (
        "the interrupt reached the pool join without the scan's cancel event "
        "set: every worker's tool runs to its own end"
    )
    assert saw_the_event == {"s0": True, "s1": True}, saw_the_event
    assert "s2" not in ran, f"a queued scanner ran after the interrupt: {ran}"
    assert took < WAIT_BOUND_SECONDS, (
        f"the join waited out the workers' own time: {took:.1f}s"
    )


def test_the_interrupts_queue_shutdown_stops_dequeues_without_a_cancel_scope(
    tmp_path, monkeypatch
):
    """The latch's queue shutdown is load-bearing on its own.

    Inside a cancel scope, a dequeued scanner is refused by the pre-start
    cancel check once the latch has set the event, so the shutdown's absence
    hides there. With no ambient cancel event there is nothing to latch and
    nothing for the pre-start check to read: the queue shutdown is the only
    thing standing between the interrupt and the freed workers dequeuing and
    running every queued scanner while the unwind waits on the pool's exit.
    Six scanners on two workers: s0 and s1 are running when the interrupt
    lands; the rest must never start.
    """
    ran: list = []
    started = {"s0": threading.Event(), "s1": threading.Event()}
    release = threading.Event()

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        ran.append(scanner_name)
        if scanner_name in started:
            started[scanner_name].set()
        # The workers hold their slots until the queue shutdown itself, which
        # is exactly the window the cell needs: a fixed sleep raced it, read
        # as a flake under load and spent its length on every run.
        release.wait(timeout=WAIT_BOUND_SECONDS)
        return [], True

    class _ReleasesWorkersOnShutdown(module.ThreadPoolExecutor):
        def shutdown(self, *args, **kwargs):
            release.set()
            return super().shutdown(*args, **kwargs)

    monkeypatch.setattr(module, "ThreadPoolExecutor", _ReleasesWorkersOnShutdown)

    executor = ScannerExecutor(
        plugin_context=MagicMock(),
        progress_display=MagicMock(),
        scanner_tasks=_tasks(tmp_path, 6),
        max_workers=2,
    )
    monkeypatch.setattr(executor, "_execute_scanner", fake_execute)

    def the_interrupt_lands_in_the_completion_wait(futures, *args, **kwargs):
        for event in started.values():
            assert event.wait(timeout=30), "a worker never started its scanner"
        raise KeyboardInterrupt("the operator pressed Ctrl-C")

    monkeypatch.setattr(
        module, "as_completed", the_interrupt_lands_in_the_completion_wait
    )

    with pytest.raises(KeyboardInterrupt):
        executor.run_parallel(MagicMock())

    assert set(ran) <= {"s0", "s1"}, (
        "a queued scanner was dequeued and run after the interrupt, with no "
        f"cancel scope to stop it at the pre-start check: {ran}"
    )


def test_a_sequential_interrupt_propagates_at_once(tmp_path, monkeypatch):
    """The sequential loop propagates a KeyboardInterrupt as itself -- the
    per-scanner handler catches Exception only -- and starts no scanner
    after it."""
    ran: list = []

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        ran.append(scanner_name)
        raise KeyboardInterrupt("the operator pressed Ctrl-C")

    executor = ScannerExecutor(
        plugin_context=MagicMock(),
        progress_display=MagicMock(),
        scanner_tasks=_tasks(tmp_path, 3),
        max_workers=3,
    )
    monkeypatch.setattr(executor, "_execute_scanner", fake_execute)

    begun = time.monotonic()
    with cancel_scope(threading.Event()):
        with pytest.raises(KeyboardInterrupt):
            executor.run_sequential(MagicMock())
    took = time.monotonic() - begun

    assert ran == ["s0"], ran
    assert took < 2.0, f"the sequential interrupt waited: {took:.1f}s"
