# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two threads registering shutdown scopes at once keep both registrations.

``shutdown_cancels`` rebuilds the registration tuple in place: it reads the
global, builds a new tuple, and stores it back, on entry and again in its
``finally``. Two threads doing that at once can both read the same old tuple,
and the second store then erases the first thread's registration -- a scan
whose event is not in the tuple is never cancelled by a shutdown signal, so
the process takes the no-scan die-now instead of a cooperative stop.

The registry writers in the same module already serialize their rebuilds
under one writer lock while the signal handlers keep reading the tuple
lock-free; these cells pin that the shutdown registration does the same.

The interleaving is forced, not raced: the planted registration tuple is a
subclass whose ``__add__`` pauses the first thread inside its
read-modify-write until the second thread shows what it does next. The
writer lock is wrapped so its second entry announces itself: if the second
thread reaches the lock while the first is paused, the registrations are
serialized and the first thread goes on at once; if the second thread
completes its whole registration instead, nothing serialized them and the
first thread's stale store is checked. Neither signal depends on a timeout,
which is only a hang guard.
"""

from __future__ import annotations

import threading

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.core.cancellation import (
    CancelEvent,
    shutdown_cancels,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def no_registrations(monkeypatch):
    """The registration tuple empty, as a fresh process starts."""
    monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", ())
    monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)


def test_two_threads_registering_at_once_keep_both_events(
    no_registrations, monkeypatch
):
    first_in_add = threading.Event()
    peer_registered = threading.Event()
    peer_tried_lock = threading.Event()
    peer_signal = threading.Event()
    gate = threading.Lock()
    state = {"first": True, "lock_entries": 0}
    real_lock = cancellation._TOOL_GROUPS_WRITE_LOCK

    class AnnouncingLock:
        """The writer lock, announcing the second thread's attempt to take it.

        The first entry is the paused thread's registration. The second is
        the peer's, and it is announced before it blocks, so the paused
        thread learns the peer is queued behind the lock without waiting for
        a timeout.
        """

        def __enter__(self):
            with gate:
                state["lock_entries"] += 1
                second = state["lock_entries"] == 2
            if second:
                peer_tried_lock.set()
                peer_signal.set()
            real_lock.acquire()
            return self

        def __exit__(self, *exc_info):
            real_lock.release()

    class PausingTuple(tuple):
        """Pauses the first appender mid read-modify-write.

        Unserialized, the peer completes its whole registration against the
        same starting tuple while this one is paused, and the paused store
        then erases the peer's. Serialized, the peer's lock attempt releases
        this one at once and both land. The result is a plain tuple either
        way, so only the first appends are instrumented.
        """

        __slots__ = ()

        def __add__(self, other):
            with gate:
                first = state["first"]
                state["first"] = False
            if first:
                first_in_add.set()
                # Released by the peer reaching the lock or finishing its
                # registration; the timeout only guards against a hang.
                peer_signal.wait(timeout=10.0)
            return tuple(self) + tuple(other)

    monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", PausingTuple())
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS_WRITE_LOCK", AnnouncingLock())

    event_a = CancelEvent()
    event_b = CancelEvent()
    a_registered = threading.Event()
    release = threading.Event()

    def hold_a():
        with shutdown_cancels(event_a):
            a_registered.set()
            release.wait(timeout=10.0)

    def hold_b():
        with shutdown_cancels(event_b):
            peer_registered.set()
            peer_signal.set()
            release.wait(timeout=10.0)

    thread_a = threading.Thread(target=hold_a)
    thread_b = threading.Thread(target=hold_b)
    thread_a.start()
    try:
        assert first_in_add.wait(timeout=10.0), (
            "thread A never reached the registration append"
        )
        thread_b.start()
        assert a_registered.wait(timeout=10.0), "thread A never registered"
        assert peer_registered.wait(timeout=10.0), "thread B never registered"

        registered = cancellation._SHUTDOWN_SCOPES
        assert any(entry is event_a for entry in registered), registered
        assert any(entry is event_b for entry in registered), (
            "the registration thread B completed was erased by thread A's "
            "concurrent store, so a shutdown signal would never cancel B's "
            "scan"
        )
    finally:
        release.set()
        thread_a.join(timeout=10.0)
        thread_b.join(timeout=10.0)

    assert not thread_a.is_alive(), "thread A did not exit its registration"
    assert not thread_b.is_alive(), "thread B did not exit its registration"
    assert tuple(cancellation._SHUTDOWN_SCOPES) == (), (
        "both registrations ended with their scopes"
    )


def test_a_registration_after_shutdown_was_requested_is_cancelled_at_entry(
    no_registrations, monkeypatch
):
    """The must-not-flag control: the append-then-check entry ordering.

    A registration that starts after a shutdown was requested is cancelled
    on the spot. The entry's check runs after the append on a normal thread
    frame, and serializing the append must not move or lose that check.
    """
    monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", True)
    event = CancelEvent()
    with shutdown_cancels(event):
        assert event.is_set(), "the late registration was not cancelled"
        assert event.stop_promptly is True
    assert tuple(cancellation._SHUTDOWN_SCOPES) == ()


def test_an_interrupt_at_the_registration_locks_exit_still_unregisters(
    no_registrations, monkeypatch
):
    """An interrupt after the append's store has landed must not leak the event.

    A Ctrl-C handler chains to the default handler, which raises
    ``KeyboardInterrupt`` in the main thread at any bytecode boundary,
    including the one right after the lock is released. The registration is
    then done but the body never ran, so only the ``finally`` can remove it.
    """
    real_lock = cancellation._TOOL_GROUPS_WRITE_LOCK
    exits = {"count": 0}

    class RaisingOnFirstExit:
        def __enter__(self):
            real_lock.acquire()
            return self

        def __exit__(self, *exc_info):
            real_lock.release()
            exits["count"] += 1
            if exits["count"] == 1:
                raise KeyboardInterrupt

    monkeypatch.setattr(cancellation, "_TOOL_GROUPS_WRITE_LOCK", RaisingOnFirstExit())

    event = CancelEvent()
    with pytest.raises(KeyboardInterrupt):
        with shutdown_cancels(event):
            pytest.fail("the body must not run after the interrupt")

    assert tuple(cancellation._SHUTDOWN_SCOPES) == (), (
        "an interrupt at the registration lock's exit left the event "
        "registered, so later shutdown signals would keep driving a finished "
        "scan's event"
    )
