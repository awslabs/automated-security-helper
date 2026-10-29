# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A waiter parked behind another caller's probe stops when its scan is cancelled.

The version and command probes serialize per key: a second caller asking the
same question waits for the first probe's answer instead of starting its own.
That wait took the per-key lock with a plain blocking acquire, which no
cancellation can reach: a caller whose scan was cancelled while another
caller's slow probe held the key waited that probe out, up to the probe's
subprocess timeout, and then answered as if the scan were still running. The
availability probe's own lock already polls; these cells pin the same shape
on the per-key locks.

The hold is forced: the first caller's probe blocks on an event, so the
second caller is parked for as long as the cell chooses. The cancelled
waiter must stop while the probe is still held; the probe is released only
after that is decided.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
)
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import (
    _UV_PROBE_CANCEL_POLL_SECONDS,
    UVToolRunner,
    _reset_uv_tool_runner_caches,
    get_uv_tool_command,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolated_caches(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()
    yield
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()


#: How many timed-out acquires prove a waiter is inside the polling loop.
_POLLS_THAT_PROVE_PARKED = 2

#: Generous bound for the waiter to reach that many polls (about 0.4s of work).
_PARK_WAIT_SECONDS = 20.0

#: The longest cancel-poll interval this file accepts. A cancel reaches a
#: parked waiter within one interval, so the interval is the cancellation
#: latency the cells exist to hold; a slower poll is a product decision that
#: has to change this number and say why.
_MAX_CANCEL_POLL_SECONDS = 1.0


class _CountingLock:
    """A per-key probe lock that reports its acquires to a ``_HeldProbe``.

    It replaces the module's lock factory for the length of a cell, so every
    caller of ``_get_or_create_probe_lock`` gets one. It therefore has to
    behave as the lock it wraps for any use, not only for the ``acquire`` and
    ``release`` the code uses today: ``acquire`` is counted, ``release`` is
    passed through, the context-manager protocol goes through them, and every
    other attribute (``locked`` and the rest) is the wrapped lock's own. A
    future caller that uses it some other way then reaches the waiter as an
    honest failure or the real lock's answer, not as a holder thread dying
    before it probes.
    """

    def __init__(self, lock, held):
        self._lock = lock
        self._held = held

    def acquire(self, blocking=True, timeout=-1):
        got = self._lock.acquire(blocking, timeout)
        self._held._note_acquire(blocking, timeout, got)
        if not got:
            self._held._note_timed_out_acquire()
        return got

    def release(self):
        self._lock.release()

    # Special methods are looked up on the type, so ``__getattr__`` cannot
    # supply the context-manager protocol; it is spelled out here.
    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc_info):
        self.release()

    def __getattr__(self, name):
        # Called only for names the wrapper does not define.
        lock = self.__dict__.get("_lock")
        if lock is None:
            raise AttributeError(name)
        return getattr(lock, name)


class _HeldProbe:
    """A spawn stub that blocks its first caller until released.

    It also wraps the per-key probe lock so the cell can see the waiter's
    polling acquire: ``second_poll`` is set once two acquires on that lock
    have timed out, which only a waiter looping on ``acquire(timeout=...)``
    behind the holder can produce.
    """

    def __init__(self, monkeypatch):
        self.in_probe = threading.Event()
        self.release = threading.Event()
        self.second_poll = threading.Event()
        self._timed_out = 0
        self._acquires: list = []
        self._count_lock = threading.Lock()

        held = self
        make_lock = uv_tool_runner._get_or_create_probe_lock

        monkeypatch.setattr(
            uv_tool_runner,
            "_get_or_create_probe_lock",
            lambda cache_key: _CountingLock(make_lock(cache_key), held),
        )

        def blocking_spawn(command, **kwargs):
            self.in_probe.set()
            assert self.release.wait(timeout=30.0), "the probe was never released"
            return SimpleNamespace(returncode=0, stdout="9.9.9\n", stderr="")

        monkeypatch.setattr(uv_tool_runner, "spawn_run", blocking_spawn)

    def _note_acquire(self, blocking, timeout, got) -> None:
        with self._count_lock:
            self._acquires.append((blocking, timeout, got))

    def acquires(self) -> list:
        """Every ``(blocking, timeout, got)`` an acquire returned, in order."""
        with self._count_lock:
            return list(self._acquires)

    def _note_timed_out_acquire(self) -> None:
        with self._count_lock:
            self._timed_out += 1
            if self._timed_out >= _POLLS_THAT_PROVE_PARKED:
                self.second_poll.set()


def _finish(held: _HeldProbe, *threads: threading.Thread) -> None:
    """Release the holder and join the threads; asserts nothing.

    It runs in a ``finally``, so it must not raise: an assertion here would
    replace the failure that sent the cell into the ``finally``. The cell
    calls ``_assert_returned`` after the ``finally`` instead.
    """
    held.release.set()
    for thread in threads:
        thread.join(timeout=10.0)


def _assert_returned(*threads: threading.Thread) -> None:
    """Call after the ``finally``: every thread ended once the holder let go."""
    for thread in threads:
        assert not thread.is_alive(), "a probe thread never returned"


def _wait_until_parked(held: _HeldProbe, parked: threading.Thread, outcome: dict):
    """Block until the waiter has timed out twice on the probe lock's acquire.

    That is a signal from the lock itself, not a sleep: two timed-out
    acquires on the per-key lock mean the waiter is inside the polling loop,
    behind the holder, with its event unset. A waiter that has not reached the
    acquire yet, or that returned from a pre-acquire check, never sets it.
    """
    assert held.second_poll.wait(timeout=_PARK_WAIT_SECONDS), (
        f"the waiter never polled the probe lock twice: {outcome}"
    )
    assert parked.is_alive(), f"the waiter did not stay parked: {outcome}"
    assert not outcome, outcome
    # The poll rate is pinned structurally, not by timing. Every FAILED
    # acquire is one turn of the waiter's polling loop, and each turn must be
    # a blocking acquire with a timeout in (0, one cancel-poll interval]: the
    # wait then happens inside the lock call, where a cancel is checked after
    # at most one interval. A non-blocking try waits outside the lock (a sleep
    # the wrapper cannot see) and can delay a cancel by the whole sleep, so a
    # failed non-blocking try fails here, as does a blocking acquire with no
    # timeout or a timeout past the interval. A zero timeout is a busy-spin,
    # and a timeout far below the interval is a spin in all but name, so the
    # floor is a tenth of the interval. A successful acquire is not a poll
    # (the holder's, or a fast-path try that got the lock) and is not limited.
    acquires = held.acquires()
    assert acquires, "the probe lock's acquire was never called"
    polls = [a for a in acquires if not a[2]]
    assert polls, f"no failed acquire was recorded: {acquires}"
    floor = _UV_PROBE_CANCEL_POLL_SECONDS / 10
    ceiling = _UV_PROBE_CANCEL_POLL_SECONDS
    bad = [a for a in polls if not (a[0] and floor <= a[1] <= ceiling)]
    assert not bad, (
        f"failed acquire(s) {bad} are not blocking waits of "
        f"{floor}s to {_UV_PROBE_CANCEL_POLL_SECONDS}s (blocking, timeout, got): "
        "a non-blocking try, an unbounded wait, a spin or a slow poll "
        "delays a cancel or burns a core"
    )


def _waiter_call(outcome: dict, event: CancelEvent, call) -> None:
    """Run *call* under *event*, which the cell sets AFTER the waiter is parked."""
    with cancel_scope(event):
        try:
            outcome["answer"] = call()
        except ScanCancelled as exc:
            outcome["raised"] = exc


def _start_parked_waiter(held: _HeldProbe, call, started: list):
    """Start a waiter on an UNSET event and prove it is parked behind the holder.

    Parked means the holder is inside its probe (so it holds the probe lock)
    and the waiter has timed out twice on its polling acquire, with no answer
    and no cancellation: it has been through the polling loop more than once,
    not returned from a pre-acquire check.

    The thread is returned even when the wait fails, through *started*, so the
    caller's ``finally`` can still release the holder and join it.
    """
    assert held.in_probe.is_set(), "the holder is not inside its probe"
    event = CancelEvent()
    outcome: dict = {}
    parked = threading.Thread(target=_waiter_call, args=(outcome, event, call))
    started.append(parked)
    parked.start()
    _wait_until_parked(held, parked, outcome)
    return parked, event, outcome


#: A stop bound that is generous on purpose. The holder stays blocked until
#: ``_finish`` releases it, so ANY bound well under that proves the cancelled
#: waiter did not sit the other caller's probe out. It does not pin the poll
#: rate (``_wait_until_parked`` does, from the acquires the lock received),
#: and a tight bound would turn a one-second scheduling stall on a loaded CI
#: worker into a red.
_STOP_BOUND_SECONDS = max(5 * _UV_PROBE_CANCEL_POLL_SECONDS, 5.0)


def _assert_stops_without_sitting_out_the_probe(
    parked: threading.Thread, event, outcome
) -> None:
    event.set()
    parked.join(timeout=_STOP_BOUND_SECONDS)
    assert not parked.is_alive(), (
        "the cancelled waiter sat out the other caller's probe instead of stopping"
    )
    assert "raised" in outcome, outcome


def test_a_cancelled_waiter_parked_behind_a_version_probe_stops(monkeypatch):
    runner = UVToolRunner()
    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    runner.uv_executable = "/zz-fake/uv"
    held = _HeldProbe(monkeypatch)

    holder = threading.Thread(
        target=lambda: runner.get_tool_version("zz-tool", "zz-package")
    )
    holder.start()
    assert held.in_probe.wait(timeout=10.0), "the first probe never started"

    started: list = []
    try:
        parked, event, outcome = _start_parked_waiter(
            held, lambda: runner.get_tool_version("zz-tool", "zz-package"), started
        )
        _assert_stops_without_sitting_out_the_probe(parked, event, outcome)
    finally:
        _finish(held, holder, *started)
    # After the finally, so a failure above is not replaced by this one.
    _assert_returned(holder, *started)


def test_a_cancelled_waiter_parked_behind_a_command_probe_stops(monkeypatch):
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: "/zz-fake/uv")
    held = _HeldProbe(monkeypatch)

    holder = threading.Thread(target=lambda: get_uv_tool_command("zz-tool"))
    holder.start()
    assert held.in_probe.wait(timeout=10.0), "the first probe never started"

    started: list = []
    try:
        parked, event, outcome = _start_parked_waiter(
            held, lambda: get_uv_tool_command("zz-tool"), started
        )
        _assert_stops_without_sitting_out_the_probe(parked, event, outcome)
    finally:
        _finish(held, holder, *started)
    # After the finally, so a failure above is not replaced by this one.
    _assert_returned(holder, *started)


def test_an_uncancelled_waiter_still_gets_the_probes_answer(monkeypatch):
    """The must-not-flag control: polling the acquire keeps the wait itself.

    A waiter whose scan is not cancelled still waits the probe out and is
    answered, exactly as the blocking acquire answered it.
    """
    runner = UVToolRunner()
    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    runner.uv_executable = "/zz-fake/uv"
    held = _HeldProbe(monkeypatch)

    holder = threading.Thread(
        target=lambda: runner.get_tool_version("zz-tool", "zz-package")
    )
    holder.start()
    assert held.in_probe.wait(timeout=10.0), "the first probe never started"

    outcome: dict = {}

    def waiter() -> None:
        outcome["answer"] = runner.get_tool_version("zz-tool", "zz-package")

    parked = threading.Thread(target=waiter)
    try:
        parked.start()
        # Held until the lock itself reports two timed-out acquires: the
        # waiter provably goes through the polling loop (an unset event, so
        # every turn finds nothing to raise) and still has no answer when the
        # holder lets go.
        _wait_until_parked(held, parked, outcome)
    finally:
        _finish(held, holder, parked)
    # After the finally, so a failure above is not replaced by this one.
    _assert_returned(holder, parked)

    assert outcome.get("answer") == "9.9.9", outcome


def test_the_cancel_poll_interval_stays_within_the_latency_ceiling():
    """The cells above compare against the interval, so the interval is bounded here.

    Without a ceiling, raising ``_UV_PROBE_CANCEL_POLL_SECONDS`` would pass
    every cell that reads it, and the cancellation latency would grow with it.
    """
    assert 0 < _UV_PROBE_CANCEL_POLL_SECONDS <= _MAX_CANCEL_POLL_SECONDS


def test_the_counting_wrapper_behaves_as_the_lock_it_wraps(monkeypatch):
    """The wrapper replaces the lock factory, so any use of it is the lock's.

    A caller that holds the lock with ``with``, or asks ``locked()``, gets the
    wrapped lock's own behavior: the real lock is held inside the block and
    free after it, and a second acquire on a held lock times out, as it does
    on the real one, and is counted.
    """
    held = _HeldProbe(monkeypatch)
    real = threading.Lock()
    wrapped = _CountingLock(real, held)

    assert wrapped.locked() is False
    with wrapped:
        assert real.locked() is True
        assert wrapped.locked() is True
        assert wrapped.acquire(timeout=0.01) is False
    assert real.locked() is False
    assert wrapped.locked() is False

    # Two acquires reached the wrapped lock: the one ``with`` made (blocking,
    # no timeout) and the timed-out one; only the timed-out one counts as a poll.
    assert held.acquires() == [(True, -1, True), (True, 0.01, False)]
    assert held._timed_out == 1
    assert not held.second_poll.is_set()
    # A name the wrapped lock lacks is still an AttributeError, not a hang.
    assert not hasattr(wrapped, "no_such_lock_attribute")
