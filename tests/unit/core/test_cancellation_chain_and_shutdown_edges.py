# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of the cancel chain and the shutdown handlers.

* ``_ChainedPrompt.is_set`` read each parent's ``stop_promptly``, which
  recursed up the chain with no guard against a cycle, and the checks that keep
  a cycle from forming were unlocked check-then-set.
* The SIGTERM and SIGINT handlers read the registered scopes before they
  published the shutdown flag, so a scope registering between the two was seen
  by neither side; the first Ctrl-C published the flag only when a scope was
  registered.
* A previous SIGINT disposition that is not callable left the first Ctrl-C
  without any effect.
* ``shutdown_cancels`` unregistered every copy of an event, so an inner
  registration of the same event dropped the outer one.

The handlers are called directly with their module state patched; no signal is
sent to the test process.
"""

from __future__ import annotations

import signal

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.core.cancellation import (
    CancelEvent,
    link_parent,
    shutdown_cancels,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def clean_shutdown_state(monkeypatch):
    """The handlers' module state, restored after the test."""
    monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)
    monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", ())
    monkeypatch.setattr(cancellation, "_SIGTERM_SEEN", False)
    monkeypatch.setattr(cancellation, "_SIGINT_SEEN", False)
    monkeypatch.setattr(cancellation, "_GRACE_WAITS", 0)
    monkeypatch.setattr(cancellation, "_PREVIOUS_SIGTERM", None)
    monkeypatch.setattr(cancellation, "_PREVIOUS_SIGINT", None)


def _flag_spy(items, reads: list):
    """A scopes tuple that appends the shutdown flag to *reads* whenever the
    handler reads it (a truth test or an iteration)."""

    class _Spy(tuple):
        __slots__ = ()

        def __bool__(self) -> bool:
            reads.append(cancellation._SHUTDOWN_REQUESTED)
            return len(self) > 0

        def __iter__(self):
            reads.append(cancellation._SHUTDOWN_REQUESTED)
            return super().__iter__()

    return _Spy(items)


class TestACycleInTheParentChain:
    def test_the_prompt_read_ends_instead_of_recursing(self):
        first, second = CancelEvent(), CancelEvent()
        # The state two racing links leave when each saw no cycle.
        first._parent = second
        second._parent = first

        # Red at the base: RecursionError.
        assert first.prompt.is_set() is False
        assert first.stop_promptly is False

    def test_a_prompt_set_on_an_ancestor_is_still_seen_through_a_cycle(self):
        first, second = CancelEvent(), CancelEvent()
        first._parent = second
        second._parent = first
        second.stop_promptly = True

        assert first.prompt.is_set() is True

    def test_an_ancestor_prompt_is_seen_through_a_plain_chain(self):
        root, middle, leaf = CancelEvent(), CancelEvent(), CancelEvent()
        link_parent(middle, root)
        link_parent(leaf, middle)
        assert leaf.prompt.is_set() is False

        root._signalled = True

        assert leaf.prompt.is_set() is True

    def test_the_cycle_check_and_the_store_run_under_one_lock(self, monkeypatch):
        held = []
        real = cancellation._chains_to

        def watching(event, target):
            held.append(cancellation._PARENT_LINK_LOCK.locked())
            return real(event, target)

        monkeypatch.setattr(cancellation, "_chains_to", watching)

        link_parent(CancelEvent(), CancelEvent())

        # Red at the base: there was no lock to hold.
        assert held == [True]


class TestTheShutdownFlagIsPublishedFirst:
    def test_sigterm_publishes_the_flag_before_it_reads_the_scopes(
        self, monkeypatch, clean_shutdown_state
    ):
        event = CancelEvent()
        reads: list = []
        monkeypatch.setattr(
            cancellation, "_SHUTDOWN_SCOPES", _flag_spy((event,), reads)
        )

        cancellation._handle_sigterm(signal.SIGTERM, None)

        # Red at the base: the flag was still False when the scopes were read.
        assert reads
        assert all(reads)
        assert event._signalled is True

    def test_sigint_publishes_the_flag_before_it_reads_the_scopes(
        self, monkeypatch, clean_shutdown_state
    ):
        event = CancelEvent()
        reads: list = []
        monkeypatch.setattr(
            cancellation, "_SHUTDOWN_SCOPES", _flag_spy((event,), reads)
        )
        monkeypatch.setattr(cancellation, "_PREVIOUS_SIGINT", lambda *a: None)

        cancellation._handle_sigint(signal.SIGINT, None)

        assert reads
        assert all(reads)
        assert event._signalled is True

    def test_a_first_ctrl_c_with_no_scope_still_requests_shutdown(
        self, monkeypatch, clean_shutdown_state
    ):
        monkeypatch.setattr(cancellation, "_PREVIOUS_SIGINT", lambda *a: None)

        cancellation._handle_sigint(signal.SIGINT, None)

        # Red at the base: the flag was set only inside `if scopes`.
        assert cancellation.shutdown_requested() is True
        late = CancelEvent()
        with shutdown_cancels(late):
            assert late.is_set()
            assert late.stop_promptly


class TestAFirstCtrlCWithoutACallablePreviousHandler:
    @pytest.mark.parametrize("previous", [signal.SIG_DFL, None])
    def test_it_raises_keyboard_interrupt(
        self, monkeypatch, clean_shutdown_state, previous
    ):
        monkeypatch.setattr(cancellation, "_PREVIOUS_SIGINT", previous)

        # Red at the base: nothing was raised and the Ctrl-C had no effect.
        with pytest.raises(KeyboardInterrupt):
            cancellation._handle_sigint(signal.SIGINT, None)

    def test_a_callable_previous_handler_is_still_the_one_chained(
        self, monkeypatch, clean_shutdown_state
    ):
        seen = []
        monkeypatch.setattr(
            cancellation, "_PREVIOUS_SIGINT", lambda signum, frame: seen.append(signum)
        )

        cancellation._handle_sigint(signal.SIGINT, None)

        assert seen == [signal.SIGINT]


class TestNestedRegistrationsOfOneEvent:
    def test_the_inner_exit_leaves_the_outer_registration(
        self, monkeypatch, clean_shutdown_state
    ):
        event = CancelEvent()

        with shutdown_cancels(event):
            with shutdown_cancels(event):
                assert cancellation._SHUTDOWN_SCOPES.count(event) == 2
            # Red at the base: the inner exit removed every copy.
            assert cancellation._SHUTDOWN_SCOPES == (event,)

        assert cancellation._SHUTDOWN_SCOPES == ()

    def test_two_different_events_still_unregister_independently(
        self, clean_shutdown_state
    ):
        first, second = CancelEvent(), CancelEvent()

        with shutdown_cancels(first):
            with shutdown_cancels(second):
                assert cancellation._SHUTDOWN_SCOPES == (first, second)
            assert cancellation._SHUTDOWN_SCOPES == (first,)

        assert cancellation._SHUTDOWN_SCOPES == ()
