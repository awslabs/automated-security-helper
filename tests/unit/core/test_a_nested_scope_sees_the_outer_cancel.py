# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancel set on an outer scan reaches the work nested under it.

The failure this pins
---------------------
A workspace scan has an event per project and one for the run, and a
project's worker enters its own cancel scope: with the two events unlinked,
a cancel of the RUN was invisible to every check made under a project's
scope, so cancelling the workspace stopped nothing until each project's own
event was found and set separately. The chain closes that: a child event
answers ``is_set`` and ``stop_promptly`` for itself OR any ancestor, while
``set`` stays local, so cancelling one project never stops its siblings or
the run.

Two ways a child gets its parent: built with one
(``CancelEvent(parent=...)``, for a per-project event made on the main
thread, since a bare pool worker has no ambient context to link from), or
recorded by ``cancel_scope`` at entry from the ambient event, when the
child does not have one yet.

The prompt rides the chain the same way, read per poll tick: a grace wait
blocks on the child's own prompt event but wakes at least every grace poll
tick and re-reads ``prompt.is_set()``, so a parent's prompt shortens a
running wait within one tick rather than instantly.
"""

import threading
import time

import pytest

from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
    current_cancel_event,
    link_parent,
    raise_if_cancelled,
)


def test_an_outer_cancel_is_seen_through_an_inner_scope():
    outer = CancelEvent()
    with cancel_scope(outer):
        inner = CancelEvent()
        with cancel_scope(inner):
            outer.set()
            assert inner.is_set(), "the outer cancel is invisible under the inner scope"
            with pytest.raises(ScanCancelled):
                raise_if_cancelled()


def test_an_inner_cancel_stays_local_to_its_scope():
    outer = CancelEvent()
    with cancel_scope(outer):
        inner = CancelEvent()
        with cancel_scope(inner):
            inner.set()
            assert inner.is_set()
        # Back under the outer scope: the inner cancel must not have
        # travelled up, or cancelling one project would stop its siblings.
        assert not outer.is_set()
        raise_if_cancelled()


def test_a_parent_given_at_construction_links_without_a_scope():
    """The pool shape: the per-project event is built on the MAIN thread with
    the scan-wide event as its parent, because the worker thread that will
    enter its scope has no ambient context to link from."""
    scan_wide = CancelEvent()
    project = CancelEvent(parent=scan_wide)
    assert not project.is_set()
    scan_wide.set()
    assert project.is_set()
    # The prompt chains the same way.
    sibling = CancelEvent(parent=scan_wide)
    assert not sibling.stop_promptly
    scan_wide.stop_promptly = True
    assert sibling.stop_promptly
    assert sibling.prompt.is_set(), "the prompt view does not read the chain"


def test_an_explicit_parent_is_kept_through_a_scope():
    """cancel_scope records the ambient event only on a child that has no
    parent yet: one given at construction wins."""
    built_with = CancelEvent()
    ambient = CancelEvent()
    child = CancelEvent(parent=built_with)
    with cancel_scope(ambient):
        with cancel_scope(child):
            built_with.set()
            assert child.is_set()
            assert current_cancel_event() is child


def test_the_scope_link_never_makes_a_cycle():
    """Re-entering an event under itself, or under an ambient that already
    chains to it, records no link: a cycle would turn every chain walk into
    a spin."""
    one = CancelEvent()
    with cancel_scope(one):
        with cancel_scope(one):
            raise_if_cancelled()
    other = CancelEvent(parent=one)
    with cancel_scope(other):
        with cancel_scope(one):
            # one must not take other as its parent: other already chains
            # to one, so the link would close a cycle.
            assert one._parent is None, "the scope linked a cycle"
            other.set()
            assert not one.is_set(), "the refused link is readable anyway"
            one.set()
            assert other.is_set(), "the construction-time chain stopped answering"


def test_the_prompt_chain_shortens_a_running_grace_wait():
    """subprocess_utils' grace wait blocks on the child's own prompt event
    but re-reads ``prompt.is_set()`` at least every grace poll tick, so a
    PARENT's prompt set before or during the wait cuts the remaining grace
    to the prompt grace without any change there."""
    from automated_security_helper.utils import subprocess_utils

    class _AChildThatNeverExits:
        def poll(self):
            return None

    scan_wide = CancelEvent()
    project = CancelEvent(parent=scan_wide)
    # Set after the wait begins: seen at the next tick, so the wait ends in
    # about PROMPT_STOP_GRACE_SECONDS instead of the 10 s grace.
    timer = threading.Timer(0.1, lambda: setattr(scan_wide, "stop_promptly", True))
    timer.start()
    began = time.monotonic()
    try:
        subprocess_utils._wait_out_grace(
            _AChildThatNeverExits(), None, 10.0, project.prompt
        )
    finally:
        timer.cancel()
    elapsed = time.monotonic() - began
    assert elapsed < 5.0, (
        f"the parent's prompt did not shorten the wait ({elapsed:.2f}s)"
    )


def test_a_link_given_after_construction_chains_the_events():
    """link_parent chains an event built where its parent was not in scope.

    The workspace pool's shape: per-project events are built on the submitting
    thread, and the pool worker that enters their scope has no ambient context
    for cancel_scope's own linking to read.
    """
    scan_wide = CancelEvent()
    project = CancelEvent()
    link_parent(project, scan_wide)
    assert not project.is_set()
    scan_wide.set()
    assert project.is_set()
    # The prompt chains too, like a construction-time parent's.
    scan_wide.stop_promptly = True
    assert project.prompt.is_set()


def test_a_link_does_not_replace_an_existing_parent():
    first = CancelEvent()
    chained = CancelEvent(parent=first)
    other = CancelEvent()
    link_parent(chained, other)
    other.set()
    assert not chained.is_set()
    first.set()
    assert chained.is_set()


def test_a_link_that_would_close_a_cycle_is_refused():
    """Like cancel_scope's guard: a parent already chaining to the event is
    refused, so no chain can become a cycle."""
    one = CancelEvent()
    two = CancelEvent(parent=one)
    link_parent(one, two)
    assert one._parent is None
    two.set()
    assert not one.is_set()
    # The construction-time chain still answers downward.
    one.set()
    assert two.is_set()


def test_a_plain_event_and_a_missing_parent_link_nothing():
    plain = threading.Event()
    scan_wide = CancelEvent()
    link_parent(plain, scan_wide)
    scan_wide.set()
    assert not plain.is_set()

    unlinked = CancelEvent()
    link_parent(unlinked, None)
    assert unlinked._parent is None
