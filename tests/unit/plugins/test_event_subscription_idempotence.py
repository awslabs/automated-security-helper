# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Event subscription on the shared plugin manager: once each, and thread-safe.

Why this matters now
--------------------
``ash_plugin_manager`` is a module-level singleton and ``load_internal_plugins()``
runs once per ``ScanExecutionEngine`` -- which is once per project in a workspace.
``subscribe`` appended without checking, so five projects produced five copies of
every handler and fired each one five times.

Log-only today, so nothing visibly broke. It becomes a verdict bug the moment a
handler touches results, and the next two phases are exactly the ones that add
such a handler: reporters, then workspace-level policy. Fixed now rather than
left as a trap for them.

The second defect was concurrency: ``not in``-then-assign is not atomic, so two
threads could each build a fresh list for the same event and one would overwrite
the other, silently discarding a subscription that had just succeeded. And
``notify`` iterated the live list, so a subscribe from another project's thread
mid-notify raised "list changed size during iteration".
"""

from __future__ import annotations

import threading
from typing import Callable, List

from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
)

EVENT = AshEventType.SCAN_COMPLETE


def _manager() -> AshPluginManager:
    """A manager with its own handler registry, never the shared singleton."""
    return AshPluginManager(plugin_library=AshPluginLibrary(event_handlers={}))


def _handlers(manager: AshPluginManager) -> List[Callable]:
    return manager.plugin_library.event_handlers.get(EVENT, [])


class TestIdempotence:
    def test_subscribing_the_same_callback_repeatedly_registers_it_once(self):
        """One handler per engine construction, not one per project."""
        manager = _manager()

        def handler(**kwargs):
            return "ran"

        for _ in range(5):
            manager.subscribe(EVENT, handler)

        assert len(_handlers(manager)) == 1

    def test_a_duplicated_handler_fires_once(self):
        """The consequence that would become a verdict bug in the next phases."""
        manager = _manager()
        calls: List[int] = []

        def handler(**kwargs):
            calls.append(1)
            return "ran"

        for _ in range(5):
            manager.subscribe(EVENT, handler)
        results = manager.notify(EVENT)

        assert calls == [1]
        assert results == ["ran"]

    def test_distinct_callbacks_both_register(self):
        """Dedupe must not collapse genuinely different subscribers."""
        manager = _manager()

        def first(**kwargs):
            return "a"

        def second(**kwargs):
            return "b"

        manager.subscribe(EVENT, first)
        manager.subscribe(EVENT, second)

        assert len(_handlers(manager)) == 2
        assert sorted(manager.notify(EVENT)) == ["a", "b"]

    def test_bound_methods_on_two_instances_are_two_subscribers(self):
        """Identity is ``==``, which for a bound method compares the instance too.

        Two instances of a handler class are genuinely two subscribers, and
        collapsing them would silently drop one.
        """
        manager = _manager()

        class Handler:
            def __init__(self, tag: str) -> None:
                self.tag = tag

            def on_event(self, **kwargs):
                return self.tag

        first, second = Handler("one"), Handler("two")
        manager.subscribe(EVENT, first.on_event)
        manager.subscribe(EVENT, second.on_event)
        manager.subscribe(EVENT, first.on_event)  # duplicate of the first

        assert len(_handlers(manager)) == 2
        assert sorted(manager.notify(EVENT)) == ["one", "two"]

    def test_subscribe_still_returns_the_callback(self):
        """It is used as a decorator; the return value is the contract."""
        manager = _manager()

        def handler(**kwargs):
            return None

        assert manager.subscribe(EVENT, handler) is handler
        # And on the deduplicated path, which returns early.
        assert manager.subscribe(EVENT, handler) is handler

    def test_events_are_kept_apart(self):
        manager = _manager()

        def handler(**kwargs):
            return "ran"

        manager.subscribe(EVENT, handler)
        manager.subscribe(AshEventType.ERROR, handler)

        assert len(_handlers(manager)) == 1
        assert len(manager.plugin_library.event_handlers[AshEventType.ERROR]) == 1


class TestThreadSafety:
    def test_concurrent_subscription_loses_nothing(self):
        """``not in``-then-assign let one thread clobber another's fresh list."""
        manager = _manager()
        callbacks: List[Callable] = []
        for index in range(50):

            def callback(index=index, **kwargs):
                return index

            callbacks.append(callback)

        start = threading.Event()

        def subscribe(target: Callable) -> None:
            start.wait()
            manager.subscribe(EVENT, target)

        threads = [
            threading.Thread(target=subscribe, args=(callback,))
            for callback in callbacks
        ]
        for thread in threads:
            thread.start()
        start.set()
        for thread in threads:
            thread.join(timeout=30)

        assert len(_handlers(manager)) == 50

    def test_notify_while_subscribing_does_not_raise(self):
        """``notify`` iterated the live list, which another project could append to."""
        manager = _manager()
        for index in range(10):

            def seeded(index=index, **kwargs):
                return index

            manager.subscribe(EVENT, seeded)

        errors: List[BaseException] = []
        start = threading.Event()

        def notifier() -> None:
            start.wait()
            for _ in range(200):
                try:
                    manager.notify(EVENT)
                except BaseException as exc:  # noqa: BLE001 -- the point is what escapes
                    errors.append(exc)
                    return

        def subscriber() -> None:
            start.wait()
            for index in range(200):

                def late(index=index, **kwargs):
                    return index

                manager.subscribe(EVENT, late)

        threads = [
            threading.Thread(target=notifier),
            threading.Thread(target=subscriber),
        ]
        for thread in threads:
            thread.start()
        start.set()
        for thread in threads:
            thread.join(timeout=30)

        assert errors == [], [repr(error) for error in errors]

    def test_concurrent_duplicate_subscription_still_registers_once(self):
        """The dedupe check and the append have to be one atomic step."""
        manager = _manager()

        def handler(**kwargs):
            return "ran"

        start = threading.Event()

        def subscribe() -> None:
            start.wait()
            for _ in range(50):
                manager.subscribe(EVENT, handler)

        threads = [threading.Thread(target=subscribe) for _ in range(8)]
        for thread in threads:
            thread.start()
        start.set()
        for thread in threads:
            thread.join(timeout=30)

        assert len(_handlers(manager)) == 1
