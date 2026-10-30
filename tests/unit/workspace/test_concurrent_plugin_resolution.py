# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Concurrent plugin resolution: a registration from another thread does not disturb it.

What the manager guarantees
---------------------------
Workspace mode runs several projects' scans in one process, so one project's thread
can call ``register_plugin_module`` while another is in ``plugin_modules``.
``plugin_modules`` copies the registrations under the manager's registry lock,
which ``register_plugin_module`` also takes, and does its
``importlib.import_module`` work over the copy. A registration landing mid-resolve
changes the dict, not the copy, so nothing reaches ``_scan_one_project``'s broad
``except Exception`` and no project is recorded FAILED for it. The resolved list is
cached with the registrations it came from, so a resolve with nothing new
registered does no import work at all (which is what ``prewarm_plugin_registry``
relies on to keep the workers out of the import loop), and the first resolve after
a new registration reads the registry again, so a plugin module a later scan
imports is part of that scan.

Why the reproduction is deterministic and not a timing loop
-----------------------------------------------------------
A first attempt raced a reader thread against a writer thread and hoped the
write would land mid-iteration. It never did -- 0 out of 10 attempts -- which
made the "the race is real" test pass by collecting no errors and the "the fix
closes it" test assert the absence of something unproducible. Both proved
nothing, which is the same failure shape as a gate that cannot fail.

So the writer is released from *inside* the loop instead. ``import_module`` is
patched to signal on its first call and wait for the registration to complete,
which puts the mutation inside the iteration by construction. The tests then
check that the registration really happened, so a pass is not a loop the writer
never entered.
"""

from __future__ import annotations

import threading
from typing import List, Optional
from unittest.mock import patch

import pytest

from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
    AshPluginRegistration,
)

pytestmark = pytest.mark.unit

#: A real, importable scanner module, so the loop body does the work it does in
#: production. A non-importable path would be caught as ImportError and skipped,
#: which would hide the hazard rather than expose it.
REAL_SCANNER_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner"
)

#: How long the writer waits to be let into the loop. Generous for the cold case,
#: where the hook fires in milliseconds, and short enough that the warm case --
#: where it never fires -- does not stall the suite.
_LOOP_ENTRY_TIMEOUT_SECONDS = 2.0


def _manager(seed: int = 8) -> AshPluginManager:
    """A manager with its own registry, seeded with resolvable scanner entries."""
    manager = AshPluginManager(plugin_library=AshPluginLibrary(scanners={}))
    for index in range(seed):
        manager.plugin_library.scanners[f"seed-{index}"] = AshPluginRegistration(
            name=f"seed-{index}",
            plugin_module_path=REAL_SCANNER_MODULE,
            version=None,
            enabled=True,
        )
    return manager


def _resolve_while_registering(manager: AshPluginManager) -> Optional[BaseException]:
    """Resolve the scanner set while a write lands *inside* the iteration.

    Returns whatever escaped ``plugin_modules``, or None. The mutation is forced
    into the loop rather than raced into it: the patched ``import_module``
    releases the writer on its first call and blocks until the write is done.

    ``plugin_modules`` does ``import importlib`` inside the method body, so there
    is no module-level attribute to patch -- the patch has to go on ``importlib``
    itself. That is process-wide for the duration, so the hook only engages for
    the one module path the loop imports; anything else passes straight through.
    """
    import importlib

    inside_loop = threading.Event()
    write_done = threading.Event()
    real_import = importlib.import_module

    def blocking_import(name, *args, **kwargs):
        if name == REAL_SCANNER_MODULE and not inside_loop.is_set():
            inside_loop.set()
            # Hold the loop open until the registry has actually been mutated.
            write_done.wait(timeout=30)
        return real_import(name, *args, **kwargs)

    def writer() -> None:
        # Short wait on purpose. On a cold cache the hook fires within
        # milliseconds; on a warm one it never fires at all, and waiting the full
        # timeout there would make the passing case the slowest test in the suite.
        if inside_loop.wait(timeout=_LOOP_ENTRY_TIMEOUT_SECONDS):
            manager.register_plugin_module(
                plugin_type="scanner",
                plugin_module_class="registered-mid-iteration",
                plugin_module_path=REAL_SCANNER_MODULE,
            )
        write_done.set()

    thread = threading.Thread(target=writer)
    thread.start()
    escaped: Optional[BaseException] = None
    try:
        with patch.object(importlib, "import_module", blocking_import):
            try:
                manager.plugin_modules("scanner")
            except BaseException as exc:  # noqa: BLE001 -- the point is what escapes
                escaped = exc
    finally:
        write_done.set()
        thread.join(timeout=30)
    return escaped


def _counting_imports(calls: List[str]):
    """Patch importlib.import_module to record the scanner module's imports."""
    import importlib

    real_import = importlib.import_module

    def counting_import(name, *args, **kwargs):
        if name == REAL_SCANNER_MODULE:
            calls.append(name)
        return real_import(name, *args, **kwargs)

    return patch.object(importlib, "import_module", counting_import)


class TestARegistrationDuringAResolve:
    """A registration forced into a resolve on a cold cache."""

    def test_a_registration_inside_a_cold_resolve_does_not_escape(self):
        manager = _manager()
        assert "scanner" not in manager._resolved_plugins

        escaped = _resolve_while_registering(manager)

        assert "registered-mid-iteration" in manager.plugin_library.scanners, (
            "the writer never registered, so the loop was not entered and this "
            "test observed nothing"
        )
        assert escaped is None, (
            "a registration made while plugin_modules was resolving escaped as "
            f"{escaped!r}; the resolve must iterate a copy of the registrations"
        )

    def test_the_resolve_still_returns_the_registered_classes(self):
        """Nothing is lost to the mutation: the seeds' class is resolved."""
        manager = _manager()
        _resolve_while_registering(manager)

        assert [cls.__name__ for cls in manager.plugin_modules("scanner")] == [
            "BanditScanner"
        ]

    def test_the_next_resolution_picks_it_up(self):
        manager = _manager()
        _resolve_while_registering(manager)
        calls: List[str] = []

        with _counting_imports(calls):
            manager.plugin_modules("scanner")

        assert calls, "the registry changed and the memo was reused anyway"
        names = [
            name for name, *_ in manager._resolved_plugins["scanner"].registrations
        ]
        assert "registered-mid-iteration" in names


class TestTheCopyIsTakenUnderTheLock:
    def test_a_resolve_waits_while_the_registry_lock_is_held(self):
        """A registration holds the lock while it inserts, so the copy must wait.

        The forced mutation above lands inside ``import_module``, after the copy, so
        it shows the resolve iterates a copy but not that the copy is taken under the
        lock. Holding the lock shows that: the resolve cannot finish until it is
        released.
        """
        manager = _manager(seed=3)
        started = threading.Event()
        finished = threading.Event()

        def resolve() -> None:
            started.set()
            manager.plugin_modules("scanner")
            finished.set()

        with manager._registry_lock:
            thread = threading.Thread(target=resolve)
            thread.start()
            assert started.wait(timeout=30)
            assert not finished.wait(timeout=0.5), (
                "plugin_modules copied the registrations without taking the lock"
            )
        thread.join(timeout=30)
        assert finished.is_set()

    def test_a_registration_waits_while_the_registry_lock_is_held(self):
        """A resolve holds the lock while it copies, so an insert must wait.

        The other half of the pair: without the lock on the insert, a registration
        could change the dict while a resolve is copying it. Holding the lock shows
        the insert takes it: the registration cannot finish until it is released.
        """
        manager = _manager(seed=3)
        started = threading.Event()
        finished = threading.Event()

        def register() -> None:
            started.set()
            manager.register_plugin_module(
                plugin_type="scanner",
                plugin_module_class="registered-while-locked",
                plugin_module_path=REAL_SCANNER_MODULE,
            )
            finished.set()

        with manager._registry_lock:
            thread = threading.Thread(target=register)
            thread.start()
            assert started.wait(timeout=30)
            assert not finished.wait(timeout=0.5), (
                "register_plugin_module inserted without taking the registry lock"
            )
            assert "registered-while-locked" not in manager.plugin_library.scanners
        thread.join(timeout=30)
        assert finished.is_set()
        assert "registered-while-locked" in manager.plugin_library.scanners


class TestTheCacheFollowsTheRegistrations:
    """What the cache does between resolves."""

    def test_the_iteration_is_only_reached_on_a_cache_miss(self):
        manager = _manager(seed=3)
        assert "scanner" not in manager._resolved_plugins
        manager.plugin_modules("scanner")
        assert "scanner" in manager._resolved_plugins

    def test_a_registration_makes_the_next_resolve_read_the_registry_again(self):
        """Once, and then the cache is warm again.

        A cache that kept serving the first resolve would give a plugin module a
        later scan imports no row in that scan's results. A cache that never
        warmed would put every workspace worker back in the import loop.
        """
        import importlib

        manager = _manager(seed=3)
        manager.plugin_modules("scanner")

        calls: List[str] = []
        real_import = importlib.import_module

        def counting_import(name, *args, **kwargs):
            if name == REAL_SCANNER_MODULE:
                calls.append(name)
            return real_import(name, *args, **kwargs)

        with patch.object(importlib, "import_module", counting_import):
            manager.plugin_modules("scanner")
            assert calls == [], "a resolve with nothing new registered imported"

            manager.register_plugin_module(
                plugin_type="scanner",
                plugin_module_class="added-later",
                plugin_module_path=REAL_SCANNER_MODULE,
            )
            manager.plugin_modules("scanner")
            assert calls, "the first resolve after a registration did not read it"

            calls.clear()
            manager.plugin_modules("scanner")
            assert calls == [], "the cache did not warm again after the re-read"

        names = [
            name for name, *_ in manager._resolved_plugins["scanner"].registrations
        ]
        assert names[-1] == "added-later"


class TestAWarmCache:
    def test_the_same_forced_mutation_does_not_escape(self):
        """Identical construction, cache resolved first. Nothing may escape."""
        manager = _manager()
        manager.plugin_modules("scanner")  # what prewarm_plugin_registry does
        assert "scanner" in manager._resolved_plugins

        assert _resolve_while_registering(manager) is None

    def test_a_warm_resolve_never_enters_the_import_loop(self):
        """With no registration since, the memo answers and nothing is imported."""
        manager = _manager()
        manager.plugin_modules("scanner")

        calls: List[str] = []
        with _counting_imports(calls):
            manager.plugin_modules("scanner")

        assert calls == []

    @pytest.mark.parametrize("readers", [2, 4, 8])
    def test_concurrent_readers_and_a_writer_are_safe(self, readers):
        """A workspace at max_parallel_projects=8 is eight concurrent readers.

        Every registration the writer makes sends the readers' next resolution
        back through the loop, so this runs the copy-and-iterate path under
        contention, not only the memo.
        """
        manager = _manager(seed=30)
        manager.plugin_modules("scanner")

        errors: List[BaseException] = []
        start = threading.Event()

        def reader() -> None:
            start.wait()
            for _ in range(20):
                try:
                    manager.plugin_modules("scanner")
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)
                    return

        def writer() -> None:
            start.wait()
            for index in range(200):
                manager.register_plugin_module(
                    plugin_type="scanner",
                    plugin_module_class=f"late-{index}",
                    plugin_module_path=REAL_SCANNER_MODULE,
                )

        threads = [threading.Thread(target=reader) for _ in range(readers)]
        threads.append(threading.Thread(target=writer))
        for thread in threads:
            thread.start()
        start.set()
        for thread in threads:
            thread.join(timeout=60)

        assert errors == [], [repr(error) for error in errors]

    def test_every_reader_sees_the_same_set(self):
        """Not a partially-registered one, which is the other half of F1."""
        manager = _manager(seed=10)
        expected = len(manager.plugin_modules("scanner"))

        seen: List[int] = []
        lock = threading.Lock()
        start = threading.Event()

        def reader() -> None:
            start.wait()
            result = manager.plugin_modules("scanner")
            with lock:
                seen.append(len(result))

        threads = [threading.Thread(target=reader) for _ in range(6)]
        for thread in threads:
            thread.start()
        start.set()
        for thread in threads:
            thread.join(timeout=60)

        assert set(seen) == {expected}
