# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Concurrent plugin resolution, and why pre-warming closes the race.

The defect
----------
``AshPluginManager.plugin_modules`` iterates ``plugin_library.scanners.items()``
and does ``importlib.import_module`` work *inside* the loop. Another project's
thread calling ``register_plugin_module`` writes a new key into that same dict
mid-iteration, and CPython raises ``RuntimeError: dictionary changed size during
iteration``. ``plugin_modules`` catches only ``ImportError``, so the
``RuntimeError`` escapes into ``_scan_one_project``'s broad ``except Exception``
and becomes a project reported FAILED for a reason that has nothing to do with
that project.

Why pre-warming closes it, mechanically
---------------------------------------
``plugin_modules`` returns early on a cache hit::

    if cache_key in self._resolved_plugins:
        return self.filter_plugin_modules(self._resolved_plugins[cache_key], ...)

The iteration is only reached on a cache *miss*. Pre-warming resolves every
plugin type before any worker starts, so every in-worker call takes the early
return and no thread ever iterates the dict.
``TestTheCacheIsWhatCloses`` asserts the two facts that argument rests on: the
iteration is reachable only on a miss, and ``register_plugin_module`` does not
invalidate the cache. If either changes, pre-warming stops working and one of
those tests fails.

Why the reproduction is deterministic and not a timing loop
-----------------------------------------------------------
A first attempt raced a reader thread against a writer thread and hoped the
write would land mid-iteration. It never did -- 0 out of 10 attempts -- which
made the "the race is real" test pass by collecting no errors and the "the fix
closes it" test assert the absence of something unproducible. Both proved
nothing, which is the same failure shape as a gate that cannot fail.

So the writer is released from *inside* the loop instead. ``import_module`` is
patched to signal on its first call and wait for the registration to complete,
which puts the mutation inside the iteration by construction. That makes the
cold-cache failure deterministic and the warm-cache result meaningful: with a
warm cache the hook is never reached at all, because there is no iteration.
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


class TestTheRaceIsReal:
    """Establishes the hazard, deterministically, before showing it avoided."""

    def test_a_cold_cache_raises_dictionary_changed_size(self):
        manager = _manager()
        assert "scanner" not in manager._resolved_plugins

        escaped = _resolve_while_registering(manager)

        assert escaped is not None, (
            "the registry was mutated inside plugin_modules' iteration and "
            "nothing escaped -- either the loop no longer iterates the live dict, "
            "or plugin_modules now catches RuntimeError. Both would be good news, "
            "but this test and the pre-warm rationale need rewriting."
        )
        assert isinstance(escaped, RuntimeError)
        assert "changed size during iteration" in str(escaped)

    def test_what_escapes_is_not_caught_by_plugin_modules(self):
        """It catches ImportError only, so this reaches the caller's handler.

        In ``_scan_one_project`` that handler is a broad ``except Exception``,
        which turns an unrelated project's registration into this project's
        FAILED status.
        """
        manager = _manager()
        escaped = _resolve_while_registering(manager)
        assert not isinstance(escaped, ImportError)


class TestTheCacheIsWhatCloses:
    """The two facts the pre-warm argument depends on."""

    def test_the_iteration_is_only_reached_on_a_cache_miss(self):
        manager = _manager(seed=3)
        assert "scanner" not in manager._resolved_plugins
        manager.plugin_modules("scanner")
        assert "scanner" in manager._resolved_plugins

    def test_registration_does_not_invalidate_the_cache(self):
        """If this changes, pre-warming stops closing the race.

        The argument is that a warm cache stays warm for the whole run. A future
        change clearing ``_resolved_plugins`` on registration would silently
        reopen the window; this is what catches it.
        """
        manager = _manager(seed=3)
        manager.plugin_modules("scanner")
        before = manager._resolved_plugins["scanner"]

        manager.register_plugin_module(
            plugin_type="scanner",
            plugin_module_class="added-later",
            plugin_module_path=REAL_SCANNER_MODULE,
        )

        assert manager._resolved_plugins["scanner"] is before


class TestAWarmCacheClosesIt:
    def test_the_same_forced_mutation_no_longer_escapes(self):
        """Identical construction, cache resolved first. Nothing may escape."""
        manager = _manager()
        manager.plugin_modules("scanner")  # what prewarm_plugin_registry does
        assert "scanner" in manager._resolved_plugins

        assert _resolve_while_registering(manager) is None

    def test_a_warm_resolve_never_enters_the_import_loop(self):
        """The mechanism, observed rather than inferred.

        If the warm path still imported, the previous test would be passing for
        the wrong reason -- a fast loop rather than no loop.
        """
        import importlib

        manager = _manager()
        manager.plugin_modules("scanner")

        calls: List[str] = []
        real_import = importlib.import_module

        def counting_import(name, *args, **kwargs):
            if name == REAL_SCANNER_MODULE:
                calls.append(name)
            return real_import(name, *args, **kwargs)

        with patch.object(importlib, "import_module", counting_import):
            manager.plugin_modules("scanner")

        assert calls == []

    @pytest.mark.parametrize("readers", [2, 4, 8])
    def test_many_concurrent_readers_are_safe_once_warm(self, readers):
        """A workspace at max_parallel_projects=8 is eight concurrent readers."""
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
