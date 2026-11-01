# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two threads invalidating the import caches at once must not race.

CPython's ``PathFinder.invalidate_caches`` deletes ``None`` entries from
``sys.path_importer_cache`` with a plain ``del`` over a snapshot of its items
and takes no lock, so two threads that both snapshot before either deletes
find the same ``None`` entry and the loser raises ``KeyError``. ASH's
per-project pool workers invalidate concurrently while resolving each
project's config and loading its plugin modules, so a correct workspace
project could be recorded FAILED with a stdlib KeyError. Every ASH call site
therefore goes through ``utils.import_caches.invalidate_import_caches``,
which serializes the stdlib call behind one lock.

The harness makes the race deterministic: a dict subclass installed as
``sys.path_importer_cache`` holds one planted ``None`` entry under an
absolute key, and a delete of that key waits on a barrier until a second
thread has taken its snapshot. The control test proves the harness exercises
the race (the bare stdlib call raises); the regression test proves the ASH
helper does not. ``sys.path_importer_cache`` is interpreter-global state, so
the fixture restores the original object on every exit.
"""

from __future__ import annotations

import importlib
import sys
import threading

import pytest

from automated_security_helper.utils.import_caches import invalidate_import_caches

pytestmark = pytest.mark.unit

#: How long a planted delete waits for the second snapshot. Under the lock
#: the second thread can never snapshot while the first holds the lock, so
#: the serialized run pays this once and then proceeds.
_RENDEZVOUS_SECONDS = 2.0


class _RacingImporterCache(dict):
    """A ``sys.path_importer_cache`` stand-in that lands the race on purpose.

    ``items()`` is the snapshot ``PathFinder.invalidate_caches`` takes; the
    second snapshot trips the barrier. A delete of the planted key waits on
    that barrier first, so whenever two threads run the stdlib call
    unserialized, both snapshots hold the planted entry before either delete
    runs, and the second delete must raise ``KeyError``.
    """

    def __init__(self, planted_key: str) -> None:
        super().__init__({planted_key: None})
        self._planted_key = planted_key
        self._barrier = threading.Barrier(2)
        self._synced = threading.Event()
        self._snapshot_lock = threading.Lock()
        self._snapshots = 0

    def _rendezvous(self) -> None:
        if self._synced.is_set() or self._barrier.broken:
            return
        try:
            self._barrier.wait(timeout=_RENDEZVOUS_SECONDS)
            self._synced.set()
        except threading.BrokenBarrierError:
            # Only one thread ever got here (the serialized case): go on.
            pass

    def items(self):
        snapshot = list(super().items())
        with self._snapshot_lock:
            self._snapshots += 1
            second_snapshot = self._snapshots == 2
        if second_snapshot:
            self._rendezvous()
        return snapshot

    def __delitem__(self, key) -> None:
        if key == self._planted_key:
            self._rendezvous()
        super().__delitem__(key)


@pytest.fixture
def racing_importer_cache(tmp_path):
    """Install the racing cache with one planted ``None`` entry, and restore."""
    planted_key = str(tmp_path / "planted-absent-landmark.zip")
    cache = _RacingImporterCache(planted_key)
    original = sys.path_importer_cache
    sys.path_importer_cache = cache
    try:
        yield cache
    finally:
        sys.path_importer_cache = original


def _run_in_two_threads(target):
    """Run ``target`` on two threads; return the exceptions they raised."""
    errors = []
    errors_lock = threading.Lock()

    def worker() -> None:
        try:
            target()
        except BaseException as exc:  # noqa: BLE001 -- collected for the assertion
            with errors_lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads), (
        "a worker thread never finished"
    )
    return errors


def test_the_bare_stdlib_call_loses_the_planted_entry_race(racing_importer_cache):
    """Control: the harness exercises the race the lock is there to stop.

    Two unserialized ``importlib.invalidate_caches()`` calls both snapshot
    the planted ``None`` entry; exactly one ``del`` wins and the other
    raises ``KeyError`` with the planted key.
    """
    errors = _run_in_two_threads(importlib.invalidate_caches)
    assert len(errors) == 1, (
        f"expected exactly one losing thread, got {errors!r}"
    )
    assert isinstance(errors[0], KeyError)
    assert racing_importer_cache._planted_key in str(errors[0])


def test_the_ash_helper_serializes_the_invalidation(racing_importer_cache):
    """Two threads through ``invalidate_import_caches`` both finish cleanly."""
    errors = _run_in_two_threads(invalidate_import_caches)
    assert errors == [], f"the serialized helper raised: {errors!r}"
    assert racing_importer_cache._planted_key not in racing_importer_cache
