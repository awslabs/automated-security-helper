"""The defaulted scanner pool starts every submitted scanner at once.

ScannerExecutor's thread pool defaulted to four workers, so a run with five
scanners started only four and the fifth waited for a slot to free. Defaulted
(``max_workers=None``), the pool now sizes itself to the submitted scanner
count, capped at ``min(32, cpu + 4)`` with the cpu figure read from
``psutil.cpu_count(logical=True)`` (``os.cpu_count() or 4`` when psutil is
unavailable or answers None). An explicitly configured ``max_workers`` keeps
exactly its value, which the second test proves by showing a pool of two
starts at most two scanners before release.

Determinism: each stub scanner sets its own "started" event and then blocks on
a shared "release" event, so how many scanners have started before release is
decided by the pool size alone, never by timing. A scanner that cannot start
(no free slot) stays queued until release, because every occupied slot blocks
on the same event.
"""

import threading
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

# Generous bound on every wait, so a sizing defect fails an assertion instead
# of hanging the suite.
_WAIT = 20.0


class _PoolConfig(ScannerPluginConfigBase):
    name: str = "pooled"


class _BlockingScanner(ScannerPluginBase):
    """A real ScannerPluginBase whose scan() blocks until the test releases it.

    A real subclass rather than MagicMock(spec=ScannerPluginBase): pydantic v2
    strips model fields off the class, so a class-level spec rejects the
    attributes ScannerExecutor actually reads.
    """

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self,
        target,
        target_type=None,
        global_ignore_paths=None,
        config=None,
        *args,
        **kwargs,
    ):
        self.started.set()
        self.started_counter.release()
        # Bounded for the same reason as _WAIT; the happy path is release.set().
        self.release.wait(timeout=3 * _WAIT)
        return None


def _make_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    (source_dir / "app.py").write_text("print('x')\n")
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    work_dir = tmp_path / "work"
    work_dir.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


def _make_scanners(context, count, release, started_counter):
    scanners = []
    for _ in range(count):
        scanner = _BlockingScanner(config=_PoolConfig(enabled=True), context=context)
        scanner.started = threading.Event()
        scanner.release = release
        scanner.started_counter = started_counter
        scanner.start_time = datetime(2026, 1, 1, 10, 0, 0)
        scanner.end_time = datetime(2026, 1, 1, 10, 0, 7)
        scanner.exit_code = 0
        scanners.append(scanner)
    return scanners


def _tasks(context, scanners):
    targets = [{"path": context.source_dir, "type": "source"}]
    return [
        (f"scanner-{index}", scanner, targets) for index, scanner in enumerate(scanners)
    ]


def _make_executor(context, scanner_tasks, **kwargs):
    return ScannerExecutor(
        plugin_context=context,
        progress_display=MagicMock(),
        scanner_tasks=scanner_tasks,
        **kwargs,
    )


def _run_in_thread(executor):
    thread = threading.Thread(
        target=executor.run_parallel,
        args=(AshAggregatedResults(),),
        daemon=True,
    )
    thread.start()
    return thread


def test_defaulted_pool_starts_every_submitted_scanner_at_once(tmp_path):
    """Five scanners, no max_workers given: all five start before release."""
    context = _make_context(tmp_path)
    release = threading.Event()
    counter = threading.Semaphore(0)
    scanners = _make_scanners(context, 5, release, counter)
    executor = _make_executor(context, _tasks(context, scanners))

    thread = _run_in_thread(executor)
    try:
        for index, scanner in enumerate(scanners):
            assert scanner.started.wait(timeout=_WAIT), (
                f"scanner {index} of 5 never started before release: the "
                "defaulted pool is smaller than the submitted scanner count"
            )
        assert not release.is_set()
    finally:
        release.set()
        thread.join(timeout=_WAIT)
    assert not thread.is_alive()


def test_explicit_max_workers_stays_authoritative(tmp_path):
    """Five scanners, max_workers=2: exactly two start before release."""
    context = _make_context(tmp_path)
    release = threading.Event()
    counter = threading.Semaphore(0)
    scanners = _make_scanners(context, 5, release, counter)
    executor = _make_executor(context, _tasks(context, scanners), max_workers=2)

    thread = _run_in_thread(executor)
    try:
        for _ in range(2):
            assert counter.acquire(timeout=_WAIT), (
                "fewer than two scanners started under max_workers=2"
            )
        # Both pool threads are now blocked on the unset release event, so no
        # third scanner can start: this count is decided, not timed.
        assert sum(scanner.started.is_set() for scanner in scanners) == 2
    finally:
        release.set()
        thread.join(timeout=_WAIT)
    assert not thread.is_alive()
    # Once released, the freed slots run the remaining scanners to completion.
    for index, scanner in enumerate(scanners):
        assert scanner.started.is_set(), f"scanner {index} never ran after release"


def test_pool_size_resolution(tmp_path, monkeypatch):
    """_pool_size: explicit value exact; defaulted = task count, capped, min 1."""
    import automated_security_helper.core.phases.scanner_executor as executor_module

    # psutil answering None and os.cpu_count() -> None exercise the documented
    # ``os.cpu_count() or 4`` fallback, making the cap min(32, 4 + 4) = 8 on
    # every host.
    monkeypatch.setattr(executor_module.psutil, "cpu_count", lambda logical=False: None)
    monkeypatch.setattr(executor_module.os, "cpu_count", lambda: None)

    context = _make_context(tmp_path)
    dummy = [(f"scanner-{i}", MagicMock(), []) for i in range(5)]

    assert _make_executor(context, dummy)._pool_size() == 5
    assert _make_executor(context, dummy, max_workers=2)._pool_size() == 2
    assert _make_executor(context, [])._pool_size() == 1

    many = [(f"scanner-{i}", MagicMock(), []) for i in range(40)]
    assert _make_executor(context, many)._pool_size() == 8


def test_pool_cap_uses_the_psutil_logical_cpu_count(tmp_path, monkeypatch):
    """The defaulted cap reads psutil.cpu_count(logical=True)."""
    import automated_security_helper.core.phases.scanner_executor as executor_module

    calls = []

    def fake_cpu_count(logical=False):
        calls.append(logical)
        return 10

    monkeypatch.setattr(executor_module.psutil, "cpu_count", fake_cpu_count)

    context = _make_context(tmp_path)
    many = [(f"scanner-{i}", MagicMock(), []) for i in range(40)]
    # min(32, 10 + 4) = 14, from the patched psutil figure, not the host's.
    assert _make_executor(context, many)._pool_size() == 14
    assert calls == [True]
