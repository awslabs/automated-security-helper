"""TDD tests for DA followup #55 — completed_scanners double-counted in parallel mode.

Contracts:
- Sequential mode: each successful scanner appears exactly once in completed_scanners.
- Parallel mode: each successful scanner appears exactly once in completed_scanners.
- Failed scanners (exception from _safe_execute_scanner) are NOT in completed_scanners.
"""
from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import ScanResultsContainer

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


# ---------------------------------------------------------------------------
# Minimal fixtures
# ---------------------------------------------------------------------------


def _make_plugin_context(tmp_path):
    ctx = MagicMock()
    ctx.output_dir = tmp_path / "out"
    ctx.output_dir.mkdir(parents=True, exist_ok=True)
    ctx.source_dir = tmp_path / "src"
    ctx.ignore_suppressions = True
    return ctx


def _make_progress():
    prog = MagicMock()
    prog.add_task.return_value = "task-id"
    prog.phase_task = None
    return prog


def _make_scanner_plugin(name: str) -> MagicMock:
    plugin = MagicMock()
    plugin.__class__.__name__ = name
    plugin.config = MagicMock()
    plugin.config.name = name
    plugin.config.enabled = True
    plugin.config.options = MagicMock()
    plugin.config.options.severity_threshold = "LOW"
    plugin.context = None
    plugin.errors = []
    plugin.output = []
    plugin.start_time = None
    plugin.end_time = None
    plugin.exit_code = 0
    return plugin


def _make_scan_targets(tmp_path) -> List[Dict[str, Any]]:
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    return [{"path": str(src), "type": "source"}]


def _make_executor(
    tmp_path,
    scanner_names: List[str],
    *,
    fail_names: frozenset[str] = frozenset(),
    crash_names: frozenset[str] = frozenset(),
    max_workers: int = 4,
) -> ScannerExecutor:
    """Build a ScannerExecutor with the given scanner names.

    fail_names:  scanners whose scan() raises (inner exception, caught by _execute_scanner;
                 scanner still reaches completed_scanners since _execute_scanner returns normally)
    crash_names: scanners whose config is None (outer exception path in _execute_scanner,
                 caught by _safe_execute_scanner; scanner does NOT reach completed_scanners)
    """
    plugin_context = _make_plugin_context(tmp_path)
    progress = _make_progress()

    scanner_tasks = []
    for name in scanner_names:
        plugin = _make_scanner_plugin(name)
        targets = _make_scan_targets(tmp_path)
        if name in crash_names:
            # Cause _execute_scanner's OUTER exception to fire by making config None
            plugin.config = None
        elif name in fail_names:
            # Cause scan() to raise — caught by inner try/except in _execute_scanner
            plugin.scan.side_effect = RuntimeError(f"{name} exploded")
        else:
            plugin.scan.return_value = {"findings": [], "status": "ok"}
        scanner_tasks.append((name, plugin, targets))

    return ScannerExecutor(
        plugin_context=plugin_context,
        progress_display=progress,
        scanner_tasks=scanner_tasks,
        max_workers=max_workers,
        process_results_fn=lambda c, a: a,
    )


# ---------------------------------------------------------------------------
# Sequential mode
# ---------------------------------------------------------------------------


class TestSequentialCompletedScanners:
    def test_single_scanner_counted_once(self, tmp_path):
        executor = _make_executor(tmp_path, ["bandit"])
        executor.run_sequential(AshAggregatedResults())
        assert len(executor.completed_scanners) == 1

    def test_three_scanners_each_counted_once(self, tmp_path):
        names = ["bandit", "grype", "trivy"]
        executor = _make_executor(tmp_path, names)
        executor.run_sequential(AshAggregatedResults())
        assert len(executor.completed_scanners) == 3

    def test_inner_scan_failure_still_counted(self, tmp_path):
        # scan() raises (inner exception) — _execute_scanner catches it and returns normally
        # so the scanner IS counted as completed (it ran, just produced error results)
        executor = _make_executor(tmp_path, ["bandit", "grype"], fail_names=frozenset(["grype"]))
        executor.run_sequential(AshAggregatedResults())
        assert len(executor.completed_scanners) == 2

    def test_outer_crash_not_in_completed(self, tmp_path):
        # config=None causes _execute_scanner's outer except to raise
        # _safe_execute_scanner catches it → scanner NOT in completed_scanners
        executor = _make_executor(
            tmp_path, ["bandit", "grype"], crash_names=frozenset(["grype"])
        )
        executor.run_sequential(AshAggregatedResults())
        grype_plugins = [p for p in executor.completed_scanners if p.config is None or (hasattr(p, 'config') and p.config is None)]
        # bandit succeeds; grype crashed → only bandit in completed
        assert len(executor.completed_scanners) == 1

    def test_all_crash_completed_is_empty(self, tmp_path):
        executor = _make_executor(
            tmp_path, ["bandit", "grype"], crash_names=frozenset(["bandit", "grype"])
        )
        executor.run_sequential(AshAggregatedResults())
        assert executor.completed_scanners == []


# ---------------------------------------------------------------------------
# Parallel mode
# ---------------------------------------------------------------------------


class TestParallelCompletedScanners:
    def test_single_scanner_counted_once_parallel(self, tmp_path):
        # Single scanner falls back to sequential inside run_parallel
        executor = _make_executor(tmp_path, ["bandit"], max_workers=2)
        executor.run_parallel(AshAggregatedResults())
        assert len(executor.completed_scanners) == 1

    def test_two_scanners_each_counted_once_parallel(self, tmp_path):
        executor = _make_executor(tmp_path, ["bandit", "grype"], max_workers=2)
        executor.run_parallel(AshAggregatedResults())
        assert len(executor.completed_scanners) == 2

    def test_three_scanners_each_counted_once_parallel(self, tmp_path):
        names = ["bandit", "grype", "trivy"]
        executor = _make_executor(tmp_path, names, max_workers=3)
        executor.run_parallel(AshAggregatedResults())
        assert len(executor.completed_scanners) == 3

    def test_no_duplicates_in_completed_parallel(self, tmp_path):
        names = ["bandit", "grype", "trivy"]
        executor = _make_executor(tmp_path, names, max_workers=3)
        executor.run_parallel(AshAggregatedResults())
        seen = set()
        for p in executor.completed_scanners:
            key = p.config.name
            assert key not in seen, f"scanner {key} counted more than once"
            seen.add(key)

    def test_inner_scan_failure_counted_parallel(self, tmp_path):
        # scan() raises (inner exception) → _execute_scanner returns normally
        # so the scanner IS counted (it ran, produced error results)
        executor = _make_executor(
            tmp_path, ["bandit", "grype"], fail_names=frozenset(["grype"]), max_workers=2
        )
        executor.run_parallel(AshAggregatedResults())
        assert len(executor.completed_scanners) == 2

    def test_outer_crash_not_in_completed_parallel(self, tmp_path):
        # config=None → outer exception in _execute_scanner → _safe_execute_scanner catches
        # → scanner NOT in completed_scanners
        executor = _make_executor(
            tmp_path, ["bandit", "grype"], crash_names=frozenset(["grype"]), max_workers=2
        )
        executor.run_parallel(AshAggregatedResults())
        assert len(executor.completed_scanners) == 1

    def test_mixed_success_crash_count_parallel(self, tmp_path):
        # bandit succeeds, grype crashes (outer), trivy succeeds
        names = ["bandit", "grype", "trivy"]
        executor = _make_executor(
            tmp_path, names, crash_names=frozenset(["grype"]), max_workers=3
        )
        executor.run_parallel(AshAggregatedResults())
        assert len(executor.completed_scanners) == 2
