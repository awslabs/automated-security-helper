# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner pool thread judges paths in the scope of the scan that started it.

A caller can hand one resolved configuration to several orchestrators, one
after another. Each scan records its output and work directories on the
configuration as its own (``path_trust.derived_roots_scope``), and a scanner
that runs in the scanner pool must be judged against that scan's directories:
the pool submits each scanner in a copy of the submitting thread's context, so
the scan's scope reaches the pool thread. A pool thread that lost the scope
would read the whole record, and would refuse a path under an earlier scan's
output directory, and would file what it records outside every scan.

Driven through a real ``ScannerExecutor`` pool (three stub scanners, because a
single scanner runs in the calling thread) inside a real orchestrator scan.
Only the per-scanner work is replaced: each stub's ``scan`` judges the scan's
products and records a directory, from the pool thread that runs it.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.path_trust import (
    honored_path,
    record_derived_roots,
    reset_path_refusal_warnings,
)
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor

SCANNERS_PER_SCAN = 3


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


def _refused(path, source, config):
    return (
        honored_path(path, source_dir=source, key="config_file", config=config) is None
    )


def _resolved(path):
    return Path(os.path.realpath(path))


class _JudgingScanner:
    """A stub scanner whose ``scan`` runs in whatever thread the pool gives it."""

    def __init__(self, name, observe):
        self.name = name
        self._observe = observe

    def scan(self, targets):
        self._observe(self.name)
        return []


def _create(tmp_path, name, config):
    """An orchestrator on *config*, and a file in its output directory."""
    source = tmp_path / name / "src"
    source.mkdir(parents=True)
    orchestrator = ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=tmp_path / name / "out",
        resolved_config=config,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
    )
    product = tmp_path / name / "out" / "derived.yaml"
    product.parent.mkdir(parents=True, exist_ok=True)
    product.write_text("")
    return orchestrator, product


@pytest.fixture
def pool_scan(monkeypatch):
    """Replace the phases with a real scanner-pool run of stub scanners.

    Returns the products to judge (filled in by the test), and what each
    scanner observed: scan name -> list of (thread id, judgments), plus the
    id of the thread that ran each scan.
    """
    products = {}
    observed = {}
    callers = {}

    def run_pool(self, phases=None):
        name = self.source_dir.parent.name
        pool_dir = self.source_dir.parent / "pool-written"
        callers[name] = threading.get_ident()
        observed[name] = []

        def observe(_scanner_name):
            record_derived_roots(self.config, pool_dir)
            observed[name].append(
                (
                    threading.get_ident(),
                    {
                        label: _refused(product, self.source_dir, self.config)
                        for label, product in products.items()
                    },
                )
            )

        targets = [{"path": str(self.source_dir), "type": "source"}]
        scanner_tasks = [
            (f"stub-{index}", _JudgingScanner(f"stub-{index}", observe), targets)
            for index in range(SCANNERS_PER_SCAN)
        ]
        ScannerExecutor(
            plugin_context=MagicMock(),
            progress_display=MagicMock(),
            scanner_tasks=scanner_tasks,
            max_workers=SCANNERS_PER_SCAN,
        ).run_parallel(MagicMock())
        return object()

    monkeypatch.setattr(
        ScannerExecutor,
        "_execute_scanner",
        lambda self, scanner_name, scanner_plugin, scan_targets: scanner_plugin.scan(
            scan_targets
        ),
    )
    monkeypatch.setattr(ASHScanOrchestrator, "_execute_scan", run_pool)
    return products, observed, callers


def test_a_second_scans_pool_threads_judge_in_that_scans_own_scope(tmp_path, pool_scan):
    products, observed, callers = pool_scan
    config = AshConfig()

    first, products["first"] = _create(tmp_path, "first", config)
    first.execute_scan()
    second, products["second"] = _create(tmp_path, "second", config)
    second.execute_scan()

    for name, expected in (
        ("first", {"first": True}),
        ("second", {"first": False, "second": True}),
    ):
        assert len(observed[name]) == SCANNERS_PER_SCAN, name
        for thread_id, judgments in observed[name]:
            assert thread_id != callers[name], f"{name} ran a scanner in its own thread"
            assert judgments == expected, name


def test_what_a_pool_thread_records_is_filed_under_its_own_scan(tmp_path, pool_scan):
    products, _observed, _callers = pool_scan
    config = AshConfig()

    first, products["first"] = _create(tmp_path, "first", config)
    first.execute_scan()
    second, products["second"] = _create(tmp_path, "second", config)
    second.execute_scan()

    first_pool_dir = _resolved(tmp_path / "first" / "pool-written")
    second_pool_dir = _resolved(tmp_path / "second" / "pool-written")
    by_run = config._run_derived_roots
    assert first_pool_dir in by_run[first._run_id]
    assert second_pool_dir in by_run[second._run_id]
    assert second_pool_dir not in by_run[first._run_id]
    assert first_pool_dir not in by_run[second._run_id]
    # A write the pool thread made outside its scan would sit in the unscoped
    # record, which every later scan on this configuration judges against.
    unscoped = list(config._derived_roots)
    assert first_pool_dir not in unscoped
    assert second_pool_dir not in unscoped
