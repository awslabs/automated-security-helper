# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ScanPhase reads the refusal the probe scope yields, and a refusal grades the row.

``plugin_probe_scope`` documents that its block is given the refusal (None when there
was none), and ScanPhase's dependency check reads it: for a refusal the executor grades
ERROR it does not run the check, whose probes could only fail for the sandbox, and the
scanner is queued so the executor refuses it before scan(). These cells go through the
real phase, so a scope that yields nothing shows as the check running.

- A backend the operator named that is unavailable: the scanner's check does not run,
  and the scanner is the ERROR that names the backend, dependencies not blamed. The
  scanner here spawns a real probe, so a check that ran under the refusing scope would
  fail its spawn and grade the scanner MISSING.
- The control: with no refusal (sandbox off, or a named backend that works) the same
  phase runs the check.
- A refusal that is not availability (a planted symlink) leaves the row with no exit
  code: no tool started, so the row claims none. The start-failure code is the
  named-backend refusal's alone.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, List
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.sandbox import scope as sandbox_scope_module
from automated_security_helper.utils.sandbox.scope import (
    SandboxUnavailable,
    clear_backend_cache,
)

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name != "posix", reason="the probes and the planted symlink are POSIX's"
    ),
]


class _ProbingConfig(ScannerPluginConfigBase):
    name: str = "probing"


class _Probing(ScannerPluginBase):
    """A scanner whose dependency check spawns a real probe of its tool.

    Each call is recorded before the spawn, so a check that ran shows in ``probed``
    whatever the spawn then did."""

    probed: List[Any] = []

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = _ProbingConfig()
        self.command = sys.executable
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        from automated_security_helper.utils.subprocess_utils import run_command

        type(self).probed.append("ran")
        try:
            result = run_command([sys.executable, "--version"], capture_output=True)
        except Exception:  # a refusing scope raises at the spawn
            return False
        return result.returncode == 0

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        return {"severity_counts": {}}


class _CountingConfig(ScannerPluginConfigBase):
    name: str = "counting"


class _Counting(ScannerPluginBase):
    """A scanner whose dependency check starts nothing and records each call, so it
    answers under a fake backend that cannot run a process."""

    counted: List[Any] = []

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = _CountingConfig()
        self.command = sys.executable
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        type(self).counted.append("ran")
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        return {"severity_counts": {}}


def _context(tmp_path, mode: str) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="test", sandbox=SandboxConfig(mode=mode)),
    )


@pytest.fixture(autouse=True)
def _fresh_state():
    clear_backend_cache()
    _Probing.probed = []
    _Counting.counted = []
    yield
    clear_backend_cache()


def _no_backend_works(monkeypatch) -> None:
    def refused(name: str):
        raise SandboxUnavailable(f"{name} is not available: no {name} on PATH")

    monkeypatch.setattr(sandbox_scope_module, "_probe_backend", refused)


def _every_backend_works(monkeypatch) -> None:
    monkeypatch.setattr(
        sandbox_scope_module,
        "_probe_backend",
        lambda name: SimpleNamespace(name=name),
    )


def _results_of(tmp_path, mode: str, plugin_class):
    context = _context(tmp_path, mode)
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[plugin_class],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(aggregated_results=aggregated, parallel=False)
    return populate_metrics_from_unified_source(aggregated_results=results)


def test_a_named_unavailable_backend_skips_the_check_and_is_an_error(
    tmp_path, monkeypatch
):
    """The operator named bwrap and it cannot run. The scanner's check is not run
    (its probes could only fail for the sandbox), and the scan is the ERROR that
    names the backend, never a MISSING that blames the scanner's own dependency."""
    _no_backend_works(monkeypatch)
    results = _results_of(tmp_path, "bwrap", _Probing)
    row = results.scanner_results.get("probing")
    assert row is not None, "the scanner left no row"

    assert _Probing.probed == [], f"the check ran under the refusal: {_Probing.probed}"
    assert row.status == ScannerStatus.ERROR, (row.status, row.missing_reason)
    assert row.dependencies_satisfied is True, row
    assert not row.missing_reason, row.missing_reason
    recorded = json.dumps(results.additional_reports.get("probing") or {})
    assert "could not start its tool" in recorded, recorded
    assert "bwrap" in recorded, recorded


@pytest.mark.parametrize("mode", ["off", "bwrap"])
def test_control_with_no_refusal_the_dependency_check_runs(tmp_path, monkeypatch, mode):
    """The cell above is not met by skipping every check under a sandbox: with the
    sandbox off, or a named backend that works, the same phase runs the check."""
    _every_backend_works(monkeypatch)
    _results_of(tmp_path, mode, _Counting)

    assert _Counting.counted, f"the check never ran with sandbox.mode {mode!r}"


def test_control_a_refusal_that_is_not_availability_carries_no_exit_code(
    tmp_path, monkeypatch
):
    """A working backend, and a results directory path that is a symlink, which the
    scanned repository can commit. Nothing is missing and no tool started: the row is
    the ERROR naming the refusal, and it claims no exit code. The start-failure code
    belongs to the named-backend refusal only."""
    _every_backend_works(monkeypatch)
    context = _context(tmp_path, "auto")
    scanner = _Counting(config=_CountingConfig(), context=context)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    scanners_dir = Path(context.output_dir) / "scanners"
    scanners_dir.mkdir(parents=True, exist_ok=True)
    (scanners_dir / "counting").symlink_to(elsewhere)

    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (container,) = executor._execute_scanner(
        "counting", scanner, [{"path": context.source_dir, "type": "source"}]
    )

    assert container.status == ScannerStatus.ERROR, container.status
    assert not container.missing_reason, container.missing_reason
    raw = container.raw_results if isinstance(container.raw_results, dict) else {}
    lines = [str(line) for line in (*container.errors, *(raw.get("errors") or []))]
    assert any("symlink" in line for line in lines), lines
    assert container.exit_code is None, container.exit_code
    assert "exit_code" not in container.model_fields_set, container.exit_code
