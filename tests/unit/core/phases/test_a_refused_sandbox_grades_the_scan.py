# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How a sandbox ASH cannot provide grades the scan: by what was asked for.

Three cases, each its own cell:

- The operator named a backend (``sandbox.mode: bwrap``) and it is not available.
  The scanner's tool could not be started as requested, so the scan is an ERROR
  with the start-failure code (127) and a reason naming the backend. MISSING
  reads as "this scanner's own dependency is not installed", which points the
  operator at the tool when the problem is the explicitly requested sandbox.
- The operator asked for ``auto``, any working backend, and none works. The
  scanner is MISSING, like any missing dependency, with the reason naming the
  backend. Sandboxing is off by default, so ``auto`` is itself a request; the
  split pinned here is named-backend vs auto, not requested vs default.
- The sandbox was refused for any other reason (here, a results directory path
  that is a symlink, which the scanned repository can commit). That is an ERROR,
  never MISSING: nothing is missing, something was refused.

In every case the scanner never runs unsandboxed. Its scan() records each call
and the cells assert none happened: the raise alone would not show it, because
ScannerExecutor turns a raise from scan() into an ERROR row too.
"""

from __future__ import annotations

import os
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
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.sandbox import scope as sandbox_scope_module
from automated_security_helper.utils.sandbox.scope import (
    SandboxUnavailable,
    clear_backend_cache,
)

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: str = "guarded"


class _NeverRuns(ScannerPluginBase):
    """A scanner whose dependencies are fine; only the sandbox can stop it.

    scan() records the call before raising, and the refusal cells assert on the
    record: the executor converts a raise from scan() into an ERROR row, so a
    regression that recorded the refusal and then ran the scanner unsandboxed
    would still show ERROR, and only the record can tell the two apart."""

    ran: List[Any] = []

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        self.ran.append(target)
        raise AssertionError("a scanner whose sandbox was refused must not run")


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
def _fresh_backend_cache():
    """The probes below must be this cell's own: the cache is per process."""
    clear_backend_cache()
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


def _run(context: PluginContext, scanner: _NeverRuns):
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (container,) = executor._execute_scanner(
        "guarded", scanner, [{"path": context.source_dir, "type": "source"}]
    )
    return container


def _error_lines(container) -> List[str]:
    raw = container.raw_results if isinstance(container.raw_results, dict) else {}
    return [str(line) for line in (*container.errors, *(raw.get("errors") or []))]


def _assert_error_not_missing(container, *said: str) -> None:
    assert container.status == ScannerStatus.ERROR, container.status
    assert not container.missing_reason, container.missing_reason
    lines = _error_lines(container)
    for text in said:
        assert any(text in line for line in lines), (text, lines)


def test_an_explicitly_requested_backend_that_is_unavailable_is_an_error(
    tmp_path, monkeypatch
):
    """The operator asked for bwrap by name and it is not there. The scan could not
    start its tool as requested: ERROR with the start-failure code, naming the
    backend, and never a MISSING that blames the scanner's own dependency."""
    _no_backend_works(monkeypatch)
    context = _context(tmp_path, "bwrap")
    scanner = _NeverRuns(config=_Config(), context=context)

    container = _run(context, scanner)

    assert not scanner.ran, f"the scanner ran unsandboxed: {scanner.ran}"
    _assert_error_not_missing(container, "could not start its tool", "bwrap")
    assert container.exit_code == 127, container.exit_code


def test_an_auto_sandbox_with_no_backend_is_missing_naming_the_backend(
    tmp_path, monkeypatch
):
    """The operator asked for auto, any working backend, and none works. The
    scanner is MISSING, like any missing dependency, and the reason names the
    backend that is missing.

    Auto set explicitly means the same as auto however it is reached: never the
    named-backend ERROR. The split is auto vs a named backend, not who set the
    mode, and the config's default is off, so auto is always somebody's choice.
    The context here records the mode as set, the way an operator's --sandbox
    auto arrives, and the assertion below pins that the shape is the explicit
    one."""
    _no_backend_works(monkeypatch)
    context = _context(tmp_path, "auto")
    assert "mode" in context.config.sandbox.model_fields_set, (
        "the cell shows nothing: auto was not explicitly set"
    )
    scanner = _NeverRuns(config=_Config(), context=context)

    container = _run(context, scanner)

    assert not scanner.ran, f"the scanner ran unsandboxed: {scanner.ran}"
    assert container.status == ScannerStatus.MISSING, container.status
    # A MISSING row never ran its tool, so nothing may claim an exit code for it:
    # the field is never set, and the model's None default reads back as None.
    assert container.exit_code is None, container.exit_code
    assert "exit_code" not in container.model_fields_set, container.exit_code
    reason = container.missing_reason or ""
    assert "bwrap" in reason, reason


@pytest.mark.skipif(os.name == "nt", reason="the planted refusal is a POSIX symlink")
def test_a_refusal_that_is_not_availability_is_an_error(tmp_path, monkeypatch):
    """A working backend, and a results directory path that is a symlink, which the
    scanned repository can commit. The sandbox is refused, nothing is missing:
    ERROR with the refusal's reason, never MISSING."""
    _every_backend_works(monkeypatch)
    context = _context(tmp_path, "auto")
    scanner = _NeverRuns(config=_Config(), context=context)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    scanners_dir = Path(context.output_dir) / "scanners"
    scanners_dir.mkdir(parents=True, exist_ok=True)
    (scanners_dir / "guarded").symlink_to(elsewhere)

    container = _run(context, scanner)

    assert not scanner.ran, f"the scanner ran unsandboxed: {scanner.ran}"
    _assert_error_not_missing(container, "symlink")


def test_control_a_working_auto_sandbox_lets_the_scan_run(tmp_path, monkeypatch):
    """The cells above are not met by refusing every sandboxed scan: with a working
    backend and nothing planted, the scanner's scan() is reached (and raises its
    own marker here)."""
    _every_backend_works(monkeypatch)
    ran: List[Any] = []

    class _Runs(_NeverRuns):
        def scan(self, target, target_type=None, *a, **k):
            ran.append(target)
            return {"severity_counts": {}}

    context = _context(tmp_path, "auto")
    scanner = _Runs(config=_Config(), context=context)

    container = _run(context, scanner)

    assert ran, "the scan never ran under a working auto sandbox"
    assert container.status != ScannerStatus.MISSING, container.status
