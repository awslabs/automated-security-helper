"""The post-scan sandbox sweep runs when the scan raises, which is when it matters.

After a sandboxed scanner's ``scan()``, the executor sweeps the scanner's results
directory for symlinks and special files a process that outlived its spawn left
behind, before the results are written there. The sweep sat after the scan's
gates, so every raise skipped it: a tool that could not start, a run that did not
finish (the timeout and could-not-stop case, the one the sweep exists for), a
post-run error, or a ``scan()`` that raised. The sweep now runs in a ``finally``.

The sandbox is faked at the executor's seams (``scanner_sandbox_scope`` and
``sweep_writable``); no backend runs.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import (
    OfflineStrategy,
    ScannerStatus,
    ScannerToolType,
)
from automated_security_helper.core.phases import scanner_executor
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class RaisingScanner(ScannerPluginBase):
    """``scan()`` raises when ``boom`` is set, else returns an empty findings list."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        self.command = "shape-tool"
        self.tool_type = ScannerToolType.SAST
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        self._pre_scan(target=target, target_type=target_type, config=config)
        self._post_scan(target=target, target_type=target_type)
        if self.boom:
            raise RuntimeError("the tool was killed")
        return {"findings": []}


@pytest.fixture
def plugin_context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="sweep"),
    )


@pytest.fixture
def sweeps(monkeypatch, tmp_path):
    """A fake sandbox scope for every scanner, and a record of each sweep's roots."""
    results_dir = tmp_path / "sandbox-results"
    results_dir.mkdir()
    scope = SimpleNamespace(
        results_dir=results_dir,
        environment_values=(),
        environment_values_unread=False,
        backend=SimpleNamespace(name="fake"),
    )
    recorded: list[list[Path]] = []

    def fake_sweep(roots, values=(), *, values_unread=False):
        recorded.append([Path(root) for root in roots])
        return 0

    monkeypatch.setattr(
        scanner_executor, "scanner_sandbox_scope", lambda *args, **kwargs: scope
    )
    monkeypatch.setattr(scanner_executor, "refuse_links_below", lambda *a, **k: None)
    monkeypatch.setattr(scanner_executor, "sweep_writable", fake_sweep)
    return results_dir, recorded


def _row(plugin_context, boom: bool):
    config = _Config()
    scanner = RaisingScanner(config=config, context=plugin_context)
    scanner.boom = boom
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "shape-tool",
        scanner,
        [{"path": Path(plugin_context.source_dir), "type": "source"}],
    )
    return row


def test_the_sweep_runs_when_scan_raises(plugin_context, sweeps):
    results_dir, recorded = sweeps

    row = _row(plugin_context, boom=True)

    assert row.status == ScannerStatus.ERROR
    assert recorded == [[results_dir]], recorded


def test_the_sweep_runs_once_when_scan_returns(plugin_context, sweeps):
    """Control: the one sweep after a scan that returned, as before."""
    results_dir, recorded = sweeps

    row = _row(plugin_context, boom=False)

    assert row.status == ScannerStatus.PASSED
    assert recorded == [[results_dir]], recorded
