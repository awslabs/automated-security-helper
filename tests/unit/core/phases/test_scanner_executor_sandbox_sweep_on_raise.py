"""The post-scan sandbox sweep runs when the scan raises, which is when it matters.

After a sandboxed scanner's ``scan()``, the executor sweeps the scanner's results
directory for symlinks and special files a process that outlived its spawn left
behind, before the results are written there. The sweep sat after the scan's
gates, so every raise skipped it: a tool that could not start, a run that did not
finish (the timeout and could-not-stop case, the one the sweep exists for), a
post-run error, or a ``scan()`` that raised. The sweep now runs in a ``finally``.

A raise from the sweep inside that ``finally`` would replace the exception already
on its way out: a scan's own failure would be reported as the sweep's, and a
keyboard interrupt (not an Exception, so not caught by the per-target handler)
would be turned into this target's error and the scan would continue. The sweep's
error is logged and raised only when nothing else is propagating.

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
    """``scan()`` raises ``raises`` when set, else returns an empty findings list."""

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
        if self.raises is not None:
            raise self.raises
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
    sweep_raises: list[BaseException] = []

    def fake_sweep(roots, values=(), *, values_unread=False):
        recorded.append([Path(root) for root in roots])
        if sweep_raises:
            raise sweep_raises[0]
        return 0

    monkeypatch.setattr(
        scanner_executor, "scanner_sandbox_scope", lambda *args, **kwargs: scope
    )
    monkeypatch.setattr(scanner_executor, "refuse_links_below", lambda *a, **k: None)
    monkeypatch.setattr(scanner_executor, "sweep_writable", fake_sweep)
    return results_dir, recorded, sweep_raises


def _row(plugin_context, raises: BaseException | None):
    config = _Config()
    scanner = RaisingScanner(config=config, context=plugin_context)
    scanner.raises = raises
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "shape-tool",
        scanner,
        [{"path": Path(plugin_context.source_dir), "type": "source"}],
    )
    return row


def _reason(row) -> str:
    return " ".join(str(error) for error in row.errors)


def test_the_sweep_runs_when_scan_raises(plugin_context, sweeps):
    results_dir, recorded, _ = sweeps

    row = _row(plugin_context, RuntimeError("the tool was killed"))

    assert row.status == ScannerStatus.ERROR
    assert recorded == [[results_dir]], recorded


def test_the_sweep_runs_once_when_scan_returns(plugin_context, sweeps):
    """Control: the one sweep after a scan that returned, as before."""
    results_dir, recorded, _ = sweeps

    row = _row(plugin_context, None)

    assert row.status == ScannerStatus.PASSED
    assert recorded == [[results_dir]], recorded


class TestASweepFailureKeepsTheExceptionAlreadyPropagating:
    def test_the_scans_own_error_stays_the_rows_reason(self, plugin_context, sweeps):
        _, _, sweep_raises = sweeps
        sweep_raises.append(RuntimeError("the sweep broke"))

        row = _row(plugin_context, RuntimeError("the tool was killed"))

        assert row.status == ScannerStatus.ERROR
        assert "the tool was killed" in _reason(row)
        assert "the sweep broke" not in _reason(row)

    def test_a_keyboard_interrupt_still_ends_the_scan(self, plugin_context, sweeps):
        """Replaced by the sweep's Exception, the interrupt was caught by the
        per-target handler as this target's error and the scan went on."""
        _, _, sweep_raises = sweeps
        sweep_raises.append(RuntimeError("the sweep broke"))

        with pytest.raises(KeyboardInterrupt):
            _row(plugin_context, KeyboardInterrupt())

    def test_a_sweep_failure_after_a_clean_scan_is_the_rows_error(
        self, plugin_context, sweeps
    ):
        """Control: with nothing else propagating the sweep's error is raised and
        graded as this target's error, as before."""
        _, _, sweep_raises = sweeps
        sweep_raises.append(RuntimeError("the sweep broke"))

        row = _row(plugin_context, None)

        assert row.status == ScannerStatus.ERROR
        assert "the sweep broke" in _reason(row)


class TestARefusalBeforeTheScanIsRedacted:
    """``refuse_links_below`` takes no redaction values, so its refusal reaches the
    row as the walk worded it, and whatever it names (a path under the results
    directory, the error the walk met) can hold a value the configuration read
    from the environment. The per-target handler redacts the exception with the
    plugin's environment values, as it redacts the sweep's, and this pins it."""

    CANARY = "env-read-canary-u18x-link-value"

    def test_the_value_is_not_in_the_rows_reason(
        self, plugin_context, sweeps, monkeypatch
    ):
        plugin_context.config._environment_values = [self.CANARY]

        def refuse(root):
            raise OSError(f"link {self.CANARY}/results/out refused below {root}")

        monkeypatch.setattr(scanner_executor, "refuse_links_below", refuse)

        row = _row(plugin_context, None)

        assert row.status == ScannerStatus.ERROR
        assert "refused below" in _reason(row), row.errors
        assert self.CANARY not in _reason(row), row.errors
        assert self.CANARY not in str(row.raw_results), row.raw_results
