"""A scanner that raises SystemExit is that scanner's failure, not the end of the scan.

A scanner's in-process code can call ``sys.exit`` (a tool run as a library, a
plugin's own guard). SystemExit is not an Exception, so neither the per-target
handler nor ``_safe_execute_scanner`` caught it: it escaped every handler, no
scanner was recorded, and in parallel mode the pool ran every queued scanner to
completion before the process exited with the plugin's code.

Both handlers now catch SystemExit beside Exception. The control: a keyboard
interrupt is still not caught and still ends the scan.
"""

from __future__ import annotations

from pathlib import Path
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
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class ExitingScanner(ScannerPluginBase):
    """``scan()`` raises what ``raises`` holds."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        self.command = "shape-tool"
        self.tool_type = ScannerToolType.SAST
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        self._pre_scan(target=target, target_type=target_type, config=config)
        self._post_scan(target=target, target_type=target_type)
        raise self.raises


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
        config=AshConfig(project_name="exits"),
    )


def _scanner(plugin_context, raises: BaseException):
    scanner = ExitingScanner(config=_Config(), context=plugin_context)
    scanner.raises = raises
    return scanner


def _executor(plugin_context):
    return ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )


def _targets(plugin_context):
    return [{"path": Path(plugin_context.source_dir), "type": "source"}]


def test_a_system_exit_from_scan_is_the_rows_error(plugin_context):
    (row,) = _executor(plugin_context)._execute_scanner(
        "shape-tool", _scanner(plugin_context, SystemExit(3)), _targets(plugin_context)
    )

    assert row.status == ScannerStatus.ERROR
    assert row.raw_results["status"] == "failed"
    assert any("Failed to execute shape-tool" in str(e) for e in row.errors), (
        row.errors
    )


def test_a_system_exit_outside_the_per_target_handler_is_a_failure_container(
    plugin_context, monkeypatch
):
    executor = _executor(plugin_context)

    def exits(*args, **kwargs):
        raise SystemExit(4)

    monkeypatch.setattr(executor, "_execute_scanner", exits)

    results, succeeded = executor._safe_execute_scanner(
        "shape-tool", _scanner(plugin_context, SystemExit(4)), _targets(plugin_context)
    )

    assert succeeded is False
    (container,) = results
    assert container.raw_results["status"] == "failed"


def test_a_keyboard_interrupt_still_ends_the_scan(plugin_context):
    """Control: an interrupt is not a scanner's failure."""
    with pytest.raises(KeyboardInterrupt):
        _executor(plugin_context)._execute_scanner(
            "shape-tool",
            _scanner(plugin_context, KeyboardInterrupt()),
            _targets(plugin_context),
        )
