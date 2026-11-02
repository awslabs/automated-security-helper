# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A row ERROR for an ungradable result is not also marked MISSING.

The executor grades MISSING only a scan() that returns False, the template's answer
for unavailable dependencies; an empty dict or list is a result it cannot grade, and
that row is ERROR with the reason. A later block then read the plugin's recorded
``dependencies_satisfied`` and, finding it False, wrote a ``missing_reason`` on the
row and logged "marking as MISSING" beside it, so a row that was ERROR for one cause
said it was MISSING too: the state the False-only MISSING branch exists to end.

The block now leaves an ERROR row alone. The recorded flag itself stays on the row
(a fact the scan recorded), and the control is a report returned with the
dependencies recorded unavailable: not ERROR, so it keeps its reason as before.
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
from automated_security_helper.core.phases import scanner_executor
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class UnavailableScanner(ScannerPluginBase):
    """Records its dependencies unavailable during scan() and returns ``returned``."""

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
        self.dependencies_satisfied = False
        self.dependency_unavailable_reason = "shape-tool is not installed"
        return self.returned


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
        config=AshConfig(project_name="one-cause"),
    )


def _row(plugin_context, returned):
    scanner = UnavailableScanner(config=_Config(), context=plugin_context)
    scanner.returned = returned
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "shape-tool",
        scanner,
        [{"path": Path(plugin_context.source_dir), "type": "source"}],
    )
    return row


def _warnings(monkeypatch) -> list:
    lines: list = []
    monkeypatch.setattr(
        scanner_executor.ASH_LOGGER,
        "warning",
        lambda message, *args, **kwargs: lines.append(str(message)),
    )
    return lines


class TestAnErrorRowGetsNoMissingReason:
    def test_an_ungradable_result_is_error_alone(self, plugin_context, monkeypatch):
        warnings = _warnings(monkeypatch)

        row = _row(plugin_context, returned={})

        assert row.status == ScannerStatus.ERROR
        assert row.missing_reason is None, row.missing_reason
        assert row.dependencies_satisfied is False, "the recorded fact stays"
        assert not any("marking as MISSING" in line for line in warnings), warnings

    def test_control_a_report_with_unavailable_dependencies_keeps_its_reason(
        self, plugin_context, monkeypatch
    ):
        warnings = _warnings(monkeypatch)

        row = _row(plugin_context, returned={"findings": []})

        assert row.status != ScannerStatus.ERROR
        assert row.missing_reason is not None
        assert "shape-tool is not installed" in row.missing_reason
        assert any("marking as MISSING" in line for line in warnings), warnings
