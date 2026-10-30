# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The executor records the level it graded each target against on the report.

A target report carried ``scanner_severity_threshold`` as the scanner's own
option, None for a scanner graded against the global threshold, so a results
file read back knew nothing of the level a target was graded against once the
configuration record held an environment reference in the threshold's place.
The executor now writes the level it graded with, the scanner's own or the
global one, so ``ScannerStatisticsCalculator`` can grade a read-back file from it.

Red at the base: a scanner with no threshold of its own recorded None.
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
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["level-tool"] = "level-tool"


class EmptySarifScanner(ScannerPluginBase):
    """Overrides ``scan()`` and returns a SARIF report with no results."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        self.command = "level-tool"
        self.tool_type = ScannerToolType.SAST
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        # The abstract hook of the template scan(); this stub overrides scan()
        # whole, so the hook is never reached.
        raise NotImplementedError

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        self._pre_scan(target=target, target_type=target_type, config=config)
        self._post_scan(target=target, target_type=target_type)
        return SarifReport(
            runs=[Run(tool=Tool(driver=ToolComponent(name="level-tool")), results=[])]
        )


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
        config=AshConfig(project_name="levels"),
    )


def _row(plugin_context, own_threshold):
    config = _Config()
    config.options.severity_threshold = own_threshold
    scanner = EmptySarifScanner(config=config, context=plugin_context)
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "level-tool",
        scanner,
        [{"path": Path(plugin_context.source_dir), "type": "source"}],
    )
    return row


def test_a_scanner_graded_against_the_global_threshold_records_it(plugin_context):
    row = _row(plugin_context, own_threshold=None)

    assert (
        row.scanner_severity_threshold
        == plugin_context.config.global_settings.severity_threshold
    )
    assert row.scanner_severity_threshold is not None


def test_a_scanner_graded_against_its_own_threshold_records_that(plugin_context):
    """The control: the scanner's own threshold was recorded before too."""
    row = _row(plugin_context, own_threshold="HIGH")

    assert row.scanner_severity_threshold == "HIGH"
