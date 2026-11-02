# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A raise in ASH's own steps on a scanner's SARIF report leaves none of it in the results.

The executor's per-target grading ``try`` covers more than reading a dict result: on
a SARIF report it runs ASH's own steps too (the missing levels, the path sanitizing,
the output-dir drop, the converted marks, the suppressions). The row was assigned
the report before that ``try``, and a raise partway only graded the row ERROR, so
the processor merged the report as it stood: half-processed, possibly changed in
place, with suppressed findings still counted and paths never made relative.

Now the row's record becomes the failure (a ``failed`` dict naming the step's
error, the shape every failure handler writes), so the processor files it as a
failed scan's record and none of the report reaches the aggregated SARIF. The
control: the same report with every step succeeding is merged.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Literal
from unittest.mock import MagicMock, patch

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
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

SCANNER = "shape-tool"


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class SarifScanner(ScannerPluginBase):
    """Overrides ``scan()`` and returns one SARIF report with one high finding."""

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
        return SarifReport(
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name=SCANNER)),
                    results=[
                        Result(
                            ruleId="R1",
                            level="error",
                            message=Message(text="x"),
                            properties=PropertyBag(scanner_name=SCANNER),
                        )
                    ],
                )
            ]
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
        config=AshConfig(project_name="sarif-steps"),
    )


def _row(plugin_context):
    scanner = SarifScanner(config=_Config(), context=plugin_context)
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        SCANNER,
        scanner,
        [{"path": Path(plugin_context.source_dir), "type": "source"}],
    )
    return row


def _merged_results(plugin_context, row) -> int:
    aggregated = ScanResultProcessor(plugin_context=plugin_context).process_container(
        row, AshAggregatedResults()
    )
    return sum(len(run.results or []) for run in aggregated.sarif.runs or [])


class TestAFailedStepOnTheReportKeepsItOutOfTheResults:
    def test_the_rows_record_is_the_failure(self, plugin_context):
        with patch(
            "automated_security_helper.core.phases.scanner_executor"
            ".apply_suppressions_to_sarif",
            side_effect=RuntimeError("the suppressions could not be read"),
        ):
            row = _row(plugin_context)

        assert row.status == ScannerStatus.ERROR
        assert isinstance(row.raw_results, dict), type(row.raw_results)
        assert row.raw_results["status"] == "failed"
        assert "the suppressions could not be read" in row.raw_results["exception"]
        assert any("could not be graded" in str(e) for e in row.errors), row.errors

    def test_none_of_the_report_reaches_the_aggregated_sarif(self, plugin_context):
        with patch(
            "automated_security_helper.core.phases.scanner_executor"
            ".apply_suppressions_to_sarif",
            side_effect=RuntimeError("the suppressions could not be read"),
        ):
            row = _row(plugin_context)

        assert _merged_results(plugin_context, row) == 0

    def test_control_a_report_every_step_accepts_is_merged(self, plugin_context):
        row = _row(plugin_context)

        assert row.status == ScannerStatus.FAILED
        assert isinstance(row.raw_results, SarifReport)
        assert _merged_results(plugin_context, row) == 1
