# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A three-argument double of ``_safe_execute_scanner`` runs under both loops.

``_safe_execute_scanner(scanner_name, scanner_plugin, scan_targets)`` is the seam
the executor's tests double: a stub with those three parameters stands in for the
scanner. A keyword argument the two run loops passed to switch SCAN_START on
broke every such double: the loop caught the TypeError as the scanner's failure,
recorded a failure row for it, and ``completed_scanners`` stayed empty while the
run read as finished. SCAN_START is now sent by the loops' own per-scanner call,
before it calls the method with the three arguments again.

Red at the base: both loops left ``completed_scanners`` empty and the double was
never called.
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
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class NeverRunScanner(ScannerPluginBase):
    """The double stands in for the scan; this scan() is never reached."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        self.command = "shape-tool"
        self.tool_type = ScannerToolType.SAST
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise AssertionError("the double replaces the scan")


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
        config=AshConfig(project_name="double"),
    )


def _targets(plugin_context):
    return [{"path": Path(plugin_context.source_dir), "type": "source"}]


def _executor(plugin_context, scanner, parallel: bool) -> ScannerExecutor:
    return ScannerExecutor(
        plugin_context=plugin_context,
        progress_display=MagicMock(),
        scanner_tasks=[("one", scanner, _targets(plugin_context))],
        max_workers=2 if parallel else 1,
    )


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
def test_a_three_argument_double_is_called_and_its_scanner_completes(
    plugin_context, parallel
):
    scanner = NeverRunScanner(config=_Config(), context=plugin_context)
    executor = _executor(plugin_context, scanner, parallel)
    calls: list[tuple] = []

    def three_argument_double(name, plugin, targets):
        calls.append((name, plugin, targets))
        row = ScanResultsContainer(
            scanner_name=name,
            target=str(targets[0]["path"]),
            target_type="source",
            status=ScannerStatus.PASSED,
        )
        return [row], True

    executor._safe_execute_scanner = three_argument_double  # type: ignore[method-assign]

    results = (
        executor.run_parallel(AshAggregatedResults())
        if parallel
        else executor.run_sequential(AshAggregatedResults())
    )

    assert results is not None
    assert [name for name, _, _ in calls] == ["one"], calls
    assert executor.completed_scanners == [scanner]
