# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A per-target scanner that kept a timeout flag is graded ERROR from the flag alone.

A scanner that runs its tool once per target records a timed-out run in its own
accounting (one failed target among more attempted) and returns the other targets'
merged report, so the executor skips the raise it makes for any other kept flag
and keeps the report (``_recorded_the_timed_out_target``). The skip promised the
row would still be ERROR, but that grade read ``scan_timed_out_after``, a second
record the run recorder sets after the flag and can fail to set (its record step
is the plugin's own code): with the flag kept and no limit recorded, the row
graded PASSED or FAILED over a run that did not finish, and the kept reason
reached no row.

The executor now remembers the kept flag it skipped the raise for and grades the
row ERROR from it, with the flag's reason in the row's errors. The controls: a
limit recorded beside the flag keeps the existing timeout line, and a scanner that
kept no flag grades on its findings.
"""

from __future__ import annotations

from datetime import datetime
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

REASON = "shape-tool (pid 4242) was killed after its limit"


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class PerTargetScanner(ScannerPluginBase):
    """Counts two targets and keeps the flag ``kept`` with the limit ``limit``
    recorded, as a run recorder that raised after the flag would leave them; one
    target failed when a flag is kept, none otherwise (a failed target grades the
    row ERROR on its own, so the no-flag control must count none); returns the
    other target's clean report."""

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
        self.targets_attempted = 2
        self.targets_failed = 1 if self.kept else 0
        self._scan_kept_flag = self.kept
        self._scan_timed_out_after = self.limit
        self.start_time = datetime(2026, 1, 1, 10, 0, 0)
        self.end_time = datetime(2026, 1, 1, 10, 0, 7)
        self.exit_code = 0
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
        config=AshConfig(project_name="kept-timeout"),
    )


def _row(plugin_context, kept, limit):
    scanner = PerTargetScanner(config=_Config(), context=plugin_context)
    scanner.kept = kept
    scanner.limit = limit
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "shape-tool",
        scanner,
        [{"path": Path(plugin_context.source_dir), "type": "source"}],
    )
    return row


def _reasons(row) -> str:
    return " ".join(str(error) for error in row.errors)


class TestAKeptTimeoutFlagAloneGradesTheRowError:
    def test_the_flag_with_no_recorded_limit_is_the_rows_error(self, plugin_context):
        row = _row(plugin_context, kept=("timed_out", REASON), limit=None)

        assert row.status == ScannerStatus.ERROR
        assert "timed out on source" in _reasons(row), row.errors
        assert REASON in _reasons(row), row.errors

    def test_control_a_recorded_limit_keeps_the_timeout_line(self, plugin_context):
        row = _row(plugin_context, kept=("timed_out", REASON), limit=30.0)

        assert row.status == ScannerStatus.ERROR
        assert "timed out after" in _reasons(row), row.errors
        assert _reasons(row).count("timed out") == 1, row.errors

    def test_control_no_kept_flag_grades_on_the_findings(self, plugin_context):
        row = _row(plugin_context, kept=None, limit=None)

        assert row.status == ScannerStatus.PASSED
        assert "timed out" not in _reasons(row), row.errors
