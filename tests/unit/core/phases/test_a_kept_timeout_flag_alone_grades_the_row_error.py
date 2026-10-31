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
        self._scan_post_run_error = self.record_error
        self.start_time = datetime(2026, 1, 1, 10, 0, 0)
        self.end_time = datetime(2026, 1, 1, 10, 0, 7)
        self.exit_code = 0
        if self.failing_finding:
            return {"findings": [{"severity": "critical"}]}
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


def _row(plugin_context, kept, limit, record_error=None, failing_finding=False):
    config = _Config()
    # Pinned, so a critical finding fails the gate whatever the global default is.
    config.options.severity_threshold = "MEDIUM"
    scanner = PerTargetScanner(config=config, context=plugin_context)
    scanner.kept = kept
    scanner.limit = limit
    scanner.record_error = record_error
    scanner.failing_finding = failing_finding
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
        """The reason text is what only the flag's grading writes. The status is
        not: the failed target the fixture counts (the skip needs one) makes a
        clean row ERROR on its own, so the test below is the one that tells the
        flag's grade from the target's."""
        row = _row(plugin_context, kept=("timed_out", REASON), limit=None)

        assert row.status == ScannerStatus.ERROR
        assert "timed out on source" in _reasons(row), row.errors
        assert REASON in _reasons(row), row.errors

    def test_the_flag_makes_the_row_error_over_findings_that_fail_the_gate(
        self, plugin_context
    ):
        """With findings that fail the severity gate, the scanner's own accounting
        of one failed target among two reads FAILED: the gate runs first and
        a failed target grades ERROR only when the findings pass it. Only the kept
        flag, with no limit recorded, turns that row ERROR, so removing the flag's
        grading leaves this row FAILED."""
        row = _row(
            plugin_context,
            kept=("timed_out", REASON),
            limit=None,
            failing_finding=True,
        )

        assert row.status == ScannerStatus.ERROR
        assert REASON in _reasons(row), row.errors

    def test_control_findings_that_fail_the_gate_with_no_flag_grade_failed(
        self, plugin_context
    ):
        """Control: the finding in the test above fails the gate by itself, so
        that test's FAILED reading without the flag is what this row shows."""
        row = _row(plugin_context, kept=None, limit=None, failing_finding=True)

        assert row.status == ScannerStatus.FAILED

    def test_control_a_recorded_limit_keeps_the_timeout_line(self, plugin_context):
        row = _row(plugin_context, kept=("timed_out", REASON), limit=30.0)

        assert row.status == ScannerStatus.ERROR
        assert "timed out after" in _reasons(row), row.errors
        assert _reasons(row).count("timed out") == 1, row.errors

    def test_a_record_failure_of_the_timed_out_run_keeps_the_report(
        self, plugin_context
    ):
        """A killed tool commonly fails its record step too. The record failure
        was raised over the report the skip kept, so one failure record replaced
        the other targets' results. Red at the base: raw_results was the failure
        record, with its exception, and no timeout line led the row."""
        row = _row(
            plugin_context,
            kept=("timed_out", REASON),
            limit=30.0,
            record_error="the stream log could not be written",
        )

        assert row.status == ScannerStatus.ERROR
        assert "exception" not in row.raw_results, row.raw_results
        assert row.raw_results.get("findings") == []
        assert "timed out after" in _reasons(row), row.errors
        assert "could not record the scanner's output" in _reasons(row), row.errors
        assert "the stream log could not be written" in _reasons(row), row.errors

    def test_control_a_record_failure_with_no_kept_flag_still_raises(
        self, plugin_context
    ):
        """The skip is for the timed-out target alone: a run that kept no flag and
        failed its record step is still this row's failure."""
        row = _row(
            plugin_context,
            kept=None,
            limit=None,
            record_error="the stream log could not be written",
        )

        assert row.status == ScannerStatus.ERROR
        assert "could not record the scanner's output" in _reasons(row), row.errors

    def test_control_no_kept_flag_grades_on_the_findings(self, plugin_context):
        row = _row(plugin_context, kept=None, limit=None)

        assert row.status == ScannerStatus.PASSED
        assert "timed out" not in _reasons(row), row.errors
