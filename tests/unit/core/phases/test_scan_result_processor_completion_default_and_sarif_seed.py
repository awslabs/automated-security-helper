# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ScanResultProcessor reads completion off the rows that say a scanner ran.

- ``validate_completion`` with no names counts the rows recorded PASSED or FAILED
  as completed; SKIPPED, MISSING and ERROR rows did not run to completion.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _plugin_context(tmp_path):
    ctx = MagicMock()
    for name in ("source", "work", "output"):
        (tmp_path / name).mkdir()
    ctx.source_dir = tmp_path / "source"
    ctx.work_dir = tmp_path / "work"
    ctx.output_dir = tmp_path / "output"
    ctx.config = MagicMock()
    ctx.config.get_plugin_config.return_value = None
    ctx.config.global_settings.ignore_paths = []
    ctx.ignore_suppressions = False
    ctx.cached_source_files = []
    return ctx


def _processor(tmp_path) -> tuple[ScanResultProcessor, MagicMock]:
    validation_manager = MagicMock()
    validation_manager.validate_execution_completion.return_value = None
    return (
        ScanResultProcessor(
            plugin_context=_plugin_context(tmp_path),
            validation_manager=validation_manager,
        ),
        validation_manager,
    )


class TestTheCompletionDefaultCountsTheRowsThatRan:
    """``_completed_scanner_names`` counted every row that was not ERROR, so a SKIPPED
    or MISSING scanner (never ran) was reported completed, and ``validate_completion``
    with no names asked the checkpoint about the wrong set."""

    def test_passed_and_failed_rows_are_the_completed_set(self, tmp_path):
        processor, validation_manager = _processor(tmp_path)
        model = AshAggregatedResults()
        for name, status in (
            ("ran-clean", ScannerStatus.PASSED),
            ("ran-found", ScannerStatus.FAILED),
            ("switched-off", ScannerStatus.SKIPPED),
            ("no-tool", ScannerStatus.MISSING),
            ("crashed", ScannerStatus.ERROR),
        ):
            model.scanner_results[name] = ScannerTargetStatusInfo(status=status)

        processor.validate_completion(model)

        validation_manager.validate_execution_completion.assert_called_once_with(
            ["ran-clean", "ran-found"]
        )

    def test_names_given_by_the_caller_are_passed_as_they_are(self, tmp_path):
        """Control: the executor's completed set, when a caller holds it, is the
        answer whatever the rows say."""
        processor, validation_manager = _processor(tmp_path)
        model = AshAggregatedResults()
        model.scanner_results["switched-off"] = ScannerTargetStatusInfo(
            status=ScannerStatus.SKIPPED
        )

        processor.validate_completion(model, ["bandit", "semgrep"])

        validation_manager.validate_execution_completion.assert_called_once_with(
            ["bandit", "semgrep"]
        )

    def test_no_rows_is_an_empty_completed_set(self, tmp_path):
        """Control: an empty model asks about nobody and raises nothing."""
        processor, validation_manager = _processor(tmp_path)

        processor.validate_completion(AshAggregatedResults())

        validation_manager.validate_execution_completion.assert_called_once_with([])
