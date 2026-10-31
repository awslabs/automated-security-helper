# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ScanResultProcessor reads completion off the rows that say a scanner ran.

- ``validate_completion`` with no names counts the rows recorded PASSED or FAILED
  as completed; SKIPPED, MISSING and ERROR rows did not run to completion.
- A model with no SARIF yet seeds its report from the model's default (an empty
  run under ASH's driver) and merges the first scanner's report into it; the
  scanner's own report object is never the aggregate.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

ASH_DRIVER_NAME = "AWS Labs - Automated Security Helper"

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _plugin_context(tmp_path):
    ctx = MagicMock()
    for name in ("source", "work", "output"):
        # parents=True: the two-models test passes a subdirectory of tmp_path that
        # nothing has created yet.
        (tmp_path / name).mkdir(parents=True)
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


def _scanner_sarif(scanner_name: str) -> SarifReport:
    return SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name=scanner_name)),
                results=[
                    Result(
                        ruleId="B101",
                        level="warning",
                        message=Message(text="assert used"),
                    )
                ],
            )
        ]
    )


def _process_sarif(tmp_path, model: AshAggregatedResults) -> SarifReport:
    """Run one SARIF container through the processor; return the scanner's report."""
    processor, _ = _processor(tmp_path)
    report = _scanner_sarif("bandit")
    container = ScanResultsContainer(
        scanner_name="bandit",
        target=str(processor.plugin_context.source_dir),
        target_type="source",
    )
    container.raw_results = report
    # Suppressions read a real configuration; the seed is what is measured here.
    with patch(
        "automated_security_helper.core.phases.scan_result_processor.apply_suppressions_to_sarif",
        side_effect=lambda sarif_report, **kwargs: sarif_report,
    ):
        processor.process_container(container, model)
    return report


def _invocation_recorded_for(tmp_path, metadata: dict, attached: dict) -> dict:
    """The ``invocation_details`` the processor attaches for one SARIF container
    whose scanner's own run had already attached *attached*."""
    processor, _ = _processor(tmp_path)
    report = _scanner_sarif("bandit")
    report.attach_scanner_details("bandit", None, attached)
    container = ScanResultsContainer(
        scanner_name="bandit",
        target=str(processor.plugin_context.source_dir),
        target_type="source",
        metadata=metadata,
    )
    container.raw_results = report
    with (
        patch(
            "automated_security_helper.core.phases.scan_result_processor."
            "apply_suppressions_to_sarif",
            side_effect=lambda sarif_report, **kwargs: sarif_report,
        ),
        patch.object(
            SarifReport,
            "attach_scanner_details",
            autospec=True,
            side_effect=SarifReport.attach_scanner_details,
        ) as attach,
    ):
        processor.process_container(container, AshAggregatedResults())
    return attach.call_args.kwargs["invocation_details"]


class TestTheInvocationKeepsWhatTheScannersRunRecorded:
    """The processor merged the container's exit code and duration over the
    invocation the scanner's run had attached, and a container with none wrote
    None over a recorded exit code."""

    def test_a_container_without_an_exit_code_leaves_the_recorded_one(self, tmp_path):
        # Red at the base: exit_code None, from the container's own empty field.
        details = _invocation_recorded_for(
            tmp_path,
            metadata={"scanner_version": "1.7"},
            attached={"exit_code": 2, "command_line": "bandit -r ."},
        )

        assert details["exit_code"] == 2
        assert details["command_line"] == "bandit -r ."

    def test_a_metadata_exit_code_still_wins_over_the_recorded_one(self, tmp_path):
        details = _invocation_recorded_for(
            tmp_path,
            metadata={"scanner_version": "1.7", "exit_code": 3},
            attached={"exit_code": 2},
        )

        assert details["exit_code"] == 3


class TestAModelWithNoSarifSeedsItFromTheDefault:
    """With ``sarif`` None on the model, the first scanner's report became the
    aggregate: the combined SARIF carried that scanner's driver, and the two were one
    object, so every later merge changed the scanner's own report in place."""

    def test_the_first_report_is_merged_into_an_ash_report_not_adopted(self, tmp_path):
        model = AshAggregatedResults()
        model.sarif = None

        report = _process_sarif(tmp_path, model)

        assert model.sarif is not report
        assert model.sarif.runs[0].tool.driver.name == ASH_DRIVER_NAME
        assert [result.ruleId for result in model.sarif.runs[0].results] == ["B101"]
        assert "bandit" in [
            extension.name for extension in model.sarif.runs[0].tool.extensions
        ]

    def test_a_model_with_its_default_report_merges_as_before(self, tmp_path):
        """Control: the default-built model takes the same shape."""
        model = AshAggregatedResults()

        report = _process_sarif(tmp_path, model)

        assert model.sarif is not report
        assert model.sarif.runs[0].tool.driver.name == ASH_DRIVER_NAME
        assert [result.ruleId for result in model.sarif.runs[0].results] == ["B101"]

    def test_the_seed_is_a_copy_of_the_default_not_the_shared_one(self, tmp_path):
        """Two models seeded from None do not share the report object."""
        first, second = AshAggregatedResults(), AshAggregatedResults()
        first.sarif = None
        second.sarif = None

        _process_sarif(tmp_path / "a", first)
        _process_sarif(tmp_path / "b", second)

        assert first.sarif is not second.sarif
        assert len(first.sarif.runs[0].results) == 1
        assert len(second.sarif.runs[0].results) == 1
