# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ScanResultProcessor: where a container's file goes, what its SARIF carries, and
what its two post-scan checks compare.

- A scanner-level container (no target: the failure container a run mode files when
  a scanner's run raised) is written under its own key, beside the source tree's
  file, not over it.
- The results directory is made through the guarded open, which refuses a link.
- The scanner's own ``tool_invocation`` (command line, arguments, exit code) survives
  the processor's attach, and a container's exit code and duration reach the SARIF
  whether or not the container carries metadata.
- Aggregated results with no SARIF report adopt the scanner's findings instead of
  dropping them.
- ``validate_completion`` reads the completed scanners off the results when it is
  given none, and ``validate_metrics`` compares against the metadata's summary.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases import scan_result_processor
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.fs_guard import OutputLinkRefused

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
        ignore_suppressions=True,
    )


def _processor(context) -> ScanResultProcessor:
    return ScanResultProcessor(plugin_context=context, validation_manager=MagicMock())


def _sarif(scanner_details=None) -> SarifReport:
    driver = {"name": "tool", "rules": [{"id": "tool-rule"}]}
    if scanner_details is not None:
        driver["properties"] = {"scanner_details": scanner_details}
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": driver},
                    "results": [
                        {
                            "ruleId": "tool-rule",
                            "level": "warning",
                            "message": {"text": "finding"},
                        }
                    ],
                }
            ],
        }
    )


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


class TestWhereAContainersFileGoes:
    def test_a_scanner_level_container_does_not_replace_the_source_target_file(
        self, tmp_path
    ):
        """The run mode's failure container has no target. Written under the
        source tree's directory it replaced the source target's file."""
        context = _context(tmp_path)
        processor = _processor(context)
        model = AshAggregatedResults()
        source = ScanResultsContainer(
            scanner_name="tool",
            target=context.source_dir,
            target_type="source",
            raw_results={"status": "passed", "findings": []},
        )
        model = processor.process_container(source, model)
        failure = ScanResultsContainer.for_failure(
            "tool", errors=["the run raised"], exception=RuntimeError("boom")
        )
        failure.raw_results = {"status": "failed", "errors": ["the run raised"]}
        model = processor.process_container(failure, model)

        scanners = context.output_dir / "scanners" / "tool"
        source_file = _read(scanners / "source" / "ASH.ScanResults.json")
        assert source_file["target_type"] == "source", source_file
        assert source_file.get("raw_results") == {"status": "passed", "findings": []}
        assert source_file.get("exception") is None, source_file
        scanner_level = _read(scanners / "None" / "ASH.ScanResults.json")
        assert scanner_level["status"] == "FAILED", scanner_level
        assert "None" in model.additional_reports["tool"]
        assert "source" in model.additional_reports["tool"]

    def test_the_results_directory_is_not_made_through_a_link(self, tmp_path):
        """A link where the scanner's directory should be, pointing outside the
        output directory: nothing is created behind it, and the write is refused."""
        context = _context(tmp_path)
        processor = _processor(context)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        scanners = context.output_dir / "scanners"
        scanners.mkdir()
        (scanners / "tool").symlink_to(elsewhere, target_is_directory=True)
        container = ScanResultsContainer(
            scanner_name="tool",
            target=context.source_dir,
            target_type="source",
            raw_results={"status": "passed", "findings": []},
        )

        with pytest.raises(OutputLinkRefused):
            processor.process_container(container, AshAggregatedResults())

        assert not (elsewhere / "source").exists(), list(elsewhere.iterdir())


class TestWhatTheSarifCarries:
    def test_the_scanners_own_tool_invocation_survives_the_attach(self, tmp_path):
        """The scanner's run attached the command line, arguments and exit code;
        the processor adds the times beside them instead of replacing them."""
        context = _context(tmp_path)
        own = {
            "tool_name": "tool",
            "tool_invocation": {
                "command_line": "tool --flag",
                "arguments": ["--flag"],
                "working_directory": ".",
                "exit_code": 3,
            },
        }
        container = ScanResultsContainer(
            scanner_name="tool",
            report_type="sarif",
            target=context.source_dir,
            target_type="source",
            raw_results=_sarif(own),
            start_time=datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
            end_time=datetime(2026, 1, 1, 10, 0, 7, tzinfo=timezone.utc),
        )

        sarif = (
            _processor(context)
            .process_container(container, AshAggregatedResults())
            .sarif
        )
        details = sarif.runs[0].results[0].properties.scanner_details

        invocation = details["tool_invocation"]
        assert invocation["command_line"] == "tool --flag", invocation
        assert invocation["arguments"] == ["--flag"], invocation
        assert invocation["working_directory"] == ".", invocation
        assert invocation["exit_code"] == 3, invocation
        assert invocation["start_time"].startswith("2026-01-01T10:00:00"), invocation
        assert invocation["end_time"].startswith("2026-01-01T10:00:07"), invocation

    def test_a_containers_exit_code_and_duration_reach_the_sarif_without_metadata(
        self, tmp_path
    ):
        """No scanner writes container metadata, so a fallback that sat under the
        metadata branch attached neither; the container's own fields do now."""
        context = _context(tmp_path)
        container = ScanResultsContainer(
            scanner_name="tool",
            report_type="sarif",
            target=context.source_dir,
            target_type="source",
            raw_results=_sarif(),
            exit_code=2,
            duration=1.5,
            start_time=datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
            end_time=datetime(2026, 1, 1, 10, 0, 1, 500000, tzinfo=timezone.utc),
        )
        assert container.metadata == {}

        sarif = (
            _processor(context)
            .process_container(container, AshAggregatedResults())
            .sarif
        )
        invocation = (
            sarif.runs[0].results[0].properties.scanner_details["tool_invocation"]
        )

        assert invocation["exit_code"] == 2, invocation
        assert invocation["duration"] == 1.5, invocation

    def test_results_with_no_sarif_report_adopt_the_scanners_findings(self, tmp_path):
        """``sarif`` is optional on the results model; with None there, the
        scanner's sanitized report was dropped and its entry still said it ran."""
        context = _context(tmp_path)
        container = ScanResultsContainer(
            scanner_name="tool",
            report_type="sarif",
            target=context.source_dir,
            target_type="source",
            raw_results=_sarif(),
        )
        model = AshAggregatedResults(sarif=None)

        model = _processor(context).process_container(container, model)

        assert model.sarif is not None
        assert len(model.sarif.get_all_results()) == 1
        assert "raw_results" not in model.additional_reports["tool"]["source"]


class TestThePostScanChecks:
    def test_validate_completion_reads_completed_scanners_off_the_results(
        self, tmp_path
    ):
        """Given no list, the scanners with a PASSED or FAILED row are the ones
        that completed (a SKIPPED or MISSING row never ran, an ERROR row did not
        complete); defaulting to none marked every queued scanner failed."""
        processor = _processor(_context(tmp_path))
        processor.validation_manager.validate_execution_completion.return_value = (
            MagicMock(has_issues=MagicMock(return_value=False))
        )
        model = AshAggregatedResults()
        model.scanner_results["ran"] = ScannerTargetStatusInfo(
            status=ScannerStatus.PASSED
        )
        model.scanner_results["crashed"] = ScannerTargetStatusInfo(
            status=ScannerStatus.ERROR
        )

        processor.validate_completion(model)

        processor.validation_manager.validate_execution_completion.assert_called_once_with(
            ["ran"]
        )

    def test_a_given_list_is_passed_as_it_is(self, tmp_path):
        processor = _processor(_context(tmp_path))
        processor.validation_manager.validate_execution_completion.return_value = (
            MagicMock(has_issues=MagicMock(return_value=False))
        )

        processor.validate_completion(AshAggregatedResults(), ["named"])

        processor.validation_manager.validate_execution_completion.assert_called_once_with(
            ["named"]
        )

    def test_validate_metrics_compares_against_the_metadata_summary(
        self, tmp_path, monkeypatch
    ):
        """The summary lives on the metadata. Read off the model itself it was
        None and the check returned before comparing, so a mismatch never logged."""
        warnings = []
        monkeypatch.setattr(
            scan_result_processor.ASH_LOGGER,
            "warning",
            lambda message, *args, **kwargs: warnings.append(str(message)),
        )
        model = AshAggregatedResults()
        model.metadata.summary_stats.total = 5
        model.scanner_results["tool"] = ScannerTargetStatusInfo(
            status=ScannerStatus.FAILED, finding_count=3
        )

        _processor(_context(tmp_path)).validate_metrics(model)

        assert any("Metrics inconsistency" in line for line in warnings), warnings
        assert any(
            "total=3" in line and "summary_stats total=5" in line for line in warnings
        ), warnings

    def test_validate_metrics_is_quiet_for_a_model_whose_totals_agree(
        self, tmp_path, monkeypatch
    ):
        """The control the mismatch test lacks. Both totals leave suppressed
        findings out (the rows' finding_count and SummaryStats.total are the
        non-suppressed sums), so a model with suppressed findings and agreeing
        totals is consistent and logs nothing."""
        warnings = []
        monkeypatch.setattr(
            scan_result_processor.ASH_LOGGER,
            "warning",
            lambda message, *args, **kwargs: warnings.append(str(message)),
        )
        model = AshAggregatedResults()
        model.metadata.summary_stats.total = 3
        model.metadata.summary_stats.suppressed = 4
        model.scanner_results["found"] = ScannerTargetStatusInfo(
            status=ScannerStatus.FAILED, finding_count=2, suppressed_finding_count=4
        )
        model.scanner_results["clean"] = ScannerTargetStatusInfo(
            status=ScannerStatus.FAILED, finding_count=1
        )

        _processor(_context(tmp_path)).validate_metrics(model)

        assert not any("Metrics inconsistency" in line for line in warnings), warnings
