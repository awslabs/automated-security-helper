"""A crashed scanner's failure report reads ERROR, live and after a reload.

Two defects met on the scanner-level report (a container with no target):

- ``ScanResultProcessor`` filed it under the Python ``None``, while the statistics
  calculator looks it up under the string ``"None"``, the key it has once the
  results are written as JSON and read back. A live run and a rebuild of its saved
  results took different branches.
- ``ScanResultsContainer.for_failure`` writes status FAILED with ``raw_results``
  ``status: "failed"``, and ``_status_info_from_report`` read FAILED as a verdict:
  not ERROR. After reload, a crashed scanner with findings rolled up FAILED ("ran
  and found something") and the completeness gate let it through.

The processor now files a target-less container under ``"None"``, and a report
whose ``raw_results`` says ``failed`` (or that carries an ``exception``) is ERROR
whatever its status, so the two reads agree.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)
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

SCANNER = "crash-tool"


def _failure_container() -> ScanResultsContainer:
    container = ScanResultsContainer.for_failure(
        SCANNER, errors=[f"Scanner {SCANNER} failed: boom"]
    )
    container.raw_results = {
        "errors": [f"Scanner {SCANNER} failed: boom"],
        "status": "failed",
        "exception": "boom",
    }
    return container


def _processed(tmp_path) -> AshAggregatedResults:
    output = tmp_path / "output"
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="crash"),
    )
    aggregated = ScanResultProcessor(plugin_context=context).process_container(
        _failure_container(), AshAggregatedResults()
    )
    aggregated.ash_config = get_default_config()
    return aggregated


def _reloaded(model: AshAggregatedResults) -> AshAggregatedResults:
    """The model as ``ash report`` reads it back from the saved results.

    The model's own JSON round trip, as ``save_model`` and ``load_model`` make
    it: a ``json.dumps(..., default=str)`` of ``additional_reports`` alone wrote
    a Python ``None`` key as ``"null"`` where pydantic writes ``"None"``, so a
    processor that filed under ``None`` again would have passed this test
    through a different branch than a real reload takes.
    """
    reloaded = AshAggregatedResults.model_validate_json(model.model_dump_json())
    reloaded.ash_config = get_default_config()
    return reloaded


class TestTheProcessorFilesATargetLessContainerUnderNone:
    def test_the_key_is_the_string_none(self, tmp_path):
        aggregated = _processed(tmp_path)

        assert list(aggregated.additional_reports[SCANNER]) == ["None"]
        assert None not in aggregated.additional_reports[SCANNER]


class TestAFailureReportIsAnError:
    def test_live(self, tmp_path):
        excluded, missing, error = ScannerStatisticsCalculator.get_scanner_status_info(
            _processed(tmp_path), SCANNER
        )

        assert (excluded, missing, error) == (False, False, True)

    def test_after_reload(self, tmp_path):
        excluded, missing, error = ScannerStatisticsCalculator.get_scanner_status_info(
            _reloaded(_processed(tmp_path)), SCANNER
        )

        assert (excluded, missing, error) == (False, False, True)

    def test_a_crash_with_findings_rolls_up_error(self, tmp_path):
        model = _reloaded(_processed(tmp_path))
        model.sarif = SarifReport(
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

        assert ScannerStatisticsCalculator.get_scanner_status(model, SCANNER) == (
            "ERROR"
        )

    def test_a_report_with_an_exception_is_an_error(self):
        excluded, missing, error = ScannerStatisticsCalculator._status_info_from_report(
            {"scanner_name": SCANNER, "status": "FAILED", "exception": "boom"}
        )

        assert error is True
        assert excluded is False

    def test_an_exception_inside_raw_results_alone_is_an_error(self):
        """The handlers' failure dict carries the exception beside its status; a
        dict that kept the text and lost the status is still a failure's. Read
        at the top of the report only, such a report was a FAILED grade."""
        excluded, missing, error = ScannerStatisticsCalculator._status_info_from_report(
            {
                "scanner_name": SCANNER,
                "status": "FAILED",
                "raw_results": {"exception": "boom"},
            }
        )

        assert error is True
        assert excluded is False

    def test_a_nested_exception_refuses_the_partial_loss_reading_too(self):
        """The one rule reaches the other reader: an ERROR row beside a report
        whose only failure mark is the nested exception is a crash, not a
        partial loss."""
        model = AshAggregatedResults()
        model.ash_config = get_default_config()
        model.additional_reports = {
            SCANNER: {
                "source": {
                    "scanner_name": SCANNER,
                    "target_type": "source",
                    "status": "ERROR",
                    "targets_attempted": 4,
                    "targets_failed": 1,
                    "raw_results": {"exception": "boom"},
                }
            }
        }

        assert (
            ScannerStatisticsCalculator.recorded_error_is_partial_loss(model, SCANNER)
            is False
        )
        # The control: the same counters with no failure mark are a partial loss.
        del model.additional_reports[SCANNER]["source"]["raw_results"]
        assert (
            ScannerStatisticsCalculator.recorded_error_is_partial_loss(model, SCANNER)
            is True
        )


class TestControls:
    def test_a_graded_failed_report_is_a_verdict(self):
        """A FAILED row the executor graded, with no failure marks, stays a verdict."""
        excluded, missing, error = ScannerStatisticsCalculator._status_info_from_report(
            {
                "scanner_name": SCANNER,
                "status": "FAILED",
                "raw_results": {"severity_counts": {"high": 1}},
            }
        )

        assert (excluded, missing, error) == (False, False, False)

    def test_a_target_keeps_its_own_key(self, tmp_path):
        output = tmp_path / "output"
        context = PluginContext(
            source_dir=tmp_path,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=AshConfig(project_name="crash"),
        )
        container = ScanResultsContainer(
            scanner_name=SCANNER, target_type="source", raw_results={"findings": []}
        )
        aggregated = ScanResultProcessor(plugin_context=context).process_container(
            container, AshAggregatedResults()
        )

        assert list(aggregated.additional_reports[SCANNER]) == ["source"]
