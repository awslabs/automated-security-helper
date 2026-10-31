"""A dict result's findings reach the summary and the scanner row.

The executor grades a scanner that returns a dict (``severity_counts`` or a
``findings`` list) from the counts it reads and writes the row FAILED when they fail
the gate. Those findings are in no SARIF, so the statistics calculator, which counts
the merged SARIF, read 0 for the scanner; with 0 actionable and no recorded row the
unified metrics rebuilt the scanner PASSED, and summary_stats counted it passed.

Two halves, pinned together: ``ScanResultProcessor`` keeps the executor's counts on
the dict result's per-target report, and ``extract_sarif_counts_for_scanner`` adds
them to the scanner's SARIF counts, whatever the SARIF holds (a scanner can return
SARIF for one target and a dict for another; read only when the SARIF held nothing,
one SARIF result dropped the dict target's findings). The controls say a SARIF
scanner's counts come from the SARIF alone, and a report whose result was SARIF
(``raw_results`` dropped) adds nothing.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
)
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

SCANNER = "shape-tool"


def _dict_result_report(high: int = 1) -> dict:
    """The per-target report the processor writes for a graded dict result."""
    counts = {
        "suppressed": 0,
        "critical": 0,
        "high": high,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    return {
        "scanner_name": SCANNER,
        "target_type": "source",
        "status": "FAILED",
        "finding_count": high,
        "severity_counts": counts,
        "raw_results": {"severity_counts": counts},
    }


def _model(report: dict | None = None) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    if report is not None:
        model.additional_reports = {SCANNER: {"source": report}}
    return model


def _sarif(scanner_name: str, levels: list[str]) -> SarifReport:
    results = [
        Result(
            ruleId=f"R{i}",
            level=level,
            message=Message(text="x"),
            properties=PropertyBag(scanner_name=scanner_name),
        )
        for i, level in enumerate(levels)
    ]
    return SarifReport(
        runs=[Run(tool=Tool(driver=ToolComponent(name=scanner_name)), results=results)]
    )


class TestTheProcessorKeepsADictResultsCounts:
    def test_severity_counts_stay_on_the_report(self, tmp_path):
        output = tmp_path / "output"
        context = PluginContext(
            source_dir=tmp_path,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=AshConfig(project_name="dict-results"),
        )
        container = ScanResultsContainer(
            scanner_name=SCANNER,
            target_type="source",
            raw_results={"severity_counts": {"high": 1}},
        )
        container.severity_counts = ScannerSeverityCount(high=1)
        container.finding_count = 1
        container.status = ScannerStatus.FAILED

        aggregated = ScanResultProcessor(plugin_context=context).process_container(
            container, AshAggregatedResults()
        )

        report = aggregated.additional_reports[SCANNER]["source"]
        assert report["severity_counts"]["high"] == 1, sorted(report)
        assert report["raw_results"] == {"severity_counts": {"high": 1}}


class TestTheStatisticsReadADictResultsCounts:
    def test_the_counts_are_the_scanners(self):
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(
            _model(_dict_result_report(high=2))
        )

        assert stats[SCANNER]["high"] == 2
        assert stats[SCANNER]["total"] == 2
        assert stats[SCANNER]["actionable"] == 2

    def test_the_row_and_the_summary_say_failed(self):
        model = _model(_dict_result_report())

        (metrics,) = get_unified_scanner_metrics(model)
        summary = ScannerStatisticsCalculator.get_summary_statistics(model)

        assert metrics.status == "FAILED"
        assert metrics.actionable == 1
        assert summary["failed_scanners"] == 1
        assert summary["passed_scanners"] == 0
        assert summary["total_high"] == 1

    def test_get_scanner_status_agrees(self):
        model = _model(_dict_result_report())

        assert ScannerStatisticsCalculator.get_scanner_status(model, SCANNER) == (
            "FAILED"
        )

    def test_a_dict_target_is_counted_beside_a_sarif_target(self):
        """One scanner, SARIF on source and a dict on converted: both targets'
        findings reach the row. Read only when the SARIF held nothing, the dict
        target's high finding was dropped by the sibling's one SARIF result."""
        converted = _dict_result_report(high=1)
        converted["target_type"] = "converted"
        model = _model()
        model.additional_reports = {
            SCANNER: {
                "source": {
                    "scanner_name": SCANNER,
                    "target_type": "source",
                    "status": "FAILED",
                    "finding_count": 1,
                    "severity_counts": {"critical": 1},
                },
                "converted": converted,
            }
        }
        model.sarif = _sarif(SCANNER, ["error"])

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        assert stats[SCANNER]["critical"] == 1
        assert stats[SCANNER]["high"] == 1
        assert stats[SCANNER]["total"] == 2


class TestControls:
    def test_a_sarif_scanner_is_counted_from_the_sarif_alone(self):
        """A SARIF report's entry has no raw_results; its counts are not added twice."""
        model = _model(
            {
                "scanner_name": SCANNER,
                "target_type": "source",
                "status": "FAILED",
                "finding_count": 1,
                "severity_counts": {"high": 1},
            }
        )
        model.sarif = _sarif(SCANNER, ["error"])

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        assert stats[SCANNER]["critical"] == 1
        assert stats[SCANNER]["high"] == 0
        assert stats[SCANNER]["total"] == 1

    def test_a_sarif_entry_with_no_sarif_findings_adds_nothing(self):
        """Counts on an entry whose result was SARIF are never read as findings."""
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(
            _model(
                {
                    "scanner_name": SCANNER,
                    "target_type": "source",
                    "status": "PASSED",
                    "severity_counts": {"high": 1},
                }
            )
        )

        assert stats[SCANNER]["total"] == 0

    def test_another_scanners_report_is_not_read(self):
        report = _dict_result_report()
        report["scanner_name"] = "other-tool"
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(_model(report))

        assert stats[SCANNER]["total"] == 0

    def test_counts_that_do_not_validate_add_nothing(self):
        report = _dict_result_report()
        report["severity_counts"] = {"high": "many"}
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(_model(report))

        assert stats[SCANNER]["total"] == 0
