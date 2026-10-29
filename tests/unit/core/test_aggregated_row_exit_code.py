"""The consolidated ``scanner_results`` row carries the exit code its targets reported.

``populate_metrics_from_unified_source`` rebuilds each scanner's row in
``scanner_results`` from the unified metrics, one row for the source and converted
targets together. Each target's own exit code is in ``additional_reports``; the
rebuilt row has to carry one of them, or a row that is ERROR because its tool exited
7 reads ``exit_code: 0``.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _report(status, exit_code=None, name="example-tool") -> dict:
    """One per-target report, as ``ScanResultProcessor`` dumps a container."""
    report = {"scanner_name": name, "status": status, "duration": 1.0}
    if exit_code is not None:
        report["exit_code"] = exit_code
    return report


def _row(reports: dict, name="example-tool"):
    results = AshAggregatedResults()
    results.additional_reports = {name: reports}
    return populate_metrics_from_unified_source(results).scanner_results[name]


def test_an_error_target_s_exit_code_is_the_row_s():
    """Source exited 0, converted exited 7, which the scanner rejects."""
    row = _row(
        {
            "source": _report(ScannerStatus.PASSED, 0),
            "converted": _report(ScannerStatus.ERROR, 7),
        }
    )

    assert row.status == ScannerStatus.ERROR
    assert row.exit_code == 7


def test_an_error_target_s_code_wins_over_a_larger_accepted_one():
    """grype: source exited 2 (a match at --fail-on), converted 1 (an error)."""
    row = _row(
        {
            "source": _report(ScannerStatus.FAILED, 2),
            "converted": _report(ScannerStatus.ERROR, 1),
        }
    )

    assert row.exit_code == 1


def test_with_no_error_target_the_largest_code_is_the_row_s():
    row = _row(
        {
            "source": _report(ScannerStatus.FAILED, 1),
            "converted": _report(ScannerStatus.PASSED, 0),
        }
    )

    assert row.exit_code == 1


def test_a_report_read_back_from_json_carries_its_code_too():
    """``ash merge`` reads the reports from files, so the status is a plain string."""
    row = _row(
        {
            "source": _report("PASSED", 0),
            "converted": _report("ERROR", 7),
        }
    )

    assert row.exit_code == 7


def test_the_code_on_a_processed_container_reaches_the_row(tmp_path):
    """From the executor's container through the processor's dump to the row."""
    output = tmp_path / "output"
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="exit-codes"),
    )
    container = ScanResultsContainer(
        scanner_name="example-tool", target_type="source", raw_results=None
    )
    container.status = ScannerStatus.ERROR
    container.exit_code = 7
    results = ScanResultProcessor(plugin_context=context).process_container(
        container, AshAggregatedResults()
    )

    row = populate_metrics_from_unified_source(results).scanner_results["example-tool"]

    assert row.exit_code == 7


@pytest.mark.parametrize("missing", [None, True, "7"], ids=["absent", "bool", "str"])
def test_a_report_without_an_integer_code_leaves_the_default(missing):
    """Control: no target says what its tool exited with, so the row carries the
    metrics' default, None (``ScannerTargetStatusInfo.exit_code``: "None ... when no
    target recorded one"), never a 0 that reads as a clean exit."""
    row = _row({"source": _report(ScannerStatus.ERROR, missing)})

    assert row.exit_code is None
