"""A reason recorded on a row with ``add_error`` reaches the files ASH writes.

``ScanResultProcessor.process_container`` dumps each row with ``exclude_unset=True``
into ``additional_reports`` and ``scanners/<name>/<target>/ASH.ScanResults.json``.
The executor records why a row is ERROR with ``container.add_error`` (a rejected
exit code, a result it cannot grade, a missing content database), so the reason
has to survive that dump, or the row reads ERROR with no cause anywhere but the
log.
"""

from __future__ import annotations

import json

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

REASON = "example-tool returned a result on source that could not be graded"


def _processed(tmp_path, container):
    output = tmp_path / "output"
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="errors"),
    )
    aggregated = ScanResultProcessor(plugin_context=context).process_container(
        container, AshAggregatedResults()
    )
    written = output / "scanners" / "example-tool" / "source" / "ASH.ScanResults.json"
    return aggregated, json.loads(written.read_text(encoding="utf-8"))


def test_a_reason_added_to_a_row_is_in_both_outputs(tmp_path):
    container = ScanResultsContainer(
        scanner_name="example-tool",
        target_type="source",
        raw_results={"tool": "its own json"},
    )
    container.status = ScannerStatus.ERROR
    container.add_error(REASON)

    aggregated, written = _processed(tmp_path, container)

    row = aggregated.additional_reports["example-tool"]["source"]
    assert row["errors"] == [REASON], row
    assert written["errors"] == [REASON], sorted(written)


def test_a_row_with_no_reason_has_no_errors_key(tmp_path):
    """Control: an unset list stays out of the dump, as before."""
    container = ScanResultsContainer(
        scanner_name="example-tool", target_type="source", raw_results=True
    )

    aggregated, written = _processed(tmp_path, container)

    assert "errors" not in aggregated.additional_reports["example-tool"]["source"]
    assert "errors" not in written


def test_a_repeated_reason_is_recorded_once():
    container = ScanResultsContainer(scanner_name="example-tool")

    container.add_error(REASON)
    container.add_error(REASON)

    assert container.errors == [REASON]
