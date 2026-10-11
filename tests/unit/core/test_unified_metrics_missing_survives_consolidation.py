"""A scanner recorded MISSING during its scan stays MISSING once the results are consolidated.

``populate_metrics_from_unified_source`` replaces each ``scanner_results`` row with one
built from the unified metrics. That row did not carry ``dependencies_satisfied``, so it
said True for a MISSING scanner. Every later reader -- the report phase, and the exit-code
gate through ``get_unified_scanner_metrics`` -- reads that row before the per-target
reports, and so saw no missing dependency. The scanner then kept its MISSING only when no
other branch claimed it first; one target that evaluated nothing (``targets_attempted``
0) made it SKIPPED, which the completeness gate lets through.

A MISSING recorded before the scan (``ScanResultsContainer.for_missing_deps``) is read
from its ``"None"`` report first and was never affected. A scanner whose ``scan()``
returns False is recorded MISSING per target by the executor, and that is the case here:
offline npm-audit with a lockfile.
"""

# The models first, and the order matters. Imported first in a fresh process,
# core.unified_metrics loads the built-in plugin modules part-way through its own
# import; the reporters module imports it back, finds it partly initialized, and is
# not registered, so every later test in that process (an xdist worker) runs with no
# reporters. Measured: 107 snapshot tests failed with this file collected first.
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import (
    get_unified_scanner_metrics,
    populate_metrics_from_unified_source,
)


def _report(container: ScanResultsContainer) -> dict:
    # The dump ScanResultProcessor.process_container writes.
    return container.model_dump(
        exclude_none=True, exclude_unset=True, by_alias=True, mode="json"
    )


def _missing_at_scan_time(name: str, target_type: str) -> dict:
    """What the executor records when scan() returns False."""
    container = ScanResultsContainer(scanner_name=name, target_type=target_type)
    container.status = ScannerStatus.MISSING
    container.dependencies_satisfied = False
    return _report(container)


def _evaluated_nothing(name: str, target_type: str) -> dict:
    container = ScanResultsContainer(scanner_name=name, target_type=target_type)
    container.targets_attempted = 0
    container.status = container.determine_status(None)
    return _report(container)


def _status_after_consolidation(reports: dict) -> tuple:
    model = AshAggregatedResults()
    model.additional_reports["npm-audit"] = reports
    model = populate_metrics_from_unified_source(aggregated_results=model)
    gate_view = {m.scanner_name: m.status for m in get_unified_scanner_metrics(model)}
    return gate_view["npm-audit"], model.scanner_results["npm-audit"]


def test_missing_on_one_target_is_not_hidden_by_the_other_evaluating_nothing():
    status, row = _status_after_consolidation(
        {
            "source": _missing_at_scan_time("npm-audit", "source"),
            "converted": _evaluated_nothing("npm-audit", "converted"),
        }
    )

    assert status == "MISSING"
    assert row.status == ScannerStatus.MISSING
    assert row.dependencies_satisfied is False


def test_the_consolidated_row_of_a_missing_scanner_says_its_dependencies_are_missing():
    status, row = _status_after_consolidation(
        {"source": _missing_at_scan_time("npm-audit", "source")}
    )

    assert status == "MISSING"
    assert row.dependencies_satisfied is False


def test_control_a_scanner_that_ran_keeps_satisfied_dependencies():
    container = ScanResultsContainer(scanner_name="npm-audit", target_type="source")
    container.status = container.determine_status(None)

    status, row = _status_after_consolidation({"source": _report(container)})

    assert status == "PASSED"
    assert row.dependencies_satisfied is True
