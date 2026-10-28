"""Consolidating the results keeps every field of a scanner's row the metrics do not compute.

``populate_metrics_from_unified_source`` replaced each ``scanner_results`` row with one
built only from the unified metrics: status, the counts and the duration. Everything
else on the row was dropped. A scanner the operator excluded (``--exclude-scanners``,
``--scanners``, a disabled config) is recorded by ``ScanPhase`` with ``excluded: true``,
and after consolidation its row said ``excluded: false`` in
``ash_aggregated_results.json`` -- the same value as a scanner that ran and found
nothing to scan. Any extra field went the same way. (``exit_code`` is one of the
fields the metrics compute, from the per-target reports, so it is replaced.)

The row is now built from the original, with only the fields the metrics compute
replaced.
"""

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)


def _report(container: ScanResultsContainer) -> dict:
    # The dump ScanResultProcessor.process_container writes.
    return container.model_dump(
        exclude_none=True, exclude_unset=True, by_alias=True, mode="json"
    )


def _ran(name: str) -> dict:
    container = ScanResultsContainer(scanner_name=name, target_type="source")
    container.status = container.determine_status(None)
    return {"source": _report(container)}


def _consolidate(model: AshAggregatedResults) -> AshAggregatedResults:
    return populate_metrics_from_unified_source(aggregated_results=model)


def test_an_excluded_scanner_stays_excluded():
    model = AshAggregatedResults()
    # What ScanPhase._record_scanner_not_selected writes for an excluded scanner.
    model.additional_reports["semgrep"] = {
        "None": _report(ScanResultsContainer.for_excluded("semgrep"))
    }
    model.scanner_results["semgrep"] = ScannerTargetStatusInfo(
        status=ScannerStatus.SKIPPED, excluded=True, dependencies_satisfied=True
    )

    row = _consolidate(model).scanner_results["semgrep"]

    assert row.status == ScannerStatus.SKIPPED
    assert row.excluded is True


def test_fields_the_metrics_do_not_compute_are_kept():
    model = AshAggregatedResults()
    model.additional_reports["bandit"] = _ran("bandit")
    model.scanner_results["bandit"] = ScannerTargetStatusInfo(
        status=ScannerStatus.PASSED, note="kept"
    )

    row = _consolidate(model).scanner_results["bandit"]

    assert getattr(row, "note", None) == "kept"


def test_the_fields_the_metrics_compute_are_replaced():
    """An ERROR report outranks the row's PASSED, and the counts come from the SARIF.

    Not PASSED versus FAILED: with no findings and nothing else to go on, the metrics
    take the status the row recorded (get_unified_scanner_metrics, last branch)."""
    model = AshAggregatedResults()
    errored = ScanResultsContainer(scanner_name="bandit", target_type="source")
    errored.status = ScannerStatus.ERROR
    model.additional_reports["bandit"] = {"source": _report(errored)}
    model.scanner_results["bandit"] = ScannerTargetStatusInfo(
        status=ScannerStatus.PASSED, finding_count=9, actionable_finding_count=9
    )

    row = _consolidate(model).scanner_results["bandit"]

    assert row.status == ScannerStatus.ERROR
    assert (row.finding_count, row.actionable_finding_count) == (0, 0)


def test_a_legacy_two_target_row_gives_its_flags_and_not_its_targets():
    model = AshAggregatedResults()
    model.additional_reports["semgrep"] = {
        "None": _report(ScanResultsContainer.for_excluded("semgrep"))
    }
    model.scanner_results["semgrep"] = ScannerStatusInfo(
        status=ScannerStatus.SKIPPED, excluded=True
    )

    row = _consolidate(model).scanner_results["semgrep"]

    assert isinstance(row, ScannerTargetStatusInfo)
    assert row.excluded is True
    assert not hasattr(row, "source") and not hasattr(row, "converted")


def test_control_a_scanner_with_no_prior_row_gets_the_metrics_row():
    model = AshAggregatedResults()
    model.additional_reports["bandit"] = _ran("bandit")

    row = _consolidate(model).scanner_results["bandit"]

    assert row.status == ScannerStatus.PASSED
    assert row.excluded is False
    assert row.dependencies_satisfied is True
