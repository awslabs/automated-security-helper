"""A SKIPPED container has to survive the trip to the summary table.

The reviewer's ask was about what an operator sees: "display 'skipped' instead of green". A
status set on ``ScanResultsContainer`` is several hops away from that. It is serialized into
``additional_reports[scanner][target_type]``, read back by
``ScannerStatisticsCalculator.get_scanner_status_info``, and only then turned into the string
``get_unified_scanner_metrics`` hands the table. That chain recomputes status from findings on
some routes, so a model-level assertion alone does not establish that anything changed on screen.

These tests walk the real chain. They also carry the negative control -- a container that did
scan cleanly must still arrive as PASSED -- because the failure mode being guarded against is a
report where every row turned yellow.
"""

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import ScanResultsContainer


def _model_with_container(container: ScanResultsContainer) -> AshAggregatedResults:
    """Put a container into an AshAggregatedResults the way ScanResultProcessor does.

    The dump keywords are copied from ``ScanResultProcessor.process_container`` verbatim,
    ``exclude_none`` included. That flag is load-bearing: it is why a no-claim
    ``targets_attempted`` never appears in a serialized report at all.
    """
    model = AshAggregatedResults()
    model.additional_reports[container.scanner_name] = {
        container.target_type: container.model_dump(
            exclude_none=True,
            exclude_unset=True,
            by_alias=True,
            mode="json",
        )
    }
    return model


def _status_in_table(container: ScanResultsContainer) -> str:
    model = _model_with_container(container)
    metrics = get_unified_scanner_metrics(model)
    rows = [m for m in metrics if m.scanner_name == container.scanner_name]
    assert rows, (
        f"{container.scanner_name} produced no row in the summary table; "
        f"got {[m.scanner_name for m in metrics]}"
    )
    return rows[0].status


def _container(**kwargs) -> ScanResultsContainer:
    kwargs.setdefault("scanner_name", "cdk-nag")
    kwargs.setdefault("target_type", "source")
    return ScanResultsContainer(**kwargs)


def test_a_tracked_zero_scan_shows_as_skipped():
    container = _container(targets_attempted=0, targets_failed=0)
    container.status = container.determine_status("MEDIUM")
    assert container.status == ScannerStatus.SKIPPED

    assert _status_in_table(container) == "SKIPPED"


def test_a_clean_scan_still_shows_as_passed():
    # The negative control. If this ever reads SKIPPED, the change has turned every clean
    # scanner yellow, which is the regression that matters more than the bug.
    container = _container(targets_attempted=6, targets_failed=0)
    container.status = container.determine_status("MEDIUM")
    assert container.status == ScannerStatus.PASSED

    assert _status_in_table(container) == "PASSED"


def test_a_non_tracking_scanner_still_shows_as_passed():
    container = _container(scanner_name="bandit")
    container.status = container.determine_status("MEDIUM")

    assert _status_in_table(container) == "PASSED"


def test_a_total_failure_still_shows_as_error():
    container = _container(targets_attempted=2, targets_failed=2)
    container.status = container.determine_status("MEDIUM")
    assert container.status == ScannerStatus.ERROR

    assert _status_in_table(container) == "ERROR"


@pytest.mark.parametrize("status", ["SKIPPED", "PASSED"])
def test_skipped_and_passed_both_count_as_not_failing(status):
    """Neither status may fail a build.

    A scan that evaluated nothing has produced no evidence of a problem, so it must not start
    failing pipelines that were green before -- that would make the fix worse than the bug for
    every repository without CloudFormation. The distinction is meant to be visible, not fatal.
    """
    from automated_security_helper.core.unified_metrics import ScannerMetrics

    assert ScannerMetrics(scanner_name="probe", status=status).passed is True


@pytest.mark.parametrize(
    "attempted,failed,expected_container_status",
    [
        (6, 0, ScannerStatus.PASSED),
        (2, 2, ScannerStatus.ERROR),
        (None, 0, ScannerStatus.PASSED),
    ],
)
def test_the_table_never_invents_a_skipped_row(
    attempted, failed, expected_container_status
):
    """Only a SKIPPED container produces a SKIPPED row.

    The complement of the first test. That one shows the status reaches the table; this one
    shows the table does not manufacture it from something else -- a clean scan, a total
    failure and a non-tracking scanner must each keep their own status.

    Deliberately not asserting that findings produce a FAILED row here. This fixture carries no
    SARIF, and the table derives its actionable count from SARIF rather than from the
    container's severity_counts, so such an assertion would be measuring the fixture. The
    severity gate is covered where it lives, in
    tests/unit/models/test_scan_results_container_nothing_scanned.py.
    """
    container = _container(targets_attempted=attempted, targets_failed=failed)
    container.status = container.determine_status("MEDIUM")
    assert container.status == expected_container_status

    assert _status_in_table(container) != "SKIPPED"
