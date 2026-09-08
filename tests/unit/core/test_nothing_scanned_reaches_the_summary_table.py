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

The chain has a second hazard, and ``TestFindingsAreNeverReportedAsSkipped`` is the guard for
it. Reaching the table as the string "SKIPPED" is not enough; it matters *which* field carried
it there. ``excluded`` and the SKIPPED it produces both set ``ScannerMetrics.passed``, so a row
that arrives via ``excluded`` claims the operator switched the scanner off, and any findings the
scanner did produce render as skipped-and-passed while the exit code still fails the build off
the same findings.
"""

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import (
    ScannerMetrics,
    get_unified_scanner_metrics,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Message,
    Message1,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

# ``AshAggregatedResults`` carries a forward reference to ``AshConfig`` that is only resolved by
# an explicit rebuild. Done here at import rather than borrowed from whichever other test module
# happened to run first: without it every test below raises PydanticUserError when this file is
# run on its own, which makes a red run say nothing about the assertions in it.
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


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


def _row_in_table(model: AshAggregatedResults, scanner_name: str) -> ScannerMetrics:
    metrics = get_unified_scanner_metrics(model)
    rows = [m for m in metrics if m.scanner_name == scanner_name]
    assert rows, (
        f"{scanner_name} produced no row in the summary table; "
        f"got {[m.scanner_name for m in metrics]}"
    )
    return rows[0]


def _status_in_table(container: ScanResultsContainer) -> str:
    return _row_in_table(
        _model_with_container(container), container.scanner_name
    ).status


def _container(**kwargs) -> ScanResultsContainer:
    kwargs.setdefault("scanner_name", "cdk-nag")
    kwargs.setdefault("target_type", "source")
    return ScanResultsContainer(**kwargs)


def test_a_tracked_zero_scan_shows_as_skipped():
    container = _container(targets_attempted=0, targets_failed=0)
    container.status = container.determine_status("MEDIUM")
    assert container.status == ScannerStatus.SKIPPED

    row = _row_in_table(_model_with_container(container), container.scanner_name)
    assert row.status == "SKIPPED"

    # Which field carried the status matters as much as the string, so this asserts the route
    # and not just the destination. ``excluded`` means "the operator switched this scanner
    # off", which is a different fact from "it ran and had nothing to evaluate", and reading
    # the second as the first is what let real findings render as skipped-and-passed. Without
    # this line the test is green through that defect rather than through the fix.
    assert row.excluded is False, (
        "the row must report SKIPPED because the scanner evaluated nothing, not because it "
        "was excluded; deriving `excluded` from the status string masks findings on the "
        "scanner's other target"
    )
    assert row.dependencies_missing is False


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


def _dump(container: ScanResultsContainer) -> dict:
    return container.model_dump(
        exclude_none=True, exclude_unset=True, by_alias=True, mode="json"
    )


def _model_with_two_targets(
    source_attempted: int | None, converted_attempted: int | None, critical: int = 0
) -> AshAggregatedResults:
    """A scanner reporting under both target types, with SARIF attributed to it.

    Two targets is the production shape, not an exotic one: ``ScanPhase`` builds one task per
    scanner carrying ``[source, converted]``, so every scanner writes two reports. The single
    ``source`` fixture used by the tests above cannot express the case where one target
    evaluated nothing and the other found something.

    The SARIF matters too. The table derives ``actionable`` from SARIF rather than from the
    container's ``severity_counts``, so a findings assertion without it would measure the
    fixture.
    """
    model = AshAggregatedResults()
    reports = {}
    for target_type, attempted in (
        ("source", source_attempted),
        ("converted", converted_attempted),
    ):
        container = ScanResultsContainer(
            scanner_name="cdk-nag",
            target_type=target_type,
            targets_attempted=attempted,
        )
        container.status = container.determine_status("MEDIUM")
        reports[target_type] = _dump(container)
    model.additional_reports["cdk-nag"] = reports

    if critical:
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                    results=[
                        Result(
                            ruleId=f"AwsSolutions-S{index}",
                            level=Level.error,
                            message=Message(root=Message1(text="Bucket is unsafe")),
                            properties=PropertyBag(scanner_name="cdk-nag"),
                        )
                        for index in range(critical)
                    ],
                )
            ],
        )
    return model


class TestFindingsAreNeverReportedAsSkipped:
    """A row carrying findings must render red, whatever its other target reported.

    The reported shape: a repository whose tracked JSON and YAML are ``package.json``,
    ``tsconfig.json`` and workflow files. cdk-nag evaluates none of them on the source pass, so
    that target reports SKIPPED, while the converted pass has real templates and real findings.

    ``passed`` is asserted alongside ``status`` because they are separate fields read by
    separate consumers -- ``report_content_emitter`` hands both to the markdown, text and HTML
    reporters -- and a row that says FAILED while ``passed`` is True is worse than either alone.
    """

    def test_a_skipped_source_target_does_not_hide_converted_findings(self):
        model = _model_with_two_targets(
            source_attempted=0, converted_attempted=2, critical=2
        )
        row = _row_in_table(model, "cdk-nag")

        assert row.critical == 2, (
            "fixture check: the findings must reach the row at all"
        )
        assert row.actionable == 2
        assert row.status == "FAILED", (
            "a scanner with actionable findings must never render as skipped; the source "
            "target evaluated nothing, which says nothing about what the converted target "
            "found"
        )
        assert row.passed is False
        assert row.excluded is False

    def test_an_excluded_scanner_carrying_findings_also_renders_red(self):
        """The pre-existing half of the same defect, independent of target tracking.

        ``for_excluded()`` has always set ``excluded`` honestly, and the excluded-before-
        findings ordering meant such a row rendered SKIPPED and passed even with findings
        attributed to it. Nothing in production reaches this state today -- an excluded scanner
        never runs, so it produces no findings -- but the ordering that allows it is the same
        ordering that produced the bug above, and pinning it here is what keeps a future
        refactor from restoring one by way of the other.
        """
        model = AshAggregatedResults()
        model.additional_reports["bandit"] = {
            "None": _dump(ScanResultsContainer.for_excluded("bandit"))
        }
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                    results=[
                        Result(
                            ruleId="B101",
                            level=Level.error,
                            message=Message(root=Message1(text="assert used")),
                            properties=PropertyBag(scanner_name="bandit"),
                        )
                    ],
                )
            ],
        )

        row = _row_in_table(model, "bandit")

        assert row.actionable == 1, (
            "fixture check: the finding must reach the row at all"
        )
        assert row.status == "FAILED"
        assert row.passed is False
        # The scanner really was excluded, and the row still says so. Only the status changed.
        assert row.excluded is True

    def test_both_targets_evaluating_nothing_still_reports_skipped(self):
        """The positive control for the aggregate rule.

        A repository with no CloudFormation anywhere leaves both targets at zero, and that is
        the case the whole change exists to surface. Requiring *every* claim to be zero is what
        keeps the test above from being satisfied by simply never reporting SKIPPED.
        """
        row = _row_in_table(
            _model_with_two_targets(source_attempted=0, converted_attempted=0),
            "cdk-nag",
        )

        assert row.status == "SKIPPED"
        assert row.excluded is False

    def test_one_target_evaluating_nothing_is_not_a_skipped_scan(self):
        """Half-empty is not empty, even with no findings to show for the other half.

        Separates the aggregate rule from the findings check above: here there is no SARIF at
        all, so a row that read SKIPPED could not be blamed on findings precedence.
        """
        row = _row_in_table(
            _model_with_two_targets(source_attempted=0, converted_attempted=3),
            "cdk-nag",
        )

        assert row.status == "PASSED"
        assert row.excluded is False

    def test_two_non_tracking_targets_still_report_passed(self):
        """The cross-scanner regression guard, at the table rather than the model.

        Both reports omit the counter entirely, which is how every non-tracking scanner looks
        after ``exclude_none``. If the aggregate rule read an absent claim as a zero claim,
        every row in a clean report would turn yellow.
        """
        row = _row_in_table(
            _model_with_two_targets(source_attempted=None, converted_attempted=None),
            "cdk-nag",
        )

        assert row.status == "PASSED"
        assert row.excluded is False
