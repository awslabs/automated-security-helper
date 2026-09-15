# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner recorded ERROR must keep reporting ERROR, findings or no findings.

The defect
----------
``get_unified_scanner_metrics`` derives a scanner's reported status in precedence
order: excluded, dependencies-missing, error, ``actionable > 0``, then the recorded
status. The ``error`` flag it consults comes from
``ScannerStatisticsCalculator.get_scanner_status_info``, and the branch that reads
``scanner_results`` -- the branch a scanner that actually ran takes -- read only
``excluded`` and ``dependencies_satisfied``. It never read ``status``. So ``error``
was False for a scanner recorded ERROR, and the ``actionable > 0`` branch then
reported it FAILED.

Measured on this tree, one scanner recorded ERROR in ``scanner_results``::

    0 SARIF findings -> metric status ERROR,  incomplete_scanners [('boom', 'ERROR')]
    3 SARIF findings -> metric status FAILED, incomplete_scanners []

FAILED means the scanner ran and found something. So an ERROR scanner whose findings
reached the SARIF became invisible to the completeness gate, and ``ash scan`` exited 2
-- "there are findings" -- for a run in which a scanner had crashed. Exit 2 tells a
reviewer that clearing the listed findings clears the scan; here it does not, because
one scanner's output is partial by definition.

Reachable rather than theoretical: a scanner that errors part-way through can have
written findings before failing, and in a multi-target run one container can error while
another produces findings under the same scanner name.

Why the fix is in the flags and not in the precedence order
-----------------------------------------------------------
Reordering ``get_unified_scanner_metrics`` to consult the recorded status before
``actionable > 0`` would break the case that branch exists for: a scanner recorded
PASSED whose findings are actionable at this threshold must read FAILED. The recorded
status is not authoritative about the finding count; it *is* authoritative about
whether the scanner crashed. So the flag derivation is what has to read it.
"""

from automated_security_helper.config.ash_config import AshConfig  # noqa: F401
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics
from automated_security_helper.interactions.run_ash_scan import incomplete_scanners
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

import pytest


def _sarif_for(scanner: str, count: int) -> SarifReport:
    """*count* HIGH findings attributed to *scanner*.

    Attribution matters: ``actionable`` is computed from the aggregated SARIF keyed by
    ``properties.scanner_name``, not from ``scanner_results``, so findings recorded only
    on the status entry never reach the branch this file is about.
    """
    results = [
        Result(
            ruleId=f"{scanner}-RULE-{index}",
            level=Level("error"),
            message=Message(root=Message1(text=f"{scanner} finding {index}")),
            properties=PropertyBag(scanner_name=scanner, issue_severity="HIGH"),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(
                        root=PhysicalLocation2(
                            artifactLocation=ArtifactLocation(uri=f"src/{scanner}.py"),
                            region=Region(startLine=index + 1),
                        )
                    )
                )
            ],
        )
        for index in range(count)
    ]
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH", version="test")),
                results=results,
                invocations=[],
                properties=PropertyBag(),
            )
        ],
    )


def _model(status: ScannerStatus, findings: int) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.scanner_results["boom"] = ScannerStatusInfo(
        status=status,
        excluded=False,
        dependencies_satisfied=True,
    )
    model.additional_reports["boom"] = {
        "source": {"scanner_name": "boom", "status": status.value, "duration": 1.0}
    }
    model.sarif = _sarif_for("boom", findings)
    return model


def _status_of(model: AshAggregatedResults, scanner: str = "boom") -> str:
    return next(
        metric.status
        for metric in get_unified_scanner_metrics(asharp_model=model)
        if metric.scanner_name == scanner
    )


class TestErrorIsNotMaskedByFindings:
    @pytest.mark.parametrize("findings", [1, 3])
    def test_an_error_scanner_with_findings_still_reports_error(self, findings):
        model = _model(ScannerStatus.ERROR, findings)
        assert _status_of(model) == "ERROR", (
            "a scanner that crashed reports ERROR whether or not it managed to write "
            "findings first; FAILED would claim it ran to completion"
        )

    @pytest.mark.parametrize("findings", [1, 3])
    def test_an_error_scanner_with_findings_still_trips_the_completeness_gate(
        self, findings
    ):
        model = _model(ScannerStatus.ERROR, findings)
        assert incomplete_scanners(model) == [("boom", "ERROR")], (
            "this is what the masking cost: the gate saw FAILED, reported nothing "
            "incomplete, and ash scan exited 2 for a run in which a scanner crashed"
        )

    def test_the_flags_derivation_reports_the_error(self):
        """Pinned at the layer the fix is in, not only through its consequence.

        get_unified_scanner_metrics checks the error flag before ``actionable > 0``, so
        the whole defect was that this returned error=False for a scanner recorded
        ERROR. Asserting it here means a future refactor of the precedence order cannot
        quietly reintroduce the masking by changing the caller.
        """
        model = _model(ScannerStatus.ERROR, 3)
        excluded, dependencies_missing, error = (
            ScannerStatisticsCalculator.get_scanner_status_info(model, "boom")
        )
        assert (excluded, dependencies_missing, error) == (False, False, True)


class TestTheFindingsBranchStillDoesItsJob:
    """Controls. Making every scanner with findings read ERROR would pass the above."""

    @pytest.mark.parametrize("findings", [1, 3])
    def test_a_passed_scanner_with_actionable_findings_reports_failed(self, findings):
        """The case the ``actionable > 0`` branch exists for, and must keep serving.

        The recorded status is not authoritative about the finding count -- a scanner
        recorded PASSED can still have findings that are actionable at this run's
        threshold -- which is why the fix reads the recorded status for ERROR only,
        rather than making it win outright.
        """
        model = _model(ScannerStatus.PASSED, findings)
        assert _status_of(model) == "FAILED"

    def test_a_passed_scanner_with_no_findings_reports_passed(self):
        model = _model(ScannerStatus.PASSED, 0)
        assert _status_of(model) == "PASSED"

    def test_an_error_scanner_with_no_findings_still_reports_error(self):
        """The half that already worked, pinned so the fix cannot regress it."""
        model = _model(ScannerStatus.ERROR, 0)
        assert _status_of(model) == "ERROR"
        assert incomplete_scanners(model) == [("boom", "ERROR")]

    def test_a_failed_scanner_with_findings_is_untouched(self):
        model = _model(ScannerStatus.FAILED, 2)
        assert _status_of(model) == "FAILED"
        assert incomplete_scanners(model) == []
