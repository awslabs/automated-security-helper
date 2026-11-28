# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The per-scanner counts do not grade a result that states no finding.

A SARIF result of kind ``pass``, ``notApplicable`` or ``informational`` says that a
rule passed, did not apply, or reported information only
(``sarif_utils.NON_FINDING_KINDS``), and SARIF asks for level ``none`` beside those
kinds. ASH grades level ``none`` INFO, so counted by its level a cdk-nag rule that
was not evaluated was an INFO finding of cdk-nag. It showed in the scanner's row, in
the summary totals and, under a threshold of ``ALL``, in the Actionable column that
the exit code's in-memory count reads.

A result states no finding when its kind is one of those and nothing in it reports a
problem: its level is ``none`` or not stated, and no ``issue_severity`` it declares is
above INFO. Such a result counts in no figure, suppressed or not. One whose level
reports a problem is a finding and is counted by its level.

Every test with a non-finding kind has a control that changes the kind and nothing
else. A failing result (the default kind), and the two kinds that assert a finding a
reader still has to judge, ``open`` and ``review``, keep the grade they had.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    Message,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import NON_FINDING_KINDS

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

# Sorted, so every pytest-xdist worker collects the same ids in the same order.
NON_FINDING = sorted(NON_FINDING_KINDS)
# The kinds that assert a finding. A result that states no kind is a failing one.
FINDING = ["fail", "open", "review"]
ANY_FINDING = [pytest.param(None, id="absent"), *FINDING]

# (suppressed, critical, high, medium, low, info)
ONE_MEDIUM = (0, 0, 0, 1, 0, 0)
ONE_MEDIUM_AND_ONE_INFO = (0, 0, 0, 1, 0, 1)
TWO_MEDIUM = (0, 0, 0, 2, 0, 0)


def _result(kind: str | None, level: str, *, suppressed: bool = False) -> Result:
    """A result of the scanner cdk-nag, with *kind* (none leaves it out) and *level*."""
    stated = {} if kind is None else {"kind": Kind(kind)}
    return Result(
        ruleId="AwsSolutions-IAM4",
        level=Level(level),
        message=Message(text="a message"),
        properties=PropertyBag(scanner_name="cdk-nag"),
        suppressions=(
            [Suppression(kind="external", justification="reviewed")]
            if suppressed
            else None
        ),
        **stated,
    )


def _model(*results: Result, threshold: str = "MEDIUM") -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = AshConfig.model_validate(
        {
            "project_name": "non-finding-kinds",
            "global_settings": {"severity_threshold": threshold},
        }
    )
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                results=list(results),
            )
        ],
    )
    return model


def _counts(model: AshAggregatedResults):
    return ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
        model, "cdk-nag"
    )


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_that_states_no_finding_is_in_no_severity_count(kind):
    model = _model(_result(kind, "none"), _result("fail", "warning"))

    assert _counts(model) == ONE_MEDIUM


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_result_that_asserts_a_finding_is_counted_as_info(kind):
    model = _model(_result(kind, "none"), _result("fail", "warning"))

    assert _counts(model) == ONE_MEDIUM_AND_ONE_INFO


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_suppressed_result_that_states_no_finding_is_in_no_count(kind):
    """A result that states no finding counts in no figure, suppressed or not."""
    model = _model(_result(kind, "none", suppressed=True), _result("fail", "warning"))

    assert _counts(model) == ONE_MEDIUM


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_whose_level_reports_a_problem_is_counted_by_its_level(kind):
    """A result of such a kind at level warning is a MEDIUM finding, as any result at
    that level is."""
    model = _model(_result(kind, "warning"), _result("fail", "warning"))

    assert _counts(model) == TWO_MEDIUM


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_scanner_row_counts_no_non_finding_at_all(kind):
    model = _model(_result(kind, "none"), _result("fail", "warning"), threshold="ALL")

    row = ScannerStatisticsCalculator.extract_scanner_statistics(model)["cdk-nag"]

    assert (row["info"], row["total"], row["actionable"]) == (0, 1, 1)


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_row_counts_a_result_that_asserts_a_finding_at_all(kind):
    model = _model(_result(kind, "none"), _result("fail", "warning"), threshold="ALL")

    row = ScannerStatisticsCalculator.extract_scanner_statistics(model)["cdk-nag"]

    assert (row["info"], row["total"], row["actionable"]) == (1, 2, 2)


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_sarif_count_check_holds_with_results_that_state_no_finding(kind):
    """The check compares findings with findings: a result that states no finding is in
    neither count, suppressed or not."""
    model = _model(
        _result("fail", "warning"),
        _result(kind, "none"),
        _result(kind, "none", suppressed=True),
    )

    assert ScannerStatisticsCalculator.verify_sarif_finding_counts(model) is True


# ---------------------------------------------------------------------------
# A scanner whose results all state no finding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_scanner_whose_only_results_state_no_finding_keeps_its_row(kind):
    """A scanner that reported only results that state no finding still ran and
    reported, so it keeps its row, the same as one that reported a finding."""
    model = _model(_result(kind, "none"))

    statistics = ScannerStatisticsCalculator.extract_scanner_statistics(model)

    assert "cdk-nag" in statistics
    assert ScannerStatisticsCalculator.sarif_counts_by_scanner(model).names == [
        "cdk-nag"
    ]


@pytest.mark.parametrize("kind", NON_FINDING)
def test_that_row_counts_nothing(kind):
    """The row of a scanner whose results all state no finding counts nothing."""
    model = _model(_result(kind, "none"))

    row = ScannerStatisticsCalculator.extract_scanner_statistics(model)["cdk-nag"]

    assert [
        row[field]
        for field in (
            "suppressed",
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "total",
            "actionable",
        )
    ] == [0, 0, 0, 0, 0, 0, 0, 0]
