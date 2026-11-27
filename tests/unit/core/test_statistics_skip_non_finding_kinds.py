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

A suppression on such a result is still a suppression, as the flat findings count it,
so only the severity buckets and what is read from them change.

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
# The kinds that assert a finding.
FINDING = ["fail", "open", "review"]

# (suppressed, critical, high, medium, low, info)
ONE_MEDIUM = (0, 0, 0, 1, 0, 0)
ONE_MEDIUM_AND_ONE_INFO = (0, 0, 0, 1, 0, 1)


def _result(kind: str, level: str, *, suppressed: bool = False) -> Result:
    """A result of the scanner cdk-nag, with *kind* and *level*."""
    return Result(
        ruleId="AwsSolutions-IAM4",
        kind=Kind(kind),
        level=Level(level),
        message=Message(text="a message"),
        properties=PropertyBag(scanner_name="cdk-nag"),
        suppressions=(
            [Suppression(kind="external", justification="reviewed")]
            if suppressed
            else None
        ),
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


@pytest.mark.parametrize("kind", FINDING)
def test_the_same_result_that_asserts_a_finding_is_counted_as_info(kind):
    model = _model(_result(kind, "none"), _result("fail", "warning"))

    assert _counts(model) == ONE_MEDIUM_AND_ONE_INFO


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_suppressed_result_that_states_no_finding_is_still_a_suppression(kind):
    model = _model(_result(kind, "none", suppressed=True), _result("fail", "warning"))

    assert _counts(model) == (1, 0, 0, 1, 0, 0)


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_scanner_row_counts_no_non_finding_at_all(kind):
    model = _model(_result(kind, "none"), _result("fail", "warning"), threshold="ALL")

    row = ScannerStatisticsCalculator.extract_scanner_statistics(model)["cdk-nag"]

    assert (row["info"], row["total"], row["actionable"]) == (0, 1, 1)


@pytest.mark.parametrize("kind", FINDING)
def test_the_same_row_counts_a_result_that_asserts_a_finding_at_all(kind):
    model = _model(_result(kind, "none"), _result("fail", "warning"), threshold="ALL")

    row = ScannerStatisticsCalculator.extract_scanner_statistics(model)["cdk-nag"]

    assert (row["info"], row["total"], row["actionable"]) == (1, 2, 2)
