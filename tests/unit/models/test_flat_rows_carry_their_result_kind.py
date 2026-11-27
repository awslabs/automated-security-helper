# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A flat row carries the SARIF kind of its result and says whether it states a finding.

A result whose ``kind`` is ``pass``, ``notApplicable`` or ``informational`` states no
finding (SARIF 3.27.9). The note ASH writes when nothing scanned a container image
is one. Its flat row read like any other row, so the reports that list the flat rows
graded it and counted it as a finding.

``result_kind`` puts the kind on the row: ``fail`` for a result that names none, and
for a row read from a scanner's additional report. ``is_finding`` says whether that
kind states a finding. A result still gives one row, in order: the flat reports, and
the consumers that pair rows with results by position, depend on it.
"""

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

NOTE = "ASH-container-image-not-scanned"

#: The kinds that state no finding; SARIF 3.27.10 pairs each with the level "none".
STATES_NO_FINDING = ("pass", "notApplicable", "informational")


def _result(rule_id: str, kind: str | None = None) -> dict:
    result = {
        "ruleId": rule_id,
        "level": "none" if kind in STATES_NO_FINDING else "warning",
        "message": {"text": f"result of {rule_id}"},
    }
    if kind is not None:
        result["kind"] = kind
    return result


def _model(*results: dict) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "bandit"}}, "results": list(results)}
            ],
        }
    )
    return model


@pytest.mark.parametrize(
    "kind, named, states_a_finding",
    [
        pytest.param("pass", "pass", False, id="pass"),
        pytest.param("notApplicable", "notApplicable", False, id="notApplicable"),
        pytest.param("informational", "informational", False, id="informational"),
        # The control: the kinds that state a finding, and no kind at all, which
        # SARIF reads as "fail" (3.27.9).
        pytest.param(None, "fail", True, id="no-kind"),
        pytest.param("fail", "fail", True, id="fail"),
        pytest.param("open", "open", True, id="open"),
        pytest.param("review", "review", True, id="review"),
    ],
)
def test_a_row_names_its_results_kind_and_says_whether_it_states_a_finding(
    kind, named, states_a_finding
):
    model = _model(_result("B602"), _result(NOTE, kind))

    flat = model.to_flat_vulnerabilities()

    assert [(row.result_kind, row.is_finding) for row in flat] == [
        ("fail", True),
        (named, states_a_finding),
    ]


def test_every_result_still_gives_one_row_in_order():
    """The pairing the flat reports depend on; green before and after."""
    kinds = [None, "fail", "open", "review", "pass", "notApplicable", "informational"]
    model = _model(*[_result(f"R-{index}", kind) for index, kind in enumerate(kinds)])

    flat = model.to_flat_vulnerabilities()

    assert [row.rule_id for row in flat] == [f"R-{index}" for index in range(7)]


def test_a_row_read_from_an_additional_report_is_a_finding_of_kind_fail():
    model = AshAggregatedResults()
    model.additional_reports = {
        "custom-plugin": [
            {"id": "x-1", "title": "A finding", "description": "d", "severity": "HIGH"}
        ]
    }

    (row,) = model.to_flat_vulnerabilities()

    assert row.source_report == "custom-plugin"
    assert (row.result_kind, row.is_finding) == ("fail", True)


LEVEL_WARNING = {"level": "warning"}
LEVEL_NONE_HIGH = {"level": "none", "properties": {"issue_severity": "HIGH"}}


@pytest.mark.parametrize("kind", STATES_NO_FINDING)
@pytest.mark.parametrize(
    "reports", [LEVEL_WARNING, LEVEL_NONE_HIGH], ids=["level-warning", "severity-high"]
)
def test_a_row_whose_result_reports_a_problem_is_a_finding(kind, reports):
    """A result that contradicts its kind is a finding: the row says so, read from
    the whole result and not from the kind alone."""
    result = {**_result("R-PAIR", kind), **reports}
    model = _model(_result("B602"), result)

    flat = model.to_flat_vulnerabilities()

    assert [row.is_finding for row in flat] == [True, True]


@pytest.mark.parametrize("kind", STATES_NO_FINDING)
def test_a_copied_row_keeps_its_verdict(kind):
    result = {**_result("R-PAIR", kind), **LEVEL_WARNING}
    (row,) = _model(result).to_flat_vulnerabilities()

    assert row.is_finding is True
    assert row.model_copy().is_finding is True


@pytest.mark.parametrize("kind", STATES_NO_FINDING)
@pytest.mark.parametrize(
    "severity, states_a_finding", [("HIGH", True), ("INFO", False)]
)
def test_a_row_built_without_a_result_reads_its_kind_and_severity(
    kind, severity, states_a_finding
):
    """A row with no result behind it (a stand-in, one read back from a dump) knows
    only its kind and graded severity: such a kind at INFO states no finding, and
    one graded above INFO reports a problem."""
    row = FlatVulnerability(
        id="x",
        title="t",
        description="d",
        severity=severity,
        scanner="bandit",
        scanner_type="SAST",
        result_kind=kind,
    )

    assert row.is_finding is states_a_finding


def test_the_kind_is_the_last_field_so_the_csv_column_follows_every_older_one():
    assert list(FlatVulnerability.model_fields)[-2:] == [
        "correlation_id",
        "result_kind",
    ]
