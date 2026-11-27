# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A result that states no finding is never new, never absent and never baselined.

A SARIF result whose ``kind`` is ``pass``, ``notApplicable`` or ``informational``
states no finding (SARIF 3.27.9). The note ASH writes when nothing scanned a
container image is one. A diff reported it as a new finding when a scan gained it
and as probably fixed when a scan lost it, a baseline removed it from the results
as an old finding, and the trend tracked it as a finding that stays open.

Now ``unique_findings`` returns the rows that state a finding, so ``ash diff``, the
MCP diff and the baseline's own side never see the note; the baseline leaves it in
the results; the history record names each row's kind; and the trend leaves out
the rows whose kind states no finding. A record written before the key existed has
none, and its rows count as before.
"""

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.finding_diff import (
    compare_findings,
    unique_findings,
)
from automated_security_helper.utils.finding_trend import TrendRun, _rows
from automated_security_helper.utils.scan_baseline import ScanBaseline, apply_baseline
from automated_security_helper.utils.scan_history import _finding_row, _valid_row

pytestmark = pytest.mark.unit

NOTE = "ASH-container-image-not-scanned"


def _bandit(rule_id: str = "B602", line: int = 10) -> dict:
    return {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": f"result of {rule_id}"},
        "properties": {
            "issue_severity": "HIGH",
            "scanner_name": "bandit",
            "tags": ["bandit"],
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src.py"},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def _note() -> dict:
    """The note, with the scanner named so a baseline can match it, as it could."""
    return {
        "ruleId": NOTE,
        "kind": "informational",
        "level": "none",
        "message": {"text": "container image example:1 was not scanned"},
        "properties": {"scanner_name": "bandit", "tags": ["bandit"]},
    }


KINDS = ("pass", "notApplicable", "informational")


def _pair(kind: str) -> dict:
    """A result that contradicts its kind: *kind* at level warning. It reports a
    problem, so it is a finding."""
    return {
        "ruleId": "R-PAIR",
        "kind": kind,
        "level": "warning",
        "message": {"text": "reports a problem despite its kind"},
        "properties": {"scanner_name": "bandit", "tags": ["bandit"]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src.py"},
                    "region": {"startLine": 30},
                }
            }
        ],
    }


def _results(*results: dict) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "scanner"}}, "results": list(results)}
            ],
        }
    )
    model.scanner_results = {"bandit": ScannerTargetStatusInfo(status="PASSED")}
    return model


def _baseline(*results: dict) -> ScanBaseline:
    old = _results(*results)
    return ScanBaseline("abc", old, tuple(old.to_flat_vulnerabilities()))


# --- diff -----------------------------------------------------------------------


def test_the_findings_of_a_scan_are_the_rows_that_state_one():
    rows = unique_findings(_results(_bandit(), _note()), "Current")

    assert [row.rule_id for row in rows] == ["B602"]


def test_a_scan_that_gains_the_note_has_no_new_finding():
    before = unique_findings(_results(_bandit()), "Baseline")
    after = unique_findings(_results(_bandit(), _note()), "Current")

    assert compare_findings(before, after).new == []


def test_a_scan_that_gains_a_failing_result_has_it_as_new():
    """Control, green before and after: the filter leaves real findings alone."""
    before = unique_findings(_results(_bandit()), "Baseline")
    after = unique_findings(_results(_bandit(), _bandit("B101", 20)), "Current")

    assert [row.rule_id for row in compare_findings(before, after).new] == ["B101"]


def test_a_scan_that_loses_the_note_has_nothing_absent():
    before = unique_findings(_results(_bandit(), _note()), "Baseline")
    after = unique_findings(_results(_bandit()), "Current")

    assert compare_findings(before, after).absent_after == []


@pytest.mark.parametrize("kind", KINDS)
def test_the_diff_sees_such_a_pair_as_new(kind):
    """A result that reports a problem despite its kind is a finding, so a scan
    that gains it has a new finding."""
    before = unique_findings(_results(_bandit()), "Baseline")
    after = unique_findings(_results(_bandit(), _pair(kind)), "Current")

    assert [row.rule_id for row in compare_findings(before, after).new] == ["R-PAIR"]


# --- baseline -------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
def test_a_baseline_removes_such_a_pair_it_names(kind):
    current = _results(_bandit(), _pair(kind))

    outcome = apply_baseline(current, _baseline(_bandit(), _pair(kind)))

    assert current.sarif.runs[0].results == []
    assert outcome.matched == 2


def test_a_baseline_removes_the_old_finding_and_keeps_the_note():
    current = _results(_bandit(), _note())

    outcome = apply_baseline(current, _baseline(_bandit(), _note()))

    assert [result.ruleId for result in current.sarif.runs[0].results] == [NOTE]
    assert outcome.matched == 1


# --- history --------------------------------------------------------------------


def test_a_history_row_names_the_kind_of_its_result():
    flat = _results(_bandit(), _note()).to_flat_vulnerabilities()

    rows = [_finding_row(row) for row in flat]

    assert [row.get("result_kind") for row in rows] == ["fail", "informational"]


def test_a_history_row_records_whether_its_result_states_a_finding():
    flat = _results(_bandit(), _note(), _pair("pass")).to_flat_vulnerabilities()

    rows = [_finding_row(row) for row in flat]

    assert [row["is_finding"] for row in rows] == [True, False, True]
    assert all(_valid_row(row) for row in rows)


def test_a_history_row_with_a_kind_that_is_not_text_is_refused():
    (row,) = [_finding_row(r) for r in _results(_bandit()).to_flat_vulnerabilities()]

    assert _valid_row(row) is True
    assert _valid_row({**row, "result_kind": 3}) is False


def test_a_history_row_written_before_the_key_existed_is_still_read():
    """Control, green before and after: the key is additive."""
    (row,) = [_finding_row(r) for r in _results(_bandit()).to_flat_vulnerabilities()]
    row.pop("result_kind", None)

    assert _valid_row(row) is True


# --- trend ----------------------------------------------------------------------


def test_the_trend_leaves_out_the_rows_that_state_no_finding_and_keeps_old_rows():
    run = TrendRun(
        "run-1",
        "file",
        {
            "findings": [
                {"id": "a", "scanner": "bandit", "result_kind": "fail"},
                {"id": "b", "scanner": "bandit", "result_kind": "informational"},
                {"id": "c", "scanner": "bandit"},
                {"id": "d", "scanner": "bandit", "result_kind": "pass"},
            ]
        },
    )

    rows = _rows(run)

    assert [(row.id, row.index) for row in rows] == [("a", 0), ("c", 2)]


@pytest.mark.parametrize("kind", KINDS)
def test_the_trend_counts_such_a_pair(kind):
    """A history row written from a result that reports a problem despite its kind
    says it is a finding, and the trend counts it."""
    (flat,) = _results(_pair(kind)).to_flat_vulnerabilities()
    record = _finding_row(flat)
    run = TrendRun("run-1", "file", {"findings": [record]})

    assert [row.id for row in _rows(run)] == [record["id"]]


def test_a_trend_row_without_the_key_falls_back_to_its_kind_and_severity():
    """Guard: a record from before the key, whose kind states no finding and whose
    severity is INFO, is not counted."""
    run = TrendRun(
        "run-1",
        "file",
        {
            "findings": [
                {
                    "id": "n",
                    "scanner": "bandit",
                    "result_kind": "informational",
                    "severity": "INFO",
                }
            ]
        },
    )

    assert _rows(run) == []


def test_a_trend_row_with_neither_key_is_counted():
    """Guard: a record from before the kind was written counts every row."""
    run = TrendRun("run-1", "file", {"findings": [{"id": "c", "scanner": "bandit"}]})

    assert [row.id for row in _rows(run)] == ["c"]
