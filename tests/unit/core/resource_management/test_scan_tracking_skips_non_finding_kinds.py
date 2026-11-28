# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan progress views leave out a result that states no finding.

A scan's progress is read from its aggregated results document. It takes the counts
the document records, and reads the SARIF results only when the document records
none: ``_add_aggregated_scanner_progress`` for a scanner's row, and
``_completed_findings_summary`` for the severity buckets and the finding count of a
completed scan. A result of kind ``pass``, ``notApplicable`` or ``informational``
(``sarif_utils.NON_FINDING_KINDS``) has level ``none``, which ASH grades INFO. Read
by level alone, the same document reported an INFO finding on the SARIF path and none
on the recorded one, because the statistics the scan records leave such a result out.
A result states no finding when its kind is one of those and nothing in it reports a
problem: its level is ``none`` or not stated, and no ``issue_severity`` it declares is
above INFO. One whose level reports a problem is a finding, counted by its level.

Every test with a non-finding kind has a control that changes the kind and nothing
else. A result that states no finding is in no bucket, suppressed or not.
"""

from __future__ import annotations

from typing import Any

import pytest

from automated_security_helper.core.resource_management import scan_tracking
from automated_security_helper.core.resource_management.scan_tracking import (
    ScanProgress,
    _completed_findings_count,
    _completed_findings_summary,
)
from automated_security_helper.utils.sarif_utils import NON_FINDING_KINDS

pytestmark = pytest.mark.unit

# Sorted, so every pytest-xdist worker collects the same ids in the same order.
NON_FINDING = sorted(NON_FINDING_KINDS)
# The kinds that assert a finding. A result that states no kind is a failing one.
FINDING = ["fail", "open", "review"]
ANY_FINDING = [pytest.param(None, id="absent"), *FINDING]


def _high() -> dict[str, Any]:
    """A HIGH finding of the scanner the notes below name."""
    return {
        "ruleId": "R-HIGH",
        "level": "error",
        "properties": {"scanner_name": "trivy", "issue_severity": "HIGH"},
    }


def _note(
    kind: str | None, *, level: str = "none", suppressed: bool = False
) -> dict[str, Any]:
    """The note a scanner records for an image it did not scan, with *kind* and
    *level*."""
    result: dict[str, Any] = {
        "ruleId": "N1",
        "level": level,
        "properties": {"scanner_name": "trivy"},
    }
    if kind is not None:
        result["kind"] = kind
    if suppressed:
        result["suppressions"] = [{"kind": "external", "justification": "accepted"}]
    return result


def _progress_of(*results: dict[str, Any]) -> ScanProgress:
    """The progress of a document that records no count for its one scanner."""
    document = {
        "scanner_results": {"trivy": {}},
        "sarif": {
            "runs": [{"tool": {"driver": {"name": "ASH"}}, "results": list(results)}]
        },
    }
    progress = ScanProgress(scan_id="s")
    scan_tracking._add_aggregated_scanner_progress(progress, document)
    return progress


# ---------------------------------------------------------------------------
# A scanner's row, read from the SARIF when the document records no count
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_that_states_no_finding_is_in_no_count_of_the_scanners_row(kind):
    progress = _progress_of(_high(), _note(kind))

    row = progress.scanners["trivy"]["source"]
    assert row.finding_count == 1
    assert (row.severity_counts["high"], row.severity_counts["info"]) == (1, 0)


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_scans_totals_leave_a_result_that_states_no_finding_out(kind):
    progress = _progress_of(_high(), _note(kind))

    assert progress.total_findings == 1
    assert (progress.severity_counts["high"], progress.severity_counts["info"]) == (
        1,
        0,
    )


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_result_that_asserts_a_finding_is_counted_as_info(kind):
    progress = _progress_of(_high(), _note(kind))

    row = progress.scanners["trivy"]["source"]
    assert row.finding_count == 2
    assert (row.severity_counts["high"], row.severity_counts["info"]) == (1, 1)
    assert progress.total_findings == 2


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_suppressed_result_that_states_no_finding_is_in_no_bucket(kind):
    """A result that states no finding counts in no figure, suppressed or not."""
    progress = _progress_of(_high(), _note(kind, suppressed=True))

    row = progress.scanners["trivy"]["source"]
    assert row.finding_count == 1
    counts = row.severity_counts
    assert (counts["high"], counts["info"], counts["suppressed"]) == (1, 0, 0)


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_whose_level_reports_a_problem_is_in_its_level_bucket_of_the_row(kind):
    """A result of such a kind at level warning is a MEDIUM finding, as any result at
    that level is."""
    progress = _progress_of(_high(), _note(kind, level="warning"))

    row = progress.scanners["trivy"]["source"]
    assert row.finding_count == 2
    assert (row.severity_counts["high"], row.severity_counts["medium"]) == (1, 1)


# ---------------------------------------------------------------------------
# A completed scan's buckets and count, read from the SARIF when the stats name none
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_completed_view_puts_a_result_that_states_no_finding_in_no_bucket(kind):
    summary = _completed_findings_summary({}, [_high(), _note(kind)])

    assert (summary["high"], summary["info"]) == (1, 0)
    assert _completed_findings_count({}, summary) == 1


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_a_completed_view_puts_the_same_result_in_info_when_it_asserts_a_finding(kind):
    summary = _completed_findings_summary({}, [_high(), _note(kind)])

    assert (summary["high"], summary["info"]) == (1, 1)
    assert _completed_findings_count({}, summary) == 2


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_completed_view_puts_a_suppressed_non_finding_in_no_bucket(kind):
    """A result that states no finding counts in no figure, suppressed or not."""
    summary = _completed_findings_summary({}, [_high(), _note(kind, suppressed=True)])

    assert (summary["high"], summary["info"], summary["suppressed"]) == (1, 0, 0)
    assert _completed_findings_count({}, summary) == 1


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_completed_view_puts_a_result_whose_level_reports_a_problem_in_its_bucket(
    kind,
):
    """A result of such a kind at level warning is a MEDIUM finding, as any result at
    that level is."""
    summary = _completed_findings_summary({}, [_high(), _note(kind, level="warning")])

    assert (summary["high"], summary["medium"]) == (1, 1)
    assert _completed_findings_count({}, summary) == 2


@pytest.mark.parametrize("kind", NON_FINDING)
def test_recorded_stats_are_read_as_recorded_whatever_the_results_hold(kind):
    """Must-not-regress control: the SARIF is read only when the stats name no bucket."""
    recorded = {"severity_counts": {"high": 1, "info": 0}}

    summary = _completed_findings_summary(recorded, [_high(), _note(kind)])

    assert (summary["high"], summary["info"]) == (1, 0)
