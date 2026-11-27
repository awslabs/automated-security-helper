# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash inspect`` lists a result that states no finding as information.

A SARIF result whose ``kind`` is ``pass``, ``notApplicable`` or ``informational``
states no finding (SARIF 3.27.9). The note ASH writes when nothing scanned a
container image is one. The findings table showed it as an active finding with the
severity INFO, and the summary line counted it among the active findings.

The table now names its severity INFORMATION, and the summary line counts it apart:
``1 active  ·  1 high  ·  1 information``. A suppressed one is still information, not
a suppressed finding.
"""

import pytest

from automated_security_helper.cli.inspect.inspect_findings_app import (
    _finding_cells,
    _summary_line,
)

pytestmark = pytest.mark.unit

NOTE = "ASH-container-image-not-scanned"


def _finding(rule_id, severity, kind=None, **extra):
    """A finding dict shaped as ``extract_findings`` builds it."""
    finding = {
        "id": -1,
        "rule_id": rule_id,
        "message": f"result of {rule_id}",
        "level": "none" if severity == "info" else "error",
        "severity": severity,
        "scanner": "bandit",
        "suppressed": False,
    }
    if kind is not None:
        finding["kind"] = kind
    finding.update(extra)
    return finding


def test_the_summary_line_counts_the_note_as_information_not_as_active():
    findings = [
        _finding("B602", "high", "fail"),
        _finding(NOTE, "info", "informational"),
    ]

    assert _summary_line(findings).plain == "1 active  ·  1 high  ·  1 information"


@pytest.mark.parametrize("kind", ["pass", "notApplicable", "informational"])
def test_every_kind_that_states_no_finding_is_counted_as_information(kind):
    findings = [_finding("B602", "high", "fail"), _finding(NOTE, "info", kind)]

    assert _summary_line(findings).plain.endswith("  ·  1 information")


def test_a_suppressed_note_is_information_and_not_a_suppressed_finding():
    findings = [
        _finding("B602", "high", "fail"),
        _finding(NOTE, "info", "informational", suppressed=True),
    ]

    assert _summary_line(findings).plain == "1 active  ·  1 high  ·  1 information"


def test_a_finding_that_names_no_kind_is_counted_as_before():
    """Control, green before and after: a dict with no ``kind`` is a finding."""
    findings = [_finding("B602", "high"), _finding("B101", "low")]

    assert _summary_line(findings).plain == "2 active  ·  1 high  ·  1 low"


def test_the_severity_cell_of_the_note_reads_information():
    note = _finding(NOTE, "info", "informational")
    finding = _finding("B602", "high", "fail")

    (note_cell,) = _finding_cells(note, ["severity"])
    (finding_cell,) = _finding_cells(finding, ["severity"])

    assert note_cell.plain == "INFORMATION"
    assert finding_cell.plain == "HIGH"
