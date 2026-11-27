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

Two more places still treated the note as a finding. The selected-finding strip named
its state Active, and the detail screen opened with its severity. The strip now says
Information, except that a suppression in effect is still shown as Suppressed, and the
detail screen's first line reads INFORMATION in the muted color the table gives it.
Every other line of both screens is unchanged.
"""

import pytest
from textual.widgets import Static

from automated_security_helper.cli.inspect.inspect_findings_app import (
    FindingDetailScreen,
    FindingsExplorerApp,
    _finding_cells,
    _named_finding,
    _summary_line,
)
from automated_security_helper.utils.ui_theme import COLORS

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


def _strip_first_line(finding):
    """The selected-finding strip's first line: the rule id, the scanner and the state."""
    return _named_finding(finding, status=True).plain.split("\n")[0]


@pytest.mark.parametrize("kind", ["pass", "notApplicable", "informational"])
def test_the_strip_names_every_kind_that_states_no_finding_information(kind):
    note = _finding(NOTE, "info", kind)

    assert _strip_first_line(note) == f"{NOTE}  ·  bandit  ·  Information"


@pytest.mark.parametrize("kind", [None, "fail", "open", "review"])
def test_the_strip_of_a_result_that_states_a_finding_still_reads_active(kind):
    """Control, green before and after: a result that names no kind, or a kind that
    asserts a finding, is an active finding."""
    finding = _finding("B602", "high", kind)

    assert _strip_first_line(finding) == "B602  ·  bandit  ·  Active"


def test_a_suppressed_note_still_reads_suppressed_on_the_strip():
    """Control, green before and after: a suppression in effect is still shown."""
    note = _finding(NOTE, "info", "informational", suppressed=True)

    assert _strip_first_line(note) == f"{NOTE}  ·  bandit  ·  Suppressed"


@pytest.mark.asyncio
async def test_the_explorers_selected_finding_strip_names_the_note_information():
    note = _finding(NOTE, "info", "informational")
    app = FindingsExplorerApp([note])
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        strip = str(app.query_one("#selected_finding", Static).render())

    assert strip.split("\n")[0] == f"{NOTE}  ·  bandit  ·  Information"


async def _detail_first_line(finding):
    """The detail screen's first line as the Text the screen was built with."""
    app = FindingsExplorerApp([finding])
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        app.push_screen(FindingDetailScreen(finding))
        await pilot.pause()
        return app.screen.query_one(".detail-severity", Static).content


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["pass", "notApplicable", "informational"])
async def test_the_detail_screen_opens_with_information_not_the_severity(kind):
    # A severity above info, so a first line that kept the severity cannot pass for
    # the word.
    note = _finding(NOTE, "medium", kind)

    first = await _detail_first_line(note)

    assert first.plain == "INFORMATION"


@pytest.mark.asyncio
async def test_the_detail_screen_gives_the_note_the_tables_information_style():
    note = _finding(NOTE, "info", "informational")
    (table_cell,) = _finding_cells(note, ["severity"])

    first = await _detail_first_line(note)

    assert str(table_cell.style) in str(first.style)
    assert COLORS["info"] not in str(first.style)


@pytest.mark.asyncio
async def test_the_detail_screen_of_a_finding_still_opens_with_its_severity():
    """Control, green before and after."""
    first = await _detail_first_line(_finding("B602", "high", "fail"))

    assert first.plain == "HIGH"
    assert COLORS["high"] in str(first.style)
