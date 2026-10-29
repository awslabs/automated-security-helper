# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A newline a finding's value carries is shown, never obeyed as layout.

The table's two-row cells, the selected-finding strip and the suppress dialog
each add their own layout newlines after a value is escaped. A value's own
newline must draw as its escape: a file named "x.py<newline>line 1" reported at
line 500 must not show "line 1" where the layout's "line 500" belongs, and must
not give the strip or the dialog a third line. The planted value also carries a
terminal control (an OSC 52 clipboard write) and a CI command after the newline,
the shapes the one-line rule exists for.
"""

from __future__ import annotations

import pytest

ESC, BEL = chr(0x1B), chr(0x07)
OSC52 = ESC + "]52;c;ZXZpbA==" + BEL
MASK = "::add-mask::explorer-mask-831"


def _planted_finding() -> dict:
    return {
        "rule_id": "R" + OSC52 + "1",
        "severity": "high",
        "scanner": "bandit",
        "message": "msg\n" + MASK,
        "file": "src/" + OSC52 + "a.py\nline 1",
        "line": 500,
        "suppressed": False,
    }


async def _table_cells(size=(120, 36)):
    from textual.widgets import DataTable

    from automated_security_helper.cli.inspect.inspect_findings_app import (
        FindingsExplorerApp,
    )

    app = FindingsExplorerApp([_planted_finding()])
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        table = app.query_one("#findings_table", DataTable)
        cells = list(table.get_row_at(0))
        fields = list(app._table_fields)
        strip = str(app.query_one("#selected_finding").render())
    return dict(zip(fields, cells)), strip


@pytest.mark.asyncio
async def test_the_location_cells_second_row_is_the_layouts_line_number():
    """The row is two lines high: the location's second line is the layout's own
    'line N', never a line a value brought."""
    cells, _ = await _table_cells()
    rows = cells["location"].plain.split("\n")
    assert rows[1:2] == ["line 500"], repr(cells["location"].plain)


@pytest.mark.asyncio
async def test_the_finding_cells_second_row_is_the_message():
    cells, _ = await _table_cells()
    rows = cells["finding"].plain.split("\n")
    assert len(rows) == 2, repr(cells["finding"].plain)


@pytest.mark.asyncio
async def test_the_selected_strip_is_one_line_per_field_row():
    _, strip = await _table_cells()
    assert len(strip.split("\n")) == 2, repr(strip)


@pytest.mark.asyncio
async def test_the_selected_status_line_is_one_line():
    """j and k write "Selected: <rule id> · Enter: details" into the one-line
    status bar. A rule id's own newline must draw as its escape: kept, it
    clips the rest of the id and the hint off the bar."""
    from textual.widgets import Static

    from automated_security_helper.cli.inspect.inspect_findings_app import (
        FindingsExplorerApp,
    )

    finding = _planted_finding()
    finding["rule_id"] = "R" + OSC52 + "1\nforged"
    app = FindingsExplorerApp([finding])
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        status_bar = app.query_one("#status_bar", Static)
        for action in (app.action_next_finding, app.action_previous_finding):
            action()
            shown = str(status_bar.render())
            assert "\n" not in shown, repr(shown)
            assert ESC not in shown, repr(shown)
            assert shown.endswith("· Enter: details"), repr(shown)


@pytest.mark.asyncio
async def test_the_search_status_shows_a_query_newline_as_an_escape():
    """The one-line status bar quotes the search query. A newline the query
    carries (a programmatic caller's, or pasted text's) must draw as its
    escape: kept, it clips the result count's hint off the bar."""
    from textual.widgets import Static

    from automated_security_helper.cli.inspect.inspect_findings_app import (
        FindingsExplorerApp,
    )

    app = FindingsExplorerApp([_planted_finding()])
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        app.search_mode = True
        app.search_query = "a\nb"
        app._populate_table()
        shown = str(app.query_one("#status_bar", Static).render())
    assert "\n" not in shown, repr(shown)
    assert shown.endswith("Esc clears search"), repr(shown)


@pytest.mark.asyncio
@pytest.mark.parametrize("control", [chr(0x0A), chr(0x09)], ids=["lf", "tab"])
async def test_scanner_select_shows_the_name_on_one_line(control):
    """The scanner filter names each scanner, free text from the results, in a
    one-line option and, once chosen, in the select's one-line current label.
    A newline or a tab the name carries draws as its escape."""
    from textual.widgets import Select
    from textual.widgets._select import SelectCurrent

    from automated_security_helper.cli.inspect.inspect_findings_app import (
        FindingsExplorerApp,
    )

    scanner = "bandit" + control + "x"
    finding = _planted_finding()
    finding["scanner"] = scanner
    app = FindingsExplorerApp([finding])
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        select = app.query_one("#scanner_select", Select)
        prompts = [
            str(getattr(prompt, "plain", prompt)) for prompt, _ in select._options
        ]
        select.value = f"scanner:{scanner}"
        await pilot.pause()
        current = str(select.query_one(SelectCurrent).query_one("#label").render())
    shown = [prompt for prompt in prompts if prompt.startswith("bandit")] + [current]
    assert len(shown) == 2, (prompts, current)
    for text in shown:
        assert "\n" not in text, repr(text)
        assert control not in text, repr(text)
        assert text.startswith("bandit") and text.endswith("x"), repr(text)


@pytest.mark.asyncio
@pytest.mark.parametrize("control", [chr(0x0A), chr(0x09)], ids=["lf", "tab"])
async def test_detail_title_shows_the_rule_id_on_one_line(control):
    """The detail view's title is the rule id. A newline the id carries must
    draw as its escape, not as a second title line under the first."""
    from textual.widgets import Static

    from automated_security_helper.cli.inspect.inspect_findings_app import (
        FindingDetailScreen,
        FindingsExplorerApp,
    )

    finding = _planted_finding()
    finding["rule_id"] = "R" + control + "forged"
    app = FindingsExplorerApp([finding])
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        app.push_screen(FindingDetailScreen(finding))
        await pilot.pause()
        shown = str(app.screen.query_one(".title", Static).render())
    assert "\n" not in shown, repr(shown)
    assert control not in shown, repr(shown)
    assert shown.startswith("R") and shown.endswith("forged"), repr(shown)


@pytest.mark.asyncio
async def test_the_suppress_dialog_names_the_finding_on_two_lines(tmp_path):
    from textual.widgets import Static

    from automated_security_helper.cli.inspect.inspect_findings_app import (
        FindingsExplorerApp,
    )

    app = FindingsExplorerApp([_planted_finding()], config_path=tmp_path / ".ash.yaml")
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.press("x")
        await pilot.pause()
        shown = str(app.screen.query_one("#suppression-finding", Static).render())
    assert len(shown.split("\n")) == 2, repr(shown)
