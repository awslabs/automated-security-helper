# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Behavior users depend on when they triage findings in the terminal."""

from unittest.mock import patch

import pytest
from rich.text import Text
from textual.widgets import DataTable, Input, Select, Static

from automated_security_helper.cli.inspect.inspect_findings_app import (
    FindingsExplorerApp,
    SuppressDialog,
)

pytestmark = pytest.mark.unit


def finding(rule="R1", severity="high", scanner="bandit", suppressed=False):
    return {
        "rule_id": rule,
        "severity": severity,
        "scanner": scanner,
        "message": "Review this finding",
        "file": "src/app.py",
        "line": 12,
        "suppressed": suppressed,
    }


def test_sorting_does_not_reorder_source_findings():
    findings = [finding("LOW", "low"), finding("HIGH", "high")]
    app = FindingsExplorerApp(findings)
    app.show_suppressed = True
    app._apply_filters()
    app._apply_sorting()
    assert [item["rule_id"] for item in app.filtered_findings] == ["HIGH", "LOW"]
    assert [item["rule_id"] for item in findings] == ["LOW", "HIGH"]


@pytest.mark.asyncio
async def test_scanner_severity_and_suppression_filters_combine():
    app = FindingsExplorerApp(
        [
            finding("MATCH"),
            finding("OTHER-SEVERITY", "low"),
            finding("OTHER-SCANNER", scanner="semgrep"),
            finding("SUPPRESSED", suppressed=True),
        ]
    )
    async with app.run_test(size=(100, 30)) as pilot:
        app.query_one("#severity_select", Select).value = "severity:high"
        app.query_one("#scanner_select", Select).value = "scanner:bandit"
        await pilot.pause()
        assert [item["rule_id"] for item in app.filtered_findings] == ["MATCH"]
        app.query_one("#suppressed_select", Select).value = "suppressed"
        await pilot.pause()
        assert [item["rule_id"] for item in app.filtered_findings] == ["SUPPRESSED"]
        await pilot.press("r")
        await pilot.pause()
        assert len(app.filtered_findings) == 3


@pytest.mark.asyncio
async def test_search_escape_clears_input_and_reopening_starts_empty():
    app = FindingsExplorerApp([finding()])
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("/")
        app.query_one("#search_input", Input).value = "does not exist"
        await pilot.pause()
        assert app.filtered_findings == []
        assert app.query_one("#empty_findings", Static).display
        assert "Press Esc" in str(app.query_one("#empty_findings", Static).render())
        await pilot.press("escape")
        await pilot.pause()
        assert app.query_one("#search_input", Input).value == ""
        assert len(app.filtered_findings) == 1
        await pilot.press("/")
        await pilot.pause()
        assert app.query_one("#search_input", Input).value == ""


@pytest.mark.asyncio
async def test_selected_finding_survives_sorting_resizing_and_details():
    app = FindingsExplorerApp([finding("HIGH"), finding("LOW", "low")])
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.press("j")
        await pilot.pause()
        table = app.query_one("#findings_table", DataTable)
        assert app.filtered_findings[table.cursor_row]["rule_id"] == "LOW"
        app.sort_reverse = True
        app._populate_table()
        await pilot.pause()
        assert app.filtered_findings[table.cursor_row]["rule_id"] == "LOW"
        await pilot.resize_terminal(60, 24)
        await pilot.pause()
        assert app.filtered_findings[table.cursor_row]["rule_id"] == "LOW"
        await pilot.press("v")
        await pilot.pause()
        assert "f" not in app.screen.active_bindings
        await pilot.press("f")
        assert not app.show_filters
        await pilot.press("escape")
        await pilot.pause()
        assert "f" in app.screen.active_bindings
        assert app.filtered_findings[table.cursor_row]["rule_id"] == "LOW"


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(60, 24), (80, 24), (120, 36)])
async def test_table_fits_terminal_and_renders_scanner_text_literally(size):
    item = finding("[red]R1[/red]")
    item["message"] = "[bold]a literal message[/bold]"
    # Enough rows to exercise the vertical scrollbar's width allowance.
    app = FindingsExplorerApp([item, *[finding(f"OTHER-{i}") for i in range(14)]])
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        table = app.query_one("#findings_table", DataTable)
        cell = table.get_row_at(0)[1]
        assert isinstance(cell, Text)
        assert cell.plain == "[red]R1[/red]\n[bold]a literal message[/bold]"
        assert table.virtual_size.width <= table.content_size.width
        assert table.max_scroll_x == 0
        assert app.query_one("#status_bar").region.bottom <= size[1]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(80, 24), (100, 34)])
async def test_suppression_requires_reason_and_preserves_input_on_save_failure(
    tmp_path,
    size,
):
    app = FindingsExplorerApp([finding()], config_path=tmp_path / ".ash.yaml")
    async with app.run_test(size=size) as pilot:
        await pilot.press("x")
        await pilot.pause()
        assert app.focused is app.screen.query_one("#reason_input", Input)
        dialog = app.screen.query_one("#suppress-dialog")
        for selector in ("#btn_cancel", "#btn_suppress"):
            assert app.screen.query_one(selector).region.bottom <= dialog.region.bottom
        await pilot.click("#btn_suppress")
        await pilot.pause()
        assert isinstance(app.screen, SuppressDialog)
        assert app.screen.query_one("#suppression-error", Static).display
        reason = app.screen.query_one("#reason_input", Input)
        reason.value = "Accepted in the fixture"
        # Textual briefly debounces repeated presses of the same button.
        await pilot.pause(0.5)
        with patch(
            "automated_security_helper.cli.inspect.inspect_findings_app.add_suppression_to_config",
            side_effect=OSError("Read-only configuration"),
        ):
            await pilot.click("#btn_suppress")
            await pilot.pause()
        assert isinstance(app.screen, SuppressDialog)
        assert reason.value == "Accepted in the fixture"
        assert "Read-only configuration" in str(
            app.screen.query_one("#suppression-error", Static).render()
        )
        assert not (tmp_path / ".ash.yaml").exists()
