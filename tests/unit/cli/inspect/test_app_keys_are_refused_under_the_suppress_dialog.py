# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The explorer's own key bindings do not act under the suppress dialog, and the
dialog's result marks the finding it was opened for.

The app's bindings stayed live under the dialog, so a j or k typed with the Save
button focused moved the hidden table's cursor, an x opened a second dialog over
the first, and a q quit the app with the typed reason. The result handler then
marked the row under the moved cursor suppressed, not the finding the dialog was
opened for.
"""

from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from automated_security_helper.cli.inspect.inspect_findings_app import (
    FindingsExplorerApp,
    SuppressDialog,
)

pytestmark = pytest.mark.unit


def _two_findings() -> list[dict]:
    return [
        {
            "rule_id": "B101",
            "severity": "high",
            "scanner": "bandit",
            "message": "Use of exec detected",
            "file": "src/app.py",
            "line": 10,
            "suppressed": False,
        },
        {
            "rule_id": "B102",
            "severity": "medium",
            "scanner": "bandit",
            "message": "Hardcoded password",
            "file": "src/db.py",
            "line": 20,
            "suppressed": False,
        },
    ]


class TestCheckAction:
    @pytest.mark.parametrize(
        "action",
        [
            "next_finding",
            "previous_finding",
            "suppress_selected",
            "view_selected",
            "toggle_filters",
            "toggle_search",
            "toggle_suppressed",
            "reset_filters",
            "quit_from_table",
        ],
    )
    def test_the_app_bindings_are_refused_under_the_dialog(self, tmp_path, action):
        app = FindingsExplorerApp(_two_findings())
        dialog = SuppressDialog(_two_findings()[0], tmp_path / ".ash.yaml")
        with (
            patch.object(
                FindingsExplorerApp,
                "screen_stack",
                new_callable=PropertyMock,
                return_value=[MagicMock(), dialog],
            ),
            patch.object(
                FindingsExplorerApp,
                "screen",
                new_callable=PropertyMock,
                return_value=dialog,
            ),
        ):
            assert app.check_action(action, ()) is False, action

    def test_textuals_own_quit_stays_allowed_under_the_dialog(self, tmp_path):
        """check_action sees actions, not keys: refusing "quit" under the dialog
        refused Textual's ctrl+q with the q key. The q key has its own action."""
        app = FindingsExplorerApp(_two_findings())
        dialog = SuppressDialog(_two_findings()[0], tmp_path / ".ash.yaml")
        with (
            patch.object(
                FindingsExplorerApp,
                "screen_stack",
                new_callable=PropertyMock,
                return_value=[MagicMock(), dialog],
            ),
            patch.object(
                FindingsExplorerApp,
                "screen",
                new_callable=PropertyMock,
                return_value=dialog,
            ),
        ):
            assert app.check_action("quit", ()) is True
            assert app.check_action("quit_from_table", ()) is False

    def test_the_q_key_is_bound_to_the_apps_own_action(self):
        bound = {b.key: b.action for b in FindingsExplorerApp.BINDINGS}

        assert bound["q"] == "quit_from_table"
        assert "quit" not in bound.values()

    def test_quit_stays_allowed_on_the_table(self):
        app = FindingsExplorerApp(_two_findings())
        table_screen = MagicMock()
        with (
            patch.object(
                FindingsExplorerApp,
                "screen_stack",
                new_callable=PropertyMock,
                return_value=[table_screen],
            ),
            patch.object(
                FindingsExplorerApp,
                "screen",
                new_callable=PropertyMock,
                return_value=table_screen,
            ),
        ):
            assert app.check_action("quit", ()) is True
            assert app.check_action("quit_from_table", ()) is True
            assert app.check_action("next_finding", ()) is True


class TestTheResultMarksTheDialogsFinding:
    def test_the_opened_finding_is_marked_whatever_the_cursor_says(self):
        findings = _two_findings()
        app = FindingsExplorerApp(findings)
        app.filtered_findings = findings
        # The cursor sits on the second row; the dialog was opened for the first.
        table = MagicMock(cursor_row=1)
        widgets = {"#status_bar": MagicMock(), "#findings_table": table}
        app.query_one = lambda selector, _type=None: widgets[selector]
        app._populate_table = MagicMock()

        app._on_suppress_result(SuppressDialog.SAVED, findings[0])

        assert findings[0]["suppressed"] is True
        assert findings[1]["suppressed"] is False


@pytest.mark.asyncio
async def test_keys_typed_at_the_save_button_move_no_hidden_cursor(tmp_path):
    from textual.widgets import Button, DataTable

    app = FindingsExplorerApp(_two_findings(), config_path=tmp_path / ".ash.yaml")
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        table = app.query_one("#findings_table", DataTable)
        assert table.cursor_row == 0
        await pilot.press("x")
        await pilot.pause()
        assert isinstance(app.screen, SuppressDialog), app.screen
        depth = len(app.screen_stack)
        # The reason input takes printable keys itself; the Save button does not.
        app.screen.query_one("#btn_suppress", Button).focus()
        await pilot.pause()
        await pilot.press("j", "x")
        await pilot.pause()
        await pilot.pause()

        assert table.cursor_row == 0, table.cursor_row
        assert len(app.screen_stack) == depth, app.screen_stack
        assert isinstance(app.screen, SuppressDialog), app.screen
