"""A message still queued when the test harness tears the app down touches no widget.

``App.run_test`` shuts the app down while the app's own message loop is still
running: Textual's ``_shutdown`` clears ``_running``, then prunes the default
screen. A message the loop has not yet dispatched is then handled by an App-level
handler whose widgets are gone, and its query raises ``NoMatches``, which
``run_test`` re-raises when its block exits. A user's app never meets this order:
its loop has ended before the screen is pruned.

Each test makes that order certain. A callback that holds the loop until the screen
is empty is queued first, then one message, and the block is left with no pause, so
the message is dispatched only after teardown has emptied the screen.

A key press posted at that moment never reaches ``check_action``: ``App.on_event``
reads the screen first, then forwards the key to a screen that is closing. Textual
runs a key's action through ``App.run_action``, which asks ``check_action`` first,
so the last test has the held loop run the action that ``j`` is bound to.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest
from textual import events
from textual.message import Message
from textual.widgets import DataTable, Input, Select

from automated_security_helper.cli.inspect.inspect_findings_app import (
    FindingsExplorerApp,
)

pytestmark = pytest.mark.unit

SIZE = (120, 36)
# How long the held loop waits for teardown to empty the screen. It ends the moment
# the screen is empty, so this bounds a failure and never delays a pass.
HOLD_SECONDS = 30


def _finding(rule_id: str, severity: str) -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "scanner": "bandit",
        "message": "Review this finding",
        "file": "src/app.py",
        "line": 12,
        "suppressed": False,
    }


def _app() -> FindingsExplorerApp:
    return FindingsExplorerApp([_finding("R1", "high"), _finding("R2", "low")])


def _row_highlighted(app: FindingsExplorerApp) -> Message:
    table = app.query_one("#findings_table", DataTable)
    return DataTable.RowHighlighted(table, 0, next(iter(table.rows)))


def _select_changed(app: FindingsExplorerApp) -> Message:
    return Select.Changed(app.query_one("#scanner_select", Select), "all")


def _input_changed(app: FindingsExplorerApp) -> Message:
    return Input.Changed(app.query_one("#search_input", Input), "x")


def _resized(app: FindingsExplorerApp) -> Message:
    # Narrower than the width the table's layout holds: a resize to that width
    # returns before it reaches a widget.
    return events.Resize.from_dimensions((SIZE[0] - 30, SIZE[1]), None)


MESSAGES = {
    "row_highlighted": _row_highlighted,
    "select_changed": _select_changed,
    "input_changed": _input_changed,
    "resize": _resized,
}


async def _leave_while_the_loop_is_held(
    app: FindingsExplorerApp,
    make_message: Callable[[FindingsExplorerApp], Message] | None = None,
    action: str | None = None,
) -> tuple[Message | None, list[Message], dict[str, bool]]:
    """Run *app*, hold its loop until teardown has emptied its screen, queue the
    message or have the held loop run *action*, and leave with no pause.

    Returns the message, every message that reached a pump, and what the held loop
    saw. Nothing is returned when a handler raised: ``run_test`` re-raises it.
    """
    dispatched: list[Message] = []
    held: dict[str, bool] = {}

    async def hold() -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + HOLD_SECONDS
        while app.default_screen.children:
            if loop.time() > deadline:
                break
            await asyncio.sleep(0.01)
        held["emptied"] = not app.default_screen.children
        if action is not None:
            held["acted"] = await app.run_action(action)

    async with app.run_test(size=SIZE, message_hook=dispatched.append) as pilot:
        # The three selects each post Changed as they mount and each one repopulates
        # the table, so messages are still moving when the first pause returns.
        for _ in range(3):
            await pilot.pause()
        message = make_message(app) if make_message is not None else None
        assert app.call_later(hold)
        if message is not None:
            assert app.post_message(message)
        # No pause here: the loop is inside hold, and a pause would wait on it.
    return message, dispatched, held


@pytest.mark.asyncio
@pytest.mark.parametrize("make_message", list(MESSAGES.values()), ids=list(MESSAGES))
async def test_a_message_queued_at_teardown_touches_no_widget(make_message):
    message, dispatched, held = await _leave_while_the_loop_is_held(
        _app(), make_message
    )

    # Reached only when no handler raised. The hold did not time out, and the
    # message was dispatched, so the handler ran against the emptied screen.
    assert held.get("emptied") is not False, "teardown never emptied the screen"
    assert any(seen is message for seen in dispatched), message


@pytest.mark.asyncio
async def test_the_action_a_key_runs_at_teardown_touches_no_widget():
    action = {b.key: b.action for b in FindingsExplorerApp.BINDINGS}["j"]

    _, _, held = await _leave_while_the_loop_is_held(_app(), action=action)

    assert held.get("emptied") is True, "teardown never emptied the screen"
    assert held.get("acted") is False, f"{action} ran against a torn-down app"
