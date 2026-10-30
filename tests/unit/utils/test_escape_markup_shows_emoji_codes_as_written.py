# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value escape_markup escapes shows its Rich emoji codes as written.

Why this exists
---------------
Rich replaces an emoji code (``:warning:``, ``:lock:``) in each text segment of a
markup string, and ``rich.markup.escape`` leaves codes alone, so a repository value
holding one is shown as the emoji, not as the text it is: through ASH's console
handler, as a MARKUP log record, through ``rich.print``, and in the stderr of
``ash mcp --transport`` naming an unknown transport. The consoles made with
``emoji=False`` show each as written.

escape_markup splits each emoji code across two markup segments with an empty
``[none][/none]`` after its first colon, so no segment holds a whole code. A
tag-shaped value holding a colon (``[a:b:]``, ``[a:b]:c``), which Rich's escape
backslashes, is opened with an empty style after its ``[`` instead, so the split
inside it ends no tag and the backslashes the escape doubled before it are halved
back. An emoji code ASH writes into its own markup, outside escape_markup, renders.
"""

from __future__ import annotations

import io
import logging

import pytest
import rich
from rich.console import Console
from typer.testing import CliRunner

from automated_security_helper.utils.log import MARKUP, ConsoleHandler, escape_markup
from automated_security_helper.utils.terminal_text import commands_broken

pytestmark = pytest.mark.unit

BACKSLASH = chr(0x5C)

VALUES = [
    ":warning:",
    ":lock:",
    "a:smile:b",
    "::warning::x",
    ":x:lock:",
    # A tag-shaped value holding a code: Rich's escape backslashes the tag, and a
    # split inside an escaped tag would end it and show the backslash, so the tag
    # is opened with an empty style after its "[" instead and the code split.
    "[a:b:]",
    # The code starts inside the tag and ends after it.
    "[a:b]:c",
    # A colon in the tag but no code: opened too, shown the same.
    "x [a:b] y",
    # Backslashes before the tag: the escape doubles them and adds one; the
    # opened tag needs none, so they are halved back to the ones written.
    BACKSLASH + "[a:b:]",
    BACKSLASH + BACKSLASH + "[a:b:]",
]


def _console(stream: io.StringIO) -> Console:
    return Console(file=stream, width=200, color_system=None)


def _logged(message: str) -> str:
    """``message`` as ASH's console handler shows a MARKUP record holding it."""
    stream = io.StringIO()
    handler = ConsoleHandler(
        console=_console(stream), markup=False, show_time=False, show_path=False
    )
    logger = logging.getLogger("ash-test-emoji-codes")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    try:
        logger.info(message, extra=MARKUP)
    finally:
        logger.handlers = []
    return stream.getvalue()


def _printed(message: str, monkeypatch) -> str:
    """``message`` as ``rich.print`` shows it."""
    stream = io.StringIO()
    monkeypatch.setattr(rich, "_console", _console(stream))
    rich.print(message)
    return stream.getvalue()


@pytest.mark.parametrize("value", VALUES)
def test_a_markup_log_record_shows_the_value_as_written(value):
    shown = _logged(f"[bold]v[/bold] {escape_markup(value)}")

    assert f"v {commands_broken(value)}" in shown, shown


@pytest.mark.parametrize("value", VALUES)
def test_rich_print_shows_the_value_as_written(value, monkeypatch):
    shown = _printed(f"[red]v[/red] {escape_markup(value)}", monkeypatch)

    assert shown.strip() == f"v {commands_broken(value)}", shown


@pytest.mark.parametrize("value", [":warning:", "a:smile:b"])
def test_ash_mcp_names_a_transport_as_written(value, monkeypatch):
    """The refusal quotes the value through escape_markup."""
    from automated_security_helper.cli.main import app
    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    result = CliRunner().invoke(app, ["mcp", "--transport", value])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert f"got '{value}'" in result.output, result.output


def test_control_an_emoji_code_ash_writes_renders(monkeypatch):
    """An emoji code in ASH's own markup, outside escape_markup, is the emoji."""
    printed = _printed(f":warning: {escape_markup('a value')}", monkeypatch)
    logged = _logged(f":warning: {escape_markup('a value')}")

    assert printed.strip() == "⚠ a value", printed
    assert "⚠ a value" in logged, logged
