# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash mcp``'s own messages print the values they quote as text.

Why this exists
---------------
The command prints to a Rich console, which reads "[...]" as markup. Its messages
quote values ASH does not control: an option's value (``--transport``,
``--mount-path``), a profile's path, and the text of the error that stopped the
server. Unescaped, a "[/x]" in one would raise MarkupError out of the print, so
the command would end in a traceback instead of its exit code, and a
"[bold]x[/bold]" would be taken as a style and lost. Each value is escaped once
where it is printed.
"""

from __future__ import annotations

import re

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

#: A closing tag with no opener, and a whole style tag around a word.
TEXT = "x[/x] [bold]y[/bold]"

USAGE_ERROR_EXIT = 5


def _plain(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _invoke(*args):
    return CliRunner().invoke(app, ["mcp", *args])


def _assert_shown_once(result, count: int = 1) -> None:
    written = _plain(result.output)
    assert "MarkupError" not in written, written
    assert written.count(TEXT) == count, written
    # Escaped once: an escape left visible would show as "\[".
    assert "\\[" not in written, written


def test_an_unknown_transport_is_quoted_as_text(monkeypatch):
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)

    result = _invoke("--transport", TEXT)

    assert result.exit_code == USAGE_ERROR_EXIT, result.output
    _assert_shown_once(result)


def test_a_missing_profile_file_is_quoted_as_text(tmp_path):
    missing = tmp_path / "p" / f"{TEXT}.yaml"

    result = _invoke("--profile", f"p={missing}")

    assert result.exit_code == 3, result.output
    _assert_shown_once(result)


def test_a_failures_class_name_is_quoted_as_text(monkeypatch):
    """The failure line names the error's class too, and a class name is a
    value ASH does not control: a plugin's exception class can carry markup in
    its name, and unescaped it raises MarkupError out of the failure print,
    ending the command in a traceback instead of its exit code."""
    from automated_security_helper.cli import mcp as mcp_module

    marked_class = type(f"Boom{TEXT}", (RuntimeError,), {})

    def failing(*args, **kwargs):
        raise marked_class("cannot bind the port")

    monkeypatch.setattr(
        mcp_module, "build_streamable_http_app", lambda **kwargs: object()
    )
    monkeypatch.setattr(mcp_module, "_run_uvicorn", failing)

    result = _invoke(
        "--transport", "streamable-http", "--host", "127.0.0.1", "--port", "1"
    )

    assert result.exit_code == 1, result.output
    _assert_shown_once(result)
    assert "cannot bind the port" in _plain(result.output), result.output


def test_the_listening_line_and_the_failure_quote_as_text(monkeypatch):
    from automated_security_helper.cli import mcp as mcp_module

    def failing(*args, **kwargs):
        raise RuntimeError(f"cannot bind {TEXT}")

    monkeypatch.setattr(
        mcp_module, "build_streamable_http_app", lambda **kwargs: object()
    )
    monkeypatch.setattr(mcp_module, "_run_uvicorn", failing)

    result = _invoke(
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.1",
        "--port",
        "1",
        "--mount-path",
        f"/{TEXT}",
    )

    assert result.exit_code == 1, result.output
    # Once in the listening line's URL, once in the failure.
    _assert_shown_once(result, count=2)
    assert "cannot bind" in _plain(result.output), result.output
