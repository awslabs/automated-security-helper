# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash inspect findings` shows a capped snippet, highlighted once.

A finding's snippet is a scanner's, and minified code reaches ``region.snippet``
whole. A detail view drawing it as a Rich Syntax lexes and wraps all of it
again on every render: with a 1 MB one-line snippet, opening the view took 48.9 s
and each terminal resize 36.5 s, and the app took no input meanwhile (measured).

The view shows at most SNIPPET_LINES lines of SNIPPET_LINE_CHARS characters,
ending a cut snippet with a "(truncated)" line, and highlights it once into a Text,
which a resize wraps again but does not lex again.
"""

from __future__ import annotations

import time

import pytest
from rich.text import Text

from automated_security_helper.cli.inspect.inspect_findings_app import (
    FindingsExplorerApp,
)

#: Minified JavaScript, one token after another with no newline.
_JS = "var a=function(b){return b+1};"


def _js(characters: int) -> str:
    return (_JS * (characters // len(_JS) + 1))[:characters]


def _finding(snippet: str) -> dict:
    return {
        "rule_id": "R1",
        "severity": "high",
        "scanner": "probe",
        "file": "web/bundle.min.js",
        "line": 1,
        "message": "m",
        "suppressed": False,
        "code_snippet": snippet,
    }


async def _settle(pilot, turns: int = 6) -> None:
    for _ in range(turns):
        await pilot.pause()


async def _shown_code(app, pilot) -> Text:
    """Open the detail view and return what its Code box was given."""
    await _settle(pilot)
    await pilot.press("v")
    await _settle(pilot)
    (code,) = list(app.screen.query(".code"))
    return code.content


def _cap():
    from automated_security_helper.cli.inspect.inspect_findings_app import (
        SNIPPET_LINE_CHARS,
        SNIPPET_LINES,
        SNIPPET_TRUNCATED,
    )

    return SNIPPET_LINES, SNIPPET_LINE_CHARS, SNIPPET_TRUNCATED


@pytest.mark.asyncio
async def test_a_megabyte_line_is_shown_cut_to_the_cap(tmp_path):
    app = FindingsExplorerApp(
        [_finding(_js(1_000_000))], config_path=tmp_path / ".ash.yaml"
    )
    async with app.run_test(size=(160, 50)) as pilot:
        shown = await _shown_code(app, pilot)

    _lines, line_chars, truncated = _cap()
    # Highlighted once: a Text, which a render wraps, not a Syntax it lexes.
    assert isinstance(shown, Text), type(shown)
    assert shown.plain.split("\n") == [_js(line_chars), truncated]


@pytest.mark.asyncio
async def test_more_lines_than_the_cap_are_cut(tmp_path):
    snippet = "".join(f"x_{n} = {n}\n" for n in range(1, 1001))
    app = FindingsExplorerApp([_finding(snippet)], config_path=tmp_path / ".ash.yaml")
    async with app.run_test(size=(160, 50)) as pilot:
        shown = await _shown_code(app, pilot)

    lines, _line_chars, truncated = _cap()
    assert shown.plain.split("\n") == [f"x_{n} = {n}" for n in range(1, lines + 1)] + [
        truncated
    ]


@pytest.mark.parametrize("ends_on_a_newline", [True, False])
def test_a_snippet_at_the_cap_is_shown_whole(ends_on_a_newline):
    from automated_security_helper.cli.inspect.inspect_findings_app import _snippet

    lines, line_chars, truncated = _cap()
    snippet = "\n".join(_js(line_chars) for _ in range(lines))
    if ends_on_a_newline:
        snippet += "\n"

    # No lexer, so the cell measures the cap rather than JavaScript's lexer.
    shown = _snippet(snippet, None)

    assert shown.plain == snippet
    assert truncated not in shown.plain


@pytest.mark.parametrize(
    "over",
    [
        pytest.param("line", id="one-line-too-many"),
        pytest.param("character", id="one-character-too-many"),
    ],
)
def test_a_snippet_one_past_the_cap_is_cut(over):
    from automated_security_helper.cli.inspect.inspect_findings_app import _snippet

    lines, line_chars, truncated = _cap()
    rows = [_js(line_chars)] * lines
    if over == "line":
        rows.append("x")
    else:
        rows[-1] += "x"

    shown = _snippet("\n".join(rows), None)

    assert shown.plain.split("\n") == [_js(line_chars)] * lines + [truncated]


#: The most one terminal resize may take with a 1 MB one-line snippet open,
#: measured as the resize and the turns that redraw it. Cut to 500 characters, it
#: took well under 1 s here (Python 3.14.6, Textual 8.2.8, on a host at load 750);
#: uncapped, 39.7 s.
RESIZE_BOUND_S = 3.0


@pytest.mark.asyncio
async def test_a_resize_with_a_megabyte_line_open_takes_bounded_time(tmp_path):
    app = FindingsExplorerApp(
        [_finding(_js(1_000_000))], config_path=tmp_path / ".ash.yaml"
    )
    async with app.run_test(size=(160, 50)) as pilot:
        await _shown_code(app, pilot)

        started = time.monotonic()
        await pilot.resize_terminal(100, 40)
        await _settle(pilot)
        elapsed = time.monotonic() - started

    assert elapsed < RESIZE_BOUND_S, elapsed


@pytest.mark.parametrize(
    "snippet",
    [
        pytest.param("x = 1\n", id="a-line"),
        pytest.param("\n".join(_js(120) for _ in range(60)), id="sixty-lines"),
    ],
)
@pytest.mark.asyncio
async def test_a_resize_does_not_lex_the_snippet_again(tmp_path, monkeypatch, snippet):
    from rich.syntax import Syntax

    lexed = []
    highlight = Syntax.highlight

    def counted(self, code, line_range=None):
        lexed.append(len(code))
        return highlight(self, code, line_range)

    monkeypatch.setattr(Syntax, "highlight", counted)
    app = FindingsExplorerApp([_finding(snippet)], config_path=tmp_path / ".ash.yaml")
    async with app.run_test(size=(160, 50)) as pilot:
        await _shown_code(app, pilot)
        assert lexed, "the snippet was never highlighted"
        lexed.clear()

        await pilot.resize_terminal(100, 40)
        await _settle(pilot)
        await pilot.resize_terminal(120, 45)
        await _settle(pilot)

    assert lexed == []
