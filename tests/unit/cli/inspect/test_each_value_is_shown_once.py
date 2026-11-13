# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash inspect findings` shows each value's controls once, one to one.

A value is shown when its controls are written as escapes and a run of backslashes
that would read as one is doubled (utils/terminal_text.py's controls_shown). Shown
twice, each escape's backslash is doubled again and no longer reads as what it
stood for. So a message is built from raw values and shown whole, once: by the
module's helpers for a widget, and by the sink itself for ASH's log and console,
which show a str they are given.

VALUE holds an ESC and a Windows-path segment that reads like an escape. Each
site must draw ONCE (its ESC as one escape, the lookalike's backslash doubled
once) and never TWICE, and the raw ESC never reaches the screen. In a snippet,
which keeps its backslashes as written, only the ESC is shown.

The doubled lookalike is the TUI keeping controls_shown's one-to-one rule, as
ash's other terminal text does: ``out\\x64`` is drawn ``out\\\\x64``, so an
escape on the screen always stands for a control. only_controls_shown is for a
snippet alone.
"""

from __future__ import annotations

import io
import logging
from contextlib import contextmanager

import pytest
import typer
from rich.console import Console

from automated_security_helper.cli.inspect import inspect_findings_app as tui
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.terminal_text import (
    controls_shown,
    only_controls_shown,
)

pytestmark = pytest.mark.unit

# The ESC is followed by "c", not "[" or "]": a complete escape sequence is
# removed from an error's text in every print, a lone ESC is shown.
VALUE = "p\x1bcq out\\x64\\Release"
ONCE = controls_shown(VALUE)
TWICE = controls_shown(ONCE)
# A file value a suppression can name: the dialog refuses to save one whose path
# holds a backslash (no suppression path names such a file alone), so the test that
# reaches the writer gives its finding a file with the ESC but with slashes.
SAVABLE_FILE = "p\x1bcq out/x64/Release"
SCREEN = (220, 60)


def _finding(**overrides) -> dict:
    finding = {
        "rule_id": f"rule {VALUE}",
        "severity": "high",
        "scanner": f"scanner {VALUE}",
        "file": f"file {VALUE}",
        "line": 3,
        "message": f"message {VALUE}",
        "suppressed": False,
        "code_snippet": f"code {VALUE}",
    }
    finding.update(overrides)
    return finding


def _drawn(app) -> str:
    width, height = app.size
    console = Console(
        width=width,
        height=height,
        file=io.StringIO(),
        force_terminal=True,
        color_system=None,
        record=True,
        legacy_windows=False,
        safe_box=False,
    )
    console.print(
        app.screen._compositor.render_update(
            full=True, screen_stack=app._background_screens
        )
    )
    return console.export_text()


def _assert_once(
    text: str, *labels: str, value: str = VALUE, snippet: bool = False
) -> None:
    """Each label followed by *value*, shown once, is on the screen; nothing raw."""
    squeezed = "".join(text.split()).replace("▌", "")
    shown = only_controls_shown(value) if snippet else controls_shown(value)
    for label in labels:
        assert "".join(f"{label} {shown}".split()) in squeezed, (label, text)
    assert "".join(controls_shown(shown).split()) not in squeezed, text
    assert "\x1b" not in text, repr(text)


async def _settle(pilot, turns: int = 6) -> None:
    for _ in range(turns):
        await pilot.pause()


def _logged(record: logging.LogRecord) -> str:
    """The record's message as it was logged, which is what the log files write.

    On a Windows console or CI runner the log module's filter rewrites a record's
    text in ASCII for the console, the raw escape in a value shown as its text,
    and keeps the message and arguments as logged on the record for the file
    sinks (``_ash_unfiltered``). A test that asks what the log got reads those,
    as the files do; ``getMessage()`` alone read the console form there.
    """
    unfiltered = getattr(record, "_ash_unfiltered", None)
    if unfiltered is None:
        return record.getMessage()
    msg, args = unfiltered
    return str(msg) % args if args else str(msg)


@contextmanager
def _records():
    """The ASH log records made inside the block, at every level."""
    records: list[logging.LogRecord] = []

    class Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Keep(logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


@pytest.mark.asyncio
async def test_the_table_and_the_status_bar(tmp_path):
    app = tui.FindingsExplorerApp([_finding()], config_path=tmp_path / ".ash.yaml")
    async with app.run_test(size=SCREEN) as pilot:
        await _settle(pilot)
        _assert_once(_drawn(app), "rule", "scanner", "file", "message")

        await pilot.press("j")
        await _settle(pilot)
        _assert_once(_drawn(app), "Selected: rule")
        await pilot.press("h", "k")
        await _settle(pilot)
        _assert_once(_drawn(app), "Selected: rule")


@pytest.mark.asyncio
async def test_the_detail_view_and_its_snippet(tmp_path):
    finding = _finding(suppressed=True, suppression_reason=f"reason {VALUE}")
    app = tui.FindingsExplorerApp([finding], config_path=tmp_path / ".ash.yaml")
    app.show_suppressed = True
    async with app.run_test(size=SCREEN) as pilot:
        await _settle(pilot)
        await pilot.press("v")
        await _settle(pilot)
        text = _drawn(app)

    _assert_once(text, "rule", "scanner", "file", "message", "reason")
    _assert_once(text, "code", snippet=True)


@pytest.mark.asyncio
async def test_the_suppress_dialog_and_a_failed_save(tmp_path, monkeypatch):
    from textual.widgets import Button, Input

    def refuse(*_args, **_kwargs):
        raise RuntimeError(f"cannot write {VALUE}")

    monkeypatch.setattr(tui, "add_suppression_to_config", refuse)
    # The dialog saves only a suppression that names its finding, so the file is
    # one a suppression path can name (SAVABLE_FILE); the writer is then reached.
    finding = _finding(file=f"file {SAVABLE_FILE}")
    app = tui.FindingsExplorerApp([finding], config_path=tmp_path / ".ash.yaml")
    with _records() as records:
        async with app.run_test(size=SCREEN, notifications=True) as pilot:
            await _settle(pilot)
            await app.push_screen(tui.SuppressDialog(finding))
            await _settle(pilot)
            # The dialog names the finding without label prefixes: the values
            # themselves ("rule {VALUE}", "file {SAVABLE_FILE}") are shown once.
            drawn = _drawn(app)
            _assert_once(drawn, "rule")
            _assert_once(drawn, "file", value=SAVABLE_FILE)

            app.screen.query_one("#reason_input", Input).value = "because"
            app.screen.query_one("#btn_suppress", Button).press()
            await _settle(pilot)
            # The failure is shown in the dialog's own error field, which
            # wraps at the dialog's width, so its border glyph is squeezed
            # out with the whitespace before comparing; the once/no-raw
            # properties are the helper's, label-free.
            text = _drawn(app)
            _assert_once(text)
            squeezed = "".join(text.split()).replace("▌", "").replace("│", "")
            assert "".join(f"cannot write {ONCE}".split()) in squeezed, text

    # The log gets the raw value, which its sink shows once.
    (error,) = [r for r in records if r.levelno == logging.ERROR]
    assert f"cannot write {VALUE}" in _logged(error), _logged(error)


@pytest.mark.asyncio
async def test_the_scanner_filter(tmp_path):
    from textual.widgets import Select

    # The option list is as narrow as the Select (30 columns, an ellipsis past
    # that), so the name is an ESC and a lookalike alone.
    scanner = "s\x1b\\x64"
    finding = _finding(scanner=scanner)
    app = tui.FindingsExplorerApp([finding], config_path=tmp_path / ".ash.yaml")
    async with app.run_test(size=SCREEN) as pilot:
        await _settle(pilot)
        # The table draws the scanner too: hidden, the option list is all that does.
        app.query_one("#findings_table").display = False
        await pilot.press("f")
        await _settle(pilot)
        app.query_one("#scanner_select", Select).focus()
        await pilot.press("enter")
        await _settle(pilot)
        _assert_once(_drawn(app), "", value=scanner)


def test_a_refused_source_read_logs_the_raw_name(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "link.py").symlink_to("/etc/hostname")
    finding = _finding(file=f"src/{VALUE}", code_snippet=None)

    with _records() as records:
        assert tui._source_excerpt(finding, tmp_path) is None
        finding["file"] = "src/link.py"
        assert tui._source_excerpt(finding, tmp_path) is None

    messages = [_logged(r) for r in records]
    assert any(VALUE in message for message in messages), messages
    assert not any(ONCE in message for message in messages), messages


def test_a_load_error_is_shown_once_on_the_console(tmp_path, monkeypatch, capsys):
    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")

    def refuse(_path):
        raise ValueError(f"bad report {VALUE}")

    monkeypatch.setattr(tui.AshAggregatedResults, "load_model", refuse)
    # A report that does not load leaves nothing to show, so the command exits 1
    # after it prints the error.
    with pytest.raises(typer.Exit):
        tui.findings_command(
            output_dir=tmp_path, report_file="report.json", config=tmp_path / ".a.yaml"
        )

    captured = capsys.readouterr()
    printed = captured.out + captured.err
    assert f"bad report {ONCE}" in printed, printed
    assert TWICE not in printed and "\x1bcq" not in printed, repr(printed)


#: A value the run read from the environment, and a message that prints it with a
#: complete color code in the middle: no contiguous match finds it until the code
#: is gone, so only a redaction that looks past the code hides it.
_SECRET_HEAD = "canary-Zq7Kx9Lm"
_SECRET_TAIL = "Pw4Nv2Rt-canary"


@pytest.mark.parametrize("carried", [True, False], ids=["value-carried", "control"])
def test_a_load_error_hides_a_value_a_complete_code_splits(
    tmp_path, monkeypatch, capsys, carried
):
    """The console line holds the carried value neither whole nor in pieces.

    The control carries no value, so the same message prints its words: the
    absence in the first case is the redaction's, not a message that was lost.
    """
    from automated_security_helper.utils.error_text import carry_environment_values

    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")

    def refuse(_path):
        error = ValueError(f"bad report {_SECRET_HEAD}\x1b[1m{_SECRET_TAIL} end")
        if carried:
            carry_environment_values(error, [_SECRET_HEAD + _SECRET_TAIL])
        raise error

    monkeypatch.setattr(tui.AshAggregatedResults, "load_model", refuse)
    with pytest.raises(typer.Exit):
        tui.findings_command(
            output_dir=tmp_path, report_file="report.json", config=tmp_path / ".a.yaml"
        )

    captured = capsys.readouterr()
    printed = captured.out + captured.err
    assert "bad report" in printed, repr(printed)
    if carried:
        assert _SECRET_HEAD not in printed, repr(printed)
        assert _SECRET_TAIL not in printed, repr(printed)
    else:
        assert _SECRET_HEAD in printed and _SECRET_TAIL in printed, repr(printed)
