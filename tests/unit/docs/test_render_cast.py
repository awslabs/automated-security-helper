"""The terminal emulator and SVG renderer of the quick-start recording.

``scripts/render_cast.py`` turns a recording (an asciicast, the run record and the
storyboard) into an animated SVG and a poster. Every rule it holds is checked here on
planted input:

* the emulator, with Rich as the oracle: what Rich prints for a table, a panel titled
  with the bar-chart emoji and Markdown at width 100 lands in the emulated grid as the
  text ``Console(record=True).export_text()`` holds, and so does what a ``Live``
  display redraws with cursor movements and line erases;
* the escape subset: deferred wrap at the last column (an exact-width line adds no
  blank row), scrolling, cursor movement, erases, SGR in 16, 256 and true color, wide
  cells and combining marks measured by ``rich.cells``, OSC titles and links, and a
  loud refusal of every other sequence, naming its bytes;
* the frames: output events closer than 50 ms merge, a typed command is one frame with
  a reveal and never one frame per character, the poster is the end screen of the
  storyboard's ``poster_scene``, and a deterministic decimation caps the count;
* the SVG: it parses, holds no script and no scheme URL, stores each distinct row once,
  pins every text run to the grid, animates one strip with step keyframes, and is
  byte for byte the same under two hash seeds;
* the command line: ``--check`` goes through ``write_or_check``, and an input the
  renderer refuses exits 2 with the reason.

Each refusal test plants one defect in an otherwise good input, and each detector has a
must-flag and a must-not-flag input.
"""

from __future__ import annotations

import ast
import importlib
import io
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, NamedTuple

import pytest
import yaml
from rich.cells import cell_len
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from automated_security_helper.utils.ui_theme import COLORS

pytestmark = pytest.mark.unit

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
MODULE = SCRIPTS / "render_cast.py"
SVG = "{http://www.w3.org/2000/svg}"

# Names the tests spell once. Code points are named, never written as escapes, so a
# file written through an editor cannot turn them into the characters.
BAR_CHART = "\N{BAR CHART}"
ZWJ = "\N{ZERO WIDTH JOINER}"
VS16 = "\N{VARIATION SELECTOR-16}"
ACUTE = "\N{COMBINING ACUTE ACCENT}"
SUN = "\N{BLACK SUN WITH RAYS}"
WHITE_FLAG = "\N{WAVING WHITE FLAG}"
RAINBOW = "\N{RAINBOW}"
CJK = "\N{CJK UNIFIED IDEOGRAPH-6F22}"
ESC = "\x1b"


def _import_script(name: str) -> Any:
    """A module of scripts/, imported the way the other tests import one."""
    sys.path.insert(0, str(SCRIPTS))
    try:
        return importlib.import_module(name)
    finally:
        sys.path.remove(str(SCRIPTS))


@pytest.fixture(scope="module")
def core():
    """scripts/_cast.py, the recording's core library."""
    return _import_script("_cast")


@pytest.fixture(scope="module")
def rc():
    """scripts/render_cast.py, the module under test."""
    return _import_script("render_cast")


# ---------------------------------------------------------------------------
# The import rule
# ---------------------------------------------------------------------------

FORBIDDEN_MODULES = frozenset({"pty", "termios", "fcntl"})


def _dynamic_import_name(call: ast.Call) -> str | None:
    """The module a ``__import__("x")`` or ``import_module("x")`` call names."""
    func = call.func
    if isinstance(func, ast.Name):
        called = func.id
    elif isinstance(func, ast.Attribute):
        called = func.attr
    else:
        return None
    if called not in {"__import__", "import_module"} or not call.args:
        return None
    first = call.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def imported_roots(source: str) -> set[str]:
    """Top-level names of every module ``source`` imports, by any spelling the parser
    can see, at module level or inside any block or function."""
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            named = _dynamic_import_name(node)
            if named:
                roots.add(named.split(".")[0])
    return roots


PLANTED_IMPORTS = {
    "import pty": {"pty"},
    "import os, termios": {"termios"},
    "from fcntl import ioctl": {"fcntl"},
    "def f():\n    import pty\n": {"pty"},
    "__import__('termios')": {"termios"},
    "import importlib\nimportlib.import_module('fcntl')": {"fcntl"},
}

CLEAN_SOURCES = [
    "import json, re",
    "text = 'import pty'",
    "# import fcntl",
    "import ptyprocess",
    "from . import pty_helpers",
]


@pytest.mark.parametrize("source", sorted(PLANTED_IMPORTS))
def test_the_import_check_flags_every_spelling(source):
    """Must-flag: each planted import is found, and only the forbidden name."""
    assert imported_roots(source) & FORBIDDEN_MODULES == PLANTED_IMPORTS[source]


@pytest.mark.parametrize("source", CLEAN_SOURCES)
def test_the_import_check_ignores_names_that_only_look_like_the_modules(source):
    """Must-not-flag: strings, comments, relative imports and longer module names."""
    assert imported_roots(source) & FORBIDDEN_MODULES == set()


def test_the_renderer_imports_no_pty_termios_or_fcntl():
    roots = imported_roots(MODULE.read_text(encoding="utf-8"))
    # A scan that saw no imports at all would pass for any file.
    assert {"dataclasses", "rich", "_cast", "_reference_docs"} <= roots
    assert roots & FORBIDDEN_MODULES == set()


def test_every_refusal_is_one_error_family(rc, core):
    assert issubclass(rc.RenderError, core.CastError)
    assert issubclass(rc.UnsupportedSequence, rc.RenderError)
    assert issubclass(core.CastError, ValueError)


def test_check_mode_is_the_reference_generators_write_or_check(rc):
    """``--check`` prints a diff and exits 1 on drift, as every reference generator."""
    reference = _import_script("_reference_docs")
    assert rc.write_or_check is reference.write_or_check


# ---------------------------------------------------------------------------
# The Rich oracle
# ---------------------------------------------------------------------------

WIDTH = 100
#: Tall enough that nothing in the oracle's streams scrolls off the top.
TALL = 120
#: What a recorded terminal says about itself, so a host's NO_COLOR and COLUMNS never
#: reach Rich's choices.
TERM_ENV = {"TERM": "xterm-256color", "COLORTERM": "truecolor"}

MARKDOWN_SOURCE = (
    "# Findings\n\n"
    "A *finding* has **three** parts: a `rule`, a place and "
    "a [link](https://example.com/page).\n\n"
    "- first item\n- second item\n\n"
    "> a quoted note\n\n"
    "```python\nprint('hello')\n```\n\n"
    "| rule | severity |\n| --- | --- |\n| B324 | HIGH |\n\n"
    "---\n"
)


def make_table() -> Table:
    table = Table(title="Scanner results", header_style="bold")
    for name in ("Scanner", "Status", "Critical", "High", "Action"):
        table.add_column(name)
    table.add_row("bandit", "[red]FAILED[/red]", "0", "2", "2")
    table.add_row(
        "detect-secrets", "[green]PASSED[/green]", "0", "0", "0", style="on #161d26"
    )
    return table


def make_panel() -> Panel:
    return Panel(
        "[b]How to read this table[/b]\nrows are scanners, columns are severities",
        title=f"{BAR_CHART} Metrics help",
        subtitle="notes",
        border_style="#42b4ff",
    )


def make_markdown() -> Markdown:
    return Markdown(MARKDOWN_SOURCE)


FACTORIES = {"table": make_table, "panel": make_panel, "markdown": make_markdown}


def terminal_console(buffer, color_system="truecolor", width=WIDTH, height=None):
    """A Rich console as a program sees one on a pty: a terminal that has color."""
    return Console(
        file=buffer,
        force_terminal=True,
        color_system=color_system,
        width=width,
        height=height,
        legacy_windows=False,
        highlight=False,
        _environ=TERM_ENV,
    )


def to_pty(stream: str) -> str:
    """Rich ends each line with LF and leaves the carriage return to the line
    discipline (ONLCR); a recording holds what the pty then delivers."""
    return stream.replace("\n", "\r\n")


def ansi_stream(*renderables, color_system="truecolor", width=WIDTH) -> str:
    buffer = io.StringIO()
    console = terminal_console(buffer, color_system, width)
    for renderable in renderables:
        console.print(renderable)
    return to_pty(buffer.getvalue())


def trimmed(lines: list[str]) -> list[str]:
    """Rows right-stripped, with the blank rows at the bottom dropped."""
    rows = [line.rstrip() for line in lines]
    while rows and not rows[-1]:
        rows.pop()
    return rows


def export_lines(*renderables, width=WIDTH, height=None) -> list[str]:
    """What ``Console(record=True).export_text()`` holds for the same renderables."""
    recorder = Console(
        record=True,
        width=width,
        height=height,
        file=io.StringIO(),
        legacy_windows=False,
        highlight=False,
        _environ=TERM_ENV,
    )
    for renderable in renderables:
        recorder.print(renderable)
    return trimmed(recorder.export_text().split("\n"))


def emulate(rc, stream: str, cols: int = WIDTH, rows: int = TALL):
    emulator = rc.Emulator(cols, rows)
    emulator.feed(stream)
    return emulator


def locate(screen, word: str) -> tuple[int, int]:
    """Row and column of ``word`` in a screen of single-cell characters."""
    for index, line in enumerate(screen.lines()):
        column = line.find(word)
        if column >= 0:
            return index, column
    raise AssertionError(f"{word!r} is not on the screen")


@pytest.mark.parametrize("name", sorted(FACTORIES))
def test_the_grid_equals_what_rich_exports_for_each_renderable(rc, name):
    emulator = emulate(rc, ansi_stream(FACTORIES[name]()))
    lines = emulator.screen().lines()
    assert lines == export_lines(FACTORIES[name]())
    assert len(lines) >= 4


def test_the_grid_equals_what_rich_exports_for_a_table_a_panel_and_markdown(rc):
    """The oracle: one stream, three renderables, width 100, truecolor."""
    stream = ansi_stream(make_table(), make_panel(), make_markdown())
    lines = emulate(rc, stream).screen().lines()
    assert lines == export_lines(make_table(), make_panel(), make_markdown())
    # The oracle is not vacuous: it holds all three parts, link text included.
    text = "\n".join(lines)
    for expected in (
        "Scanner results",
        "detect-secrets",
        "Metrics help",
        "B324",
        "link",
    ):
        assert expected in text


@pytest.mark.parametrize("color_system", ["standard", "256", "truecolor"])
def test_every_rich_color_system_lands_as_the_same_text(rc, color_system):
    stream = ansi_stream(
        make_table(), make_panel(), make_markdown(), color_system=color_system
    )
    lines = emulate(rc, stream).screen().lines()
    assert lines == export_lines(make_table(), make_panel(), make_markdown())


def test_a_wide_emoji_takes_two_cells_and_the_border_stays_in_column_100(rc):
    screen = emulate(rc, ansi_stream(make_panel())).screen()
    top = screen.rows[0]
    assert len(top) == WIDTH
    at = [index for index, cell in enumerate(top) if cell.text == BAR_CHART]
    assert len(at) == 1
    assert top[at[0] + 1].text == ""
    # The right border is the last cell: a one-cell emoji would have pushed it to a
    # 101st column, and the line would have wrapped.
    assert top[WIDTH - 1].text not in ("", " ")
    assert screen.lines() == export_lines(make_panel())


def test_rich_styles_reach_the_cells(rc):
    screen = emulate(rc, ansi_stream(make_table())).screen()
    row, column = locate(screen, "FAILED")
    assert screen.rows[row][column].style.fg == 1
    row, column = locate(screen, "PASSED")
    assert screen.rows[row][column].style.fg == 2
    row, column = locate(screen, "Critical")
    assert screen.rows[row][column].style.bold
    row, column = locate(screen, "Scanner results")
    assert screen.rows[row][column].style.italic
    # The second row's own style is a true-color background.
    row, column = locate(screen, "detect-secrets")
    assert screen.rows[row][column].style.bg == (0x16, 0x1D, 0x26)
    # A cell no style reached is the default style.
    row, column = locate(screen, "bandit")
    assert screen.rows[row][column].style == rc.Style()


def test_true_color_and_256_color_codes_are_kept_as_written(rc):
    truecolor = emulate(
        rc, ansi_stream(Text("tc", style="#ff8800")), cols=20, rows=4
    ).screen()
    assert truecolor.rows[0][0].style.fg == (255, 136, 0)
    indexed = emulate(
        rc,
        ansi_stream(Text("ix", style="color(202)"), color_system="256"),
        cols=20,
        rows=4,
    ).screen()
    assert indexed.rows[0][0].style.fg == 202


# ---------------------------------------------------------------------------
# Live displays: cursor movement and line erases
# ---------------------------------------------------------------------------


def live_stream(renders, *, width=WIDTH, height=None, **live_options) -> str:
    """What a pty reads from a ``Live`` that is refreshed once per render, by hand."""
    buffer = io.StringIO()
    console = terminal_console(buffer, width=width, height=height)
    with Live(
        console=console,
        auto_refresh=False,
        redirect_stdout=False,
        redirect_stderr=False,
        **live_options,
    ) as live:
        for make in renders:
            live.update(make(), refresh=True)
    return to_pty(buffer.getvalue())


def three_renders():
    return [
        lambda: Panel("first-only\ntwo\nthree", title="progress"),
        lambda: Panel("one\ntwo\nthree\nfour\nfive", title="progress"),
        lambda: Text.from_markup("[green]done[/green] in three steps"),
    ]


def test_a_live_with_three_manual_refreshes_ends_on_the_last_render(rc):
    renders = three_renders()
    stream = live_stream(renders)
    screen = emulate(rc, stream, rows=20).screen()
    # The last render is one line, shorter than the two before it: every line of
    # them has to be gone, not just overwritten where the new text reached.
    assert screen.lines() == export_lines(renders[-1]())
    assert screen.lines() == ["done in three steps"]
    assert "first-only" not in screen.text()
    # Rich leaves the cursor below the display and shows it again.
    assert screen.cursor_visible


def test_the_cursor_is_hidden_while_the_live_runs_and_shown_after(rc):
    stream = live_stream(three_renders())
    shown_at = stream.rindex(ESC + "[?25h")
    assert not emulate(rc, stream[:shown_at], rows=20).screen().cursor_visible
    assert emulate(rc, stream, rows=20).screen().cursor_visible


def make_layout(log_lines: list[str], percent: int) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(Panel("\n".join(log_lines), title="log"), name="log"),
        Layout(Panel(f"progress {percent} percent", title="progress"), size=3),
    )
    return layout


def test_a_live_over_a_layout_redraws_the_whole_screen_each_refresh(rc):
    """The shape ASH's progress display has: a Layout the height of the console."""
    renders = [
        lambda: make_layout(["first-only"], 10),
        lambda: make_layout(["first-only", "second"], 50),
        lambda: make_layout(["second", "third", "fourth"], 100),
    ]
    stream = live_stream(renders, height=10, screen=False, vertical_overflow="visible")
    screen = emulate(rc, stream, rows=14).screen()
    expected = export_lines(make_layout(["second", "third", "fourth"], 100), height=10)
    assert len(expected) == 10
    assert screen.lines() == expected
    assert "first-only" not in screen.text()


def test_an_exact_width_rich_line_adds_no_blank_row(rc):
    """Rich prints a full-width line and LF: a terminal does not wrap before the LF."""
    text = Text("x" * WIDTH)
    screen = emulate(rc, ansi_stream(text, Text("after")), rows=6).screen()
    assert screen.lines() == ["x" * WIDTH, "after"]


# ---------------------------------------------------------------------------
# The emulator: text, wrapping and scrolling
# ---------------------------------------------------------------------------


def feed(rc, data: str, cols: int = 10, rows: int = 4):
    emulator = rc.Emulator(cols, rows)
    emulator.feed(data)
    return emulator


def cursor_of(emulator) -> tuple[int, int]:
    screen = emulator.screen()
    return screen.cursor_row, screen.cursor_col


def test_text_lands_at_the_cursor_and_crlf_starts_a_new_line(rc):
    emulator = feed(rc, "ab\r\ncd")
    assert emulator.screen().lines() == ["ab", "cd"]
    assert cursor_of(emulator) == (1, 2)


def test_a_line_feed_alone_moves_down_and_keeps_the_column(rc):
    assert feed(rc, "ab\ncd").screen().lines() == ["ab", "  cd"]


def test_a_carriage_return_goes_to_column_zero_and_text_overwrites(rc):
    assert feed(rc, "abcd\rXY").screen().lines() == ["XYcd"]


def test_backspace_moves_left_without_erasing_and_stops_at_column_zero(rc):
    assert feed(rc, "abc\b\bX").screen().lines() == ["aXc"]
    assert feed(rc, "\b\bX").screen().lines() == ["X"]


def test_tab_goes_to_the_next_stop_every_eight_columns_and_stops_at_the_edge(rc):
    assert feed(rc, "a\tb", cols=20).screen().lines() == ["a" + " " * 7 + "b"]
    assert feed(rc, "\t\t\t\tb", cols=20).screen().lines() == [" " * 19 + "b"]


def test_an_exact_width_line_followed_by_crlf_adds_no_blank_row(rc):
    emulator = feed(rc, "x" * 10 + "\r\ny", cols=10)
    assert emulator.screen().lines() == ["x" * 10, "y"]
    assert cursor_of(emulator) == (1, 1)


def test_the_character_after_an_exact_width_line_wraps(rc):
    assert feed(rc, "x" * 10 + "z", cols=10).screen().lines() == ["x" * 10, "z"]


def test_the_wrap_waits_on_the_last_cell_until_a_character_needs_the_next_row(rc):
    emulator = feed(rc, "x" * 10, cols=10)
    assert cursor_of(emulator) == (0, 9)
    assert emulator.screen().lines() == ["x" * 10]


def test_a_carriage_return_cancels_a_pending_wrap(rc):
    assert feed(rc, "x" * 10 + "\ry", cols=10).screen().lines() == ["y" + "x" * 9]


def test_cursor_movement_cancels_a_pending_wrap(rc):
    emulator = feed(rc, "x" * 10 + ESC + "[2Dy", cols=10)
    assert emulator.screen().lines() == ["x" * 7 + "y" + "xx"]


def test_a_line_feed_on_the_bottom_row_scrolls_the_screen_up(rc):
    emulator = feed(rc, "a\r\nb\r\nc\r\nd", cols=10, rows=3)
    assert emulator.screen().lines() == ["b", "c", "d"]
    assert cursor_of(emulator) == (2, 1)


def test_a_wrap_on_the_bottom_row_scrolls_too(rc):
    emulator = feed(rc, "a\r\nb\r\n" + "x" * 10 + "z", cols=10, rows=3)
    assert emulator.screen().lines() == ["b", "x" * 10, "z"]


def test_an_exact_width_line_on_the_bottom_row_scrolls_once(rc):
    emulator = feed(rc, "a\r\nb\r\n" + "x" * 10 + "\r\n", cols=10, rows=3)
    assert emulator.screen().lines() == ["b", "x" * 10]


def test_a_snapshot_does_not_change_when_more_is_fed_and_shares_untouched_rows(rc):
    emulator = feed(rc, "one\r\ntwo", rows=3)
    before = emulator.screen()
    emulator.feed("\r\nthree")
    after = emulator.screen()
    assert before.lines() == ["one", "two"]
    assert after.lines() == ["one", "two", "three"]
    assert before.rows[0] is after.rows[0]
    assert before.rows[2] is not after.rows[2]


def test_a_screen_smaller_than_two_columns_or_one_row_is_refused(rc):
    for cols, rows in ((1, 3), (10, 0), (0, 0)):
        with pytest.raises(rc.RenderError):
            rc.Emulator(cols, rows)


# ---------------------------------------------------------------------------
# The emulator: cursor movement and erases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sequence", "expected"),
    [
        ("[A", (1, 5)),
        ("[0A", (1, 5)),
        ("[2A", (0, 5)),
        ("[99A", (0, 5)),
        ("[B", (3, 5)),
        ("[99B", (5, 5)),
        ("[C", (2, 6)),
        ("[0C", (2, 6)),
        ("[99C", (2, 11)),
        ("[D", (2, 4)),
        ("[99D", (2, 0)),
        ("[E", (3, 0)),
        ("[2E", (4, 0)),
        ("[99E", (5, 0)),
        ("[F", (1, 0)),
        ("[2F", (0, 0)),
        ("[G", (2, 0)),
        ("[4G", (2, 3)),
        ("[99G", (2, 11)),
        ("[H", (0, 0)),
        ("[4H", (3, 0)),
        ("[4;7H", (3, 6)),
        ("[;3H", (0, 2)),
        ("[99;99H", (5, 11)),
    ],
)
def test_cursor_movement_from_row_3_column_6_of_a_12_by_6_screen(
    rc, sequence, expected
):
    emulator = rc.Emulator(12, 6)
    emulator.feed(ESC + "[3;6H" + ESC + sequence)
    assert cursor_of(emulator) == expected


def filled(rc):
    emulator = rc.Emulator(5, 3)
    emulator.feed("abcde\r\nfghij\r\nklmno")
    # Row 2, column 3: the cursor is on the "h".
    emulator.feed(ESC + "[2;3H")
    return emulator


@pytest.mark.parametrize(
    ("sequence", "expected"),
    [
        ("[K", ["abcde", "fg", "klmno"]),
        ("[0K", ["abcde", "fg", "klmno"]),
        ("[1K", ["abcde", "   ij", "klmno"]),
        ("[2K", ["abcde", "", "klmno"]),
        ("[J", ["abcde", "fg"]),
        ("[0J", ["abcde", "fg"]),
        ("[1J", ["", "   ij", "klmno"]),
        ("[2J", []),
    ],
)
def test_erases_clear_what_the_spec_says_and_leave_the_cursor(rc, sequence, expected):
    emulator = filled(rc)
    emulator.feed(ESC + sequence)
    assert emulator.screen().lines() == expected
    assert cursor_of(emulator) == (1, 2)


def test_an_erase_uses_the_current_background_and_nothing_else(rc):
    emulator = filled(rc)
    emulator.feed(ESC + "[1;31;44m" + ESC + "[K")
    cell = emulator.screen().rows[1][3]
    assert cell.text == " "
    assert cell.style == rc.Style(bg=4)
    emulator.feed(ESC + "[0m" + ESC + "[2;1H" + ESC + "[K")
    assert emulator.screen().rows[1][3].style == rc.Style()


@pytest.mark.parametrize("sequence", ["[3J", "[4J", "[3K", "[9K"])
def test_an_erase_mode_outside_the_spec_is_refused(rc, sequence):
    with pytest.raises(rc.UnsupportedSequence):
        rc.Emulator(5, 3).feed(ESC + sequence)


# ---------------------------------------------------------------------------
# The emulator: SGR
# ---------------------------------------------------------------------------


def style_at(rc, data: str, column: int = 0):
    emulator = rc.Emulator(20, 3)
    emulator.feed(data)
    return emulator.screen().rows[0][column].style


@pytest.mark.parametrize(
    ("code", "field"),
    [
        ("1", "bold"),
        ("2", "dim"),
        ("3", "italic"),
        ("4", "underline"),
        ("7", "reverse"),
    ],
)
def test_each_sgr_attribute_is_set_and_its_reset_clears_it(rc, code, field):
    assert style_at(rc, f"{ESC}[{code}mX") == rc.Style(**{field: True})
    undo = {"1": "22", "2": "22", "3": "23", "4": "24", "7": "27"}[code]
    assert style_at(rc, f"{ESC}[{code}m{ESC}[{undo}mX") == rc.Style()


def test_sgr_22_clears_bold_and_dim_together(rc):
    assert style_at(rc, f"{ESC}[1;2m{ESC}[22mX") == rc.Style()


def test_sgr_0_and_an_empty_sgr_reset_everything(rc):
    set_all = f"{ESC}[1;2;3;4;7;31;42m"
    assert style_at(rc, f"{set_all}{ESC}[0mX") == rc.Style()
    assert style_at(rc, f"{set_all}{ESC}[mX") == rc.Style()
    assert style_at(rc, f"{set_all}{ESC}[;mX") == rc.Style()


@pytest.mark.parametrize("index", range(8))
def test_the_sixteen_colors_foreground_and_background(rc, index):
    assert style_at(rc, f"{ESC}[{30 + index}mX").fg == index
    assert style_at(rc, f"{ESC}[{90 + index}mX").fg == 8 + index
    assert style_at(rc, f"{ESC}[{40 + index}mX").bg == index
    assert style_at(rc, f"{ESC}[{100 + index}mX").bg == 8 + index


def test_sgr_39_and_49_return_to_the_default_colors(rc):
    assert style_at(rc, f"{ESC}[31;42m{ESC}[39;49mX") == rc.Style()


def test_256_colors_and_true_colors_are_read_in_both_places(rc):
    assert style_at(rc, f"{ESC}[38;5;202mX").fg == 202
    assert style_at(rc, f"{ESC}[48;5;17mX").bg == 17
    assert style_at(rc, f"{ESC}[38;2;1;2;3mX").fg == (1, 2, 3)
    assert style_at(rc, f"{ESC}[48;2;250;251;252mX").bg == (250, 251, 252)


def test_one_sgr_may_set_many_things_in_any_order(rc):
    style = style_at(rc, f"{ESC}[1;38;2;255;0;0;48;5;4;4;3mX")
    assert style == rc.Style(
        fg=(255, 0, 0), bg=4, bold=True, underline=True, italic=True
    )


def test_a_style_stays_until_reset_across_lines_and_wraps(rc):
    emulator = feed(rc, f"{ESC}[31mab\r\ncd", cols=10)
    rows = emulator.screen().rows
    assert [rows[0][0].style.fg, rows[1][1].style.fg] == [1, 1]
    # A cell written before the style was set keeps the style it had.
    emulator = feed(rc, f"a{ESC}[31mb")
    assert emulator.screen().rows[0][0].style.fg is None


@pytest.mark.parametrize(
    "sequence",
    [
        "[5m",
        "[6m",
        "[8m",
        "[9m",
        "[21m",
        "[53m",
        "[10m",
        "[38;5;256m",
        "[48;2;1;2m",
        "[38;2;256;0;0m",
        "[38m",
        "[38;7m",
        "[38:2::1:2:3m",
        "[1;5m",
    ],
)
def test_an_sgr_outside_the_subset_is_refused_whole(rc, sequence):
    with pytest.raises(rc.UnsupportedSequence):
        rc.Emulator(10, 3).feed("ab" + ESC + sequence)


# ---------------------------------------------------------------------------
# The emulator: cursor visibility, OSC, split feeds
# ---------------------------------------------------------------------------


def test_the_cursor_is_hidden_and_shown_by_private_mode_25(rc):
    emulator = feed(rc, "")
    assert emulator.screen().cursor_visible
    emulator.feed(ESC + "[?25l")
    assert not emulator.screen().cursor_visible
    emulator.feed(ESC + "[?25h")
    assert emulator.screen().cursor_visible


@pytest.mark.parametrize("terminator", ["\x07", ESC + "\\"], ids=["bel", "st"])
@pytest.mark.parametrize("code", ["0", "1", "2"])
def test_a_title_sequence_is_ignored_and_draws_nothing(rc, code, terminator):
    emulator = feed(rc, f"a{ESC}]{code};the title{terminator}b")
    assert emulator.screen().lines() == ["ab"]


def test_an_osc_8_link_shows_its_text_and_its_id_changes_nothing(rc):
    def link(identifier: str) -> str:
        return (
            f"{ESC}]8;id={identifier};https://example.com/a{ESC}\\link{ESC}]8;;{ESC}\\"
            " done"
        )

    first = feed(rc, link("123"))
    second = feed(rc, link("987654"))
    assert first.screen().lines() == ["link done"]
    assert first.screen() == second.screen()


def test_a_sequence_split_between_feeds_is_read_whole(rc):
    emulator = rc.Emulator(10, 3)
    for piece in (ESC, "[3", "1", "mX", f"{ESC}]0;ti", "tle\x07Y"):
        emulator.feed(piece)
    screen = emulator.screen()
    assert screen.lines() == ["XY"]
    assert [screen.rows[0][0].style.fg, screen.rows[0][1].style.fg] == [1, 1]
    assert emulator.pending_sequence == ""


def test_a_stream_that_stops_inside_a_sequence_leaves_it_pending(rc):
    emulator = feed(rc, f"ab{ESC}[3")
    assert emulator.pending_sequence == f"{ESC}[3"
    emulator = feed(rc, f"ab{ESC}]0;title")
    assert emulator.pending_sequence == f"{ESC}]0;title"
    emulator = feed(rc, f"ab{ESC}")
    assert emulator.pending_sequence == ESC
    assert feed(rc, "ab").pending_sequence == ""


# ---------------------------------------------------------------------------
# The emulator: wide cells and combining marks, through rich.cells
# ---------------------------------------------------------------------------


def test_a_wide_character_takes_two_cells(rc):
    emulator = feed(rc, CJK + "a", cols=6)
    screen = emulator.screen()
    assert [cell.text for cell in screen.rows[0][:3]] == [CJK, "", "a"]
    assert screen.lines() == [CJK + "a"]
    assert cursor_of(emulator) == (0, 3)


def test_a_wide_character_that_does_not_fit_moves_whole_to_the_next_row(rc):
    emulator = feed(rc, "abcde" + CJK, cols=6)
    screen = emulator.screen()
    assert screen.lines() == ["abcde", CJK]
    assert screen.rows[0][5].text == " "


def test_a_wide_character_in_the_last_two_cells_defers_the_wrap(rc):
    emulator = feed(rc, "abcd" + CJK + "\r\nz", cols=6)
    assert emulator.screen().lines() == ["abcd" + CJK, "z"]


def test_writing_over_half_of_a_wide_character_blanks_the_other_half(rc):
    left = feed(rc, CJK + "\rX", cols=4).screen()
    assert [cell.text for cell in left.rows[0][:3]] == ["X", " ", " "]
    right = feed(rc, "a" + CJK + ESC + "[1;3HX", cols=6).screen()
    assert [cell.text for cell in right.rows[0][:4]] == ["a", " ", "X", " "]


def test_a_combining_mark_joins_the_cell_before_it(rc):
    emulator = feed(rc, "e" + ACUTE + "x")
    row = emulator.screen().rows[0]
    assert [row[0].text, row[1].text] == ["e" + ACUTE, "x"]
    assert cursor_of(emulator) == (0, 2)


def test_a_combining_mark_with_nothing_before_it_draws_nothing(rc):
    emulator = feed(rc, ACUTE + "x")
    assert emulator.screen().lines() == ["x"]
    emulator = feed(rc, "a\r" + ACUTE + "x")
    assert emulator.screen().lines() == ["x"]


def test_variation_selector_16_widens_a_narrow_emoji_as_rich_measures_it(rc):
    assert cell_len(SUN) == 1
    assert cell_len(SUN + VS16) == 2
    emulator = feed(rc, SUN + VS16 + "x", cols=6)
    row = emulator.screen().rows[0]
    assert [cell.text for cell in row[:3]] == [SUN + VS16, "", "x"]
    assert cursor_of(emulator) == (0, 3)


def test_a_zero_width_joiner_sequence_is_one_cluster_as_wide_as_rich_says(rc):
    flag = WHITE_FLAG + VS16 + ZWJ + RAINBOW
    assert cell_len(flag) == 2
    emulator = feed(rc, flag + "x", cols=6)
    row = emulator.screen().rows[0]
    assert [cell.text for cell in row[:3]] == [flag, "", "x"]


# ---------------------------------------------------------------------------
# The emulator: what it refuses
# ---------------------------------------------------------------------------

#: Sequences outside the subset, and the bytes the refusal has to name for each. A
#: sequence refused at its first byte after ESC names those two bytes only.
REFUSED = [
    (ESC + "[?2026h", ESC + "[?2026h"),
    (ESC + "[?1049h", ESC + "[?1049h"),
    (ESC + "[?7l", ESC + "[?7l"),
    (ESC + "[?25;1h", ESC + "[?25;1h"),
    (ESC + "[?25p", ESC + "[?25p"),
    (ESC + "[5n", ESC + "[5n"),
    (ESC + "[>0c", ESC + "[>0c"),
    (ESC + "[2 q", ESC + "[2 q"),
    (ESC + "[1;2;3A", ESC + "[1;2;3A"),
    (ESC + "[1;2;3;4H", ESC + "[1;2;3;4H"),
    (ESC + "[@", ESC + "[@"),
    (ESC + "[P", ESC + "[P"),
    (ESC + "[L", ESC + "[L"),
    (ESC + "[M", ESC + "[M"),
    (ESC + "[S", ESC + "[S"),
    (ESC + "[T", ESC + "[T"),
    (ESC + "[d", ESC + "[d"),
    (ESC + "[X", ESC + "[X"),
    (ESC + "[r", ESC + "[r"),
    (ESC + "[s", ESC + "[s"),
    (ESC + "[u", ESC + "[u"),
    (ESC + "[4h", ESC + "[4h"),
    (ESC + "[f", ESC + "[f"),
    (ESC + "7", ESC + "7"),
    (ESC + "8", ESC + "8"),
    (ESC + "M", ESC + "M"),
    (ESC + "c", ESC + "c"),
    (ESC + "=", ESC + "="),
    (ESC + "(B", ESC + "("),
    (ESC + "P1$r", ESC + "P"),
    (ESC + "_x", ESC + "_"),
    (ESC + "]52;c;aGk=\x07", ESC + "]52;c;aGk=\x07"),
    (ESC + "]133;A\x07", ESC + "]133;A\x07"),
    (ESC + "]7;file:///tmp" + ESC + "\\", ESC + "]7;file:///tmp" + ESC + "\\"),
    (ESC + "]8\x07", ESC + "]8\x07"),
    ("\x07", "\x07"),
    ("\x0b", "\x0b"),
    ("\x0c", "\x0c"),
    ("\x00", "\x00"),
    ("\x0e", "\x0e"),
    ("\x7f", "\x7f"),
    ("\x9b", "\x9b"),
    (ESC + "[1\n", ESC + "[1\n"),
]


def escaped(text: str) -> str:
    return text.encode("unicode_escape").decode("ascii")


@pytest.mark.parametrize(("data", "named"), REFUSED)
def test_a_sequence_outside_the_subset_is_refused_naming_its_bytes(rc, data, named):
    emulator = rc.Emulator(20, 4)
    with pytest.raises(rc.UnsupportedSequence) as raised:
        emulator.feed("ab" + data + "cd")
    assert raised.value.sequence == named
    assert escaped(named) in str(raised.value)


def test_an_unknown_csi_sequence_is_refused(rc):
    """Synchronized output (?2026) is a CSI sequence the subset does not hold."""
    with pytest.raises(rc.UnsupportedSequence) as raised:
        feed(rc, ESC + "[?2026h")
    assert "\\x1b[?2026h" in str(raised.value)
    assert isinstance(raised.value, rc.RenderError)


@pytest.mark.parametrize("code", [0xFFFE, 0xFFFF, 0xD800, 0xDFFF])
def test_a_character_xml_cannot_hold_is_refused(rc, code):
    with pytest.raises(rc.UnsupportedSequence):
        feed(rc, "a" + chr(code))


def test_a_sequence_longer_than_any_the_subset_holds_is_refused(rc):
    with pytest.raises(rc.UnsupportedSequence):
        feed(rc, ESC + "[" + "1" * 200 + "A")
    with pytest.raises(rc.UnsupportedSequence):
        feed(rc, ESC + "]0;" + "t" * 5000 + "\x07")


def test_everything_the_subset_holds_is_not_refused(rc):
    """Must-not-flag: one stream of every admitted sequence."""
    stream = (
        "a\tb\b\r\n"
        + "".join(f"{ESC}[{code}" for code in ("A", "B", "C", "D", "E", "F", "G"))
        + f"{ESC}[2;3H{ESC}[K{ESC}[1K{ESC}[2K{ESC}[J{ESC}[1J{ESC}[2J"
        + f"{ESC}[1;3;4;7;31;42;91;101;38;5;9;48;2;1;2;3m{ESC}[0m{ESC}[m"
        + f"{ESC}[?25l{ESC}[?25h{ESC}]0;t\x07{ESC}]2;t{ESC}\\"
        + f"{ESC}]8;id=1;https://example.com{ESC}\\x{ESC}]8;;{ESC}\\"
    )
    assert feed(rc, stream, cols=20, rows=6).pending_sequence == ""


# ---------------------------------------------------------------------------
# A small recording, made the way the recorder makes one: storyboard, retimer, record
# ---------------------------------------------------------------------------


class Recording(NamedTuple):
    storyboard: Any
    retimed: Any
    cast: Any
    record: Any
    runs: dict


def storyboard_data(*, cols=40, rows=8, playback="once", poster="scan") -> dict:
    return {
        "schema": 1,
        "journey": "docs/journeys/example.journey.yaml",
        "terminal": {"cols": cols, "rows": rows, "prompt": "$ "},
        "typing": {"chars_per_second": 30, "lead_in_s": 0.3},
        "output": {"max_gap_s": 0.8},
        "poster_scene": poster,
        "playback": playback,
        "scenes": [
            {
                "id": "version",
                "caption": "Check the install",
                "duration_s": 10,
                "block": "version",
                "hold_s": 2,
            },
            {
                "id": "scan",
                "caption": "Scan the project",
                "duration_s": 12,
                "block": "scan",
                "clear": True,
                "output_window_s": 6,
                "hold_s": 3,
            },
            {
                "id": "report",
                "caption": "Read the findings",
                "duration_s": 10,
                "block": "report",
                "hold_s": 2,
            },
        ],
    }


def mini_runs(core) -> dict:
    scanning = (
        core.RawChunk(0.10, f"{ESC}[?25l{ESC}[33mscanning 1 of 2{ESC}[0m"),
        core.RawChunk(0.60, f"\r{ESC}[2K{ESC}[33mscanning 2 of 2{ESC}[0m"),
        core.RawChunk(
            1.10, f"\r{ESC}[2K{ESC}[1;32mPASSED{ESC}[0m bandit\r\n{ESC}[?25h"
        ),
    )
    return {
        "version": core.SceneRun(
            "ash --version", (core.RawChunk(0.02, "ash 1.0\r\n"),)
        ),
        "scan": core.SceneRun("ash --scanners bandit", scanning),
        "report": core.SceneRun(
            "ash report",
            (core.RawChunk(0.02, f"{ESC}[1mHIGH{ESC}[0m B324 app.py:7\r\n"),),
        ),
    }


def build_recording(core, data=None, runs=None) -> Recording:
    storyboard = core.parse_storyboard(
        data or storyboard_data(), None, source="the test storyboard"
    )
    runs = runs or mini_runs(core)
    retimed = core.retime(storyboard, runs)
    cast = core.build_cast(storyboard, retimed)
    scenes = tuple(
        core.SceneRecord(
            scene_id=scene.scene_id,
            command=runs[scene.scene_id].typed,
            exit_code=0,
            end_screen=("done",),
            typing=done.typing,
        )
        for scene, done in zip(storyboard.scenes, retimed.scenes, strict=True)
    )
    record = core.RunRecord(
        ash_version="1.0", scanners=(), findings=(), reports=(), scenes=scenes
    )
    return Recording(storyboard, retimed, cast, record, runs)


@pytest.fixture
def recording(core) -> Recording:
    return build_recording(core)


def timeline_of(rc, recording, **options):
    return rc.build_timeline(
        recording.cast, recording.record, recording.storyboard, **options
    )


def scene_end_screens(rc, cast) -> list:
    """The emulated screen at the end of each scene, found without the renderer's own
    frame logic: feed every event, and read the screen just before each marker and at
    the end."""
    emulator = rc.Emulator(cast.header.width, cast.header.height)
    ends = []
    seen_marker = False
    for event in cast.events:
        if event.code == "m":
            if seen_marker:
                ends.append(emulator.screen())
            seen_marker = True
        elif event.code == "o":
            emulator.feed(event.data)
    ends.append(emulator.screen())
    return ends


def test_one_screen_is_emulated_after_each_output_event(rc, core):
    events = (
        core.CastEvent(0.0, "m", "scene"),
        core.CastEvent(0.0, "o", "ab"),
        core.CastEvent(0.5, "i", "q"),
        core.CastEvent(1.0, "o", "\r\ncd"),
    )
    cast = core.Cast(core.CastHeader(width=10, height=3), events)
    screens = list(rc.emulated_screens(cast))
    assert [screen.lines() for screen in screens] == [["ab"], ["ab", "cd"]]


def test_a_resize_event_is_refused(rc, core):
    events = (core.CastEvent(0.0, "o", "ab"), core.CastEvent(1.0, "r", "20x5"))
    cast = core.Cast(core.CastHeader(width=10, height=3), events)
    with pytest.raises(rc.RenderError, match="resize"):
        list(rc.emulated_screens(cast))


def test_a_cast_that_ends_inside_a_sequence_is_refused(rc, core):
    events = (core.CastEvent(0.0, "o", "ab"), core.CastEvent(1.0, "o", ESC + "[3"))
    cast = core.Cast(core.CastHeader(width=10, height=3), events)
    with pytest.raises(rc.RenderError, match="ends inside"):
        list(rc.emulated_screens(cast))


def test_an_unknown_sequence_in_a_cast_is_refused_with_its_bytes(rc, core):
    events = (core.CastEvent(0.0, "o", "ab" + ESC + "[?2026h"),)
    cast = core.Cast(core.CastHeader(width=10, height=3), events)
    with pytest.raises(rc.UnsupportedSequence, match=re.escape("\\x1b[?2026h")):
        list(rc.emulated_screens(cast))


# ---------------------------------------------------------------------------
# Frames
# ---------------------------------------------------------------------------


def test_a_typed_command_is_one_frame_and_never_one_frame_per_character(rc, recording):
    timeline = timeline_of(rc, recording)
    assert len(timeline.reveals) == 3
    typed_total = sum(len(run.typed) for run in recording.runs.values())
    assert [reveal.chars for reveal in timeline.reveals] == [13, 21, 10]
    assert len(timeline.frames) < typed_total
    for reveal, scene_record in zip(
        timeline.reveals, recording.record.scenes, strict=True
    ):
        frame = timeline.frames[reveal.frame]
        scene = recording.storyboard.scene(scene_record.scene_id)
        # The frame shows the whole command; the reveal uncovers it as typed.
        assert frame.time_ms == scene.start_ms
        typed = frame.screen.row_text(reveal.row)[
            reveal.col : reveal.col + reveal.chars
        ]
        assert typed == scene_record.command
        assert reveal.col == len("$ ")
        assert (reveal.start_ms, reveal.end_ms) == (
            scene_record.typing.start_ms,
            scene_record.typing.end_ms,
        )
        # No other frame of the scene holds a half-typed command: the frames after
        # the typing frame all come after the typing ended.
        later = [
            f for f in timeline.frames if f.scene == frame.scene and f is not frame
        ]
        assert all(f.time_ms >= scene_record.typing.end_ms for f in later)


def test_the_frames_of_the_small_recording_are_the_ones_the_events_make(rc, recording):
    timeline = timeline_of(rc, recording)
    # version: typing frame + the end of typing and its output within 50 ms.
    # scan: typing frame + the line feed + three redraws. report: as version.
    assert [frame.scene for frame in timeline.frames] == [0, 0, 1, 1, 1, 1, 1, 2, 2]
    assert [frame.time_ms for frame in timeline.frames] == sorted(
        {frame.time_ms for frame in timeline.frames}
    )


def test_frame_times_increase_strictly_from_zero(rc, recording):
    times = [frame.time_ms for frame in timeline_of(rc, recording).frames]
    assert times[0] == 0
    assert all(
        later > earlier for earlier, later in zip(times, times[1:], strict=False)
    )
    assert times[-1] < recording.storyboard.total_ms


def lettered(core, offsets_ms) -> Recording:
    """A one-scene-per-run recording whose output is one letter per chunk."""
    runs = mini_runs(core)
    letters = "abcdefgh"
    runs["scan"] = core.SceneRun(
        "ash scan",
        tuple(
            core.RawChunk(offset / 1000, letters[index])
            for index, offset in enumerate(offsets_ms)
        ),
    )
    return build_recording(core, runs=runs)


def test_output_events_closer_than_50_ms_merge_into_one_frame(rc, core):
    # Offsets after the line feed: 0 and 49 share a frame, 50 starts the next one
    # (it is not closer than 50 ms to the first), 60 joins it, and 120 starts a third.
    recording = lettered(core, [0, 49, 50, 60, 120])
    timeline = timeline_of(rc, recording)
    scan = [frame for frame in timeline.frames if frame.scene == 1]
    end = recording.record.scenes[1].typing.end_ms
    assert [frame.time_ms - end for frame in scan[1:]] == [0, 50, 120]
    assert [frame.screen.row_text(1).rstrip() for frame in scan[1:]] == [
        "ab",
        "abcd",
        "abcde",
    ]


def test_the_merge_window_is_set_by_the_caller(rc, core):
    recording = lettered(core, [0, 49, 50, 60, 120])
    timeline = timeline_of(rc, recording, merge_ms=1)
    scan = [frame for frame in timeline.frames if frame.scene == 1]
    assert len(scan) == 1 + 5


def test_every_scene_ends_on_a_frame_that_is_its_end_screen(rc, recording):
    timeline = timeline_of(rc, recording)
    ends = scene_end_screens(rc, recording.cast)
    assert len(ends) == 3
    assert len(timeline.scene_frames) == 3
    for index, last in enumerate(timeline.scene_frames):
        assert timeline.frames[last].scene == index
        assert timeline.frames[last].screen == ends[index]
        # It is the scene's last frame: the next frame belongs to the next scene.
        if last + 1 < len(timeline.frames):
            assert timeline.frames[last + 1].scene == index + 1


def test_the_poster_frame_is_the_end_screen_of_the_scene_the_storyboard_names(rc, core):
    for poster, index in (("version", 0), ("scan", 1), ("report", 2)):
        recording = build_recording(core, storyboard_data(poster=poster))
        timeline = timeline_of(rc, recording)
        ends = scene_end_screens(rc, recording.cast)
        assert timeline.poster_frame == timeline.scene_frames[index]
        assert timeline.frames[timeline.poster_frame].screen == ends[index]
    # The three posters are three different screens.
    assert len({tuple(end.lines()) for end in ends}) == 3


def test_a_scene_that_clears_starts_its_typing_frame_on_a_clean_screen(rc, recording):
    timeline = timeline_of(rc, recording)
    frame = timeline.frames[timeline.reveals[1].frame]
    assert frame.screen.lines() == ["$ ash --scanners bandit"]


# ---------------------------------------------------------------------------
# Decimation
# ---------------------------------------------------------------------------


def test_decimation_drops_the_frame_shown_for_the_least_time_first(rc, recording):
    full = timeline_of(rc, recording)
    assert len(full.frames) == 9
    line_feed = recording.record.scenes[1].typing.end_ms
    smaller = timeline_of(rc, recording, max_frames=8)
    assert len(smaller.frames) == 8
    dropped = {f.time_ms for f in full.frames} - {f.time_ms for f in smaller.frames}
    # The line feed ends 100 ms before the first redraw; every other frame the
    # decimation may drop is shown for 500 ms.
    assert dropped == {line_feed}


def test_decimation_keeps_what_the_poster_the_reveals_and_the_scene_ends_need(
    rc, recording
):
    full = timeline_of(rc, recording)
    smaller = timeline_of(rc, recording, max_frames=6)
    assert len(smaller.frames) == 6
    times = [frame.time_ms for frame in smaller.frames]
    assert all(
        later > earlier for earlier, later in zip(times, times[1:], strict=False)
    )
    assert len(smaller.reveals) == 3
    for reveal in smaller.reveals:
        assert smaller.frames[reveal.frame].screen.row_text(reveal.row).strip()
    for index, last in enumerate(smaller.scene_frames):
        assert (
            smaller.frames[last].screen == full.frames[full.scene_frames[index]].screen
        )
    assert (
        smaller.frames[smaller.poster_frame].screen
        == full.frames[full.poster_frame].screen
    )


def test_decimation_is_deterministic(rc, recording):
    first = timeline_of(rc, recording, max_frames=7)
    second = timeline_of(rc, recording, max_frames=7)
    assert first == second


def test_a_cap_below_the_frames_that_must_stay_is_refused(rc, recording):
    with pytest.raises(rc.RenderError, match="frames"):
        timeline_of(rc, recording, max_frames=5)


# ---------------------------------------------------------------------------
# A cast, a record and a storyboard that disagree are refused
# ---------------------------------------------------------------------------


def altered(core, recording, *, events=None, header=None, scenes=None):
    """The recording's cast and record with one thing changed."""
    cast = core.Cast(
        header=header or recording.cast.header,
        events=tuple(events if events is not None else recording.cast.events),
    )
    record = recording.record
    if scenes is not None:
        record = core.RunRecord(
            ash_version=record.ash_version,
            scanners=(),
            findings=(),
            reports=(),
            scenes=tuple(scenes),
        )
    return cast, record


def refuse(rc, recording, cast, record, match):
    with pytest.raises(rc.RenderError, match=match):
        rc.build_timeline(cast, record, recording.storyboard)


def test_a_marker_whose_words_differ_from_the_caption_is_refused(rc, core, recording):
    events = list(recording.cast.events)
    index = next(i for i, event in enumerate(events) if event.code == "m")
    events[index] = core.CastEvent(events[index].time, "m", "Other words")
    cast, record = altered(core, recording, events=events)
    refuse(rc, recording, cast, record, "caption")


def test_a_missing_marker_is_refused(rc, core, recording):
    events = list(recording.cast.events)
    markers = [index for index, event in enumerate(events) if event.code == "m"]
    del events[markers[-1]]
    cast, record = altered(core, recording, events=events)
    refuse(rc, recording, cast, record, "scene markers")


def test_a_marker_that_starts_at_another_time_than_the_storyboard_is_refused(
    rc, core, recording
):
    events = list(recording.cast.events)
    markers = [i for i, event in enumerate(events) if event.code == "m"]
    late = events[markers[1]]
    events[markers[1]] = core.CastEvent(late.time + 0.001, "m", late.data)
    # Keep the times in order: the events after it move by the same millisecond.
    for index in range(markers[1] + 1, len(events)):
        events[index] = core.CastEvent(
            events[index].time + 0.001, events[index].code, events[index].data
        )
    cast, record = altered(core, recording, events=events)
    refuse(rc, recording, cast, record, "starts at")


def test_a_cast_of_another_size_than_the_storyboard_terminal_is_refused(
    rc, core, recording
):
    header = core.CastHeader(width=41, height=8)
    cast, record = altered(core, recording, header=header)
    refuse(rc, recording, cast, record, "terminal")


def test_events_before_the_first_marker_are_refused(rc, core, recording):
    events = [core.CastEvent(0.0, "o", "stray")] + list(recording.cast.events)
    cast, record = altered(core, recording, events=events)
    refuse(rc, recording, cast, record, "before the first scene marker")


def test_a_record_that_lacks_a_scene_is_refused(rc, core, recording):
    cast, record = altered(core, recording, scenes=recording.record.scenes[:2])
    refuse(rc, recording, cast, record, "record")


def test_a_record_with_the_scenes_in_another_order_is_refused(rc, core, recording):
    scenes = list(reversed(recording.record.scenes))
    cast, record = altered(core, recording, scenes=scenes)
    refuse(rc, recording, cast, record, "record")


def test_a_record_whose_typed_count_differs_from_the_cast_is_refused(
    rc, core, recording
):
    scenes = list(recording.record.scenes)
    span = scenes[0].typing
    scenes[0] = core.SceneRecord(
        scene_id=scenes[0].scene_id,
        command=scenes[0].command,
        exit_code=0,
        end_screen=("done",),
        typing=core.TypingSpan(span.start_ms, span.end_ms, span.chars + 1),
    )
    cast, record = altered(core, recording, scenes=scenes)
    refuse(rc, recording, cast, record, "typed characters")


def test_a_record_whose_command_differs_from_what_the_cast_types_is_refused(
    rc, core, recording
):
    scenes = list(recording.record.scenes)
    scenes[0] = core.SceneRecord(
        scene_id=scenes[0].scene_id,
        command="ash --versioX",
        exit_code=0,
        end_screen=("done",),
        typing=scenes[0].typing,
    )
    cast, record = altered(core, recording, scenes=scenes)
    refuse(rc, recording, cast, record, "types")


def test_a_command_too_long_for_one_row_is_refused(rc, core):
    data = storyboard_data(cols=20)
    runs = mini_runs(core)
    runs["version"] = core.SceneRun("x" * 30, runs["version"].chunks)
    recording = build_recording(core, data, runs)
    refuse(rc, recording, recording.cast, recording.record, "one row")


# ---------------------------------------------------------------------------
# The SVG
# ---------------------------------------------------------------------------

SCHEME = re.compile(r"\s*[A-Za-z][A-Za-z0-9+.\-]*:")


def markup_problems(text: str) -> list[str]:
    """What makes an SVG unfit to serve under GitHub's CSP for repository images:
    a script, an event handler, a foreign element, a URL with a scheme in any
    attribute, or ``url(`` and ``@import`` in the stylesheet. Text a terminal showed
    may hold anything; only markup is read."""
    problems = []
    if "<script" in text.lower():
        problems.append("a script element")
    root = ET.fromstring(text)
    for element in root.iter():
        if not element.tag.startswith(SVG):
            problems.append(f"a foreign element {element.tag}")
        for name, value in element.attrib.items():
            if SCHEME.match(value):
                problems.append(f"{name} holds a URL with a scheme")
            if name.lower().startswith("on"):
                problems.append(f"the event handler {name}")
    for style in root.iter(SVG + "style"):
        if re.search(r"url\(|@import", style.text or "", re.IGNORECASE):
            problems.append("the stylesheet holds url( or @import")
    return problems


PLANTED_MARKUP = {
    "a script": '<svg xmlns="http://www.w3.org/2000/svg"><script>x()</script></svg>',
    "a scheme URL": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<use href="https://example.com/a.svg#x"/></svg>'
    ),
    "a stylesheet URL": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        "<style>.a{fill:url(https://example.com/x)}</style></svg>"
    ),
    "an event handler": '<svg xmlns="http://www.w3.org/2000/svg"><rect onload="x()"/></svg>',
    "a foreign element": (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:h="http://www.w3.org/1999/xhtml"><h:p/></svg>'
    ),
}


@pytest.mark.parametrize("name", sorted(PLANTED_MARKUP))
def test_the_markup_check_flags_each_planted_defect(name):
    assert markup_problems(PLANTED_MARKUP[name]) != []


def test_the_markup_check_passes_text_that_only_looks_like_markup():
    clean = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 9 9">'
        '<style>.a{fill:#fff}</style><use href="#r1"/>'
        "<text>&lt;script&gt; https://example.com url(x)</text></svg>"
    )
    assert markup_problems(clean) == []


class Rendered(NamedTuple):
    recording: Recording
    rendering: Any
    root: ET.Element
    css: str
    timeline: Any


def style_text(root: ET.Element) -> str:
    styles = list(root.iter(SVG + "style"))
    assert len(styles) == 1
    return styles[0].text or ""


def render_recording(rc, recording) -> Rendered:
    rendering = rc.render(recording.cast, recording.record, recording.storyboard)
    root = ET.fromstring(rendering.svg)
    timeline = rc.build_timeline(recording.cast, recording.record, recording.storyboard)
    return Rendered(recording, rendering, root, style_text(root), timeline)


@pytest.fixture
def rendered(rc, recording) -> Rendered:
    return render_recording(rc, recording)


def tokens(element: ET.Element) -> list[str]:
    return element.get("class", "").split()


def find_all(root: ET.Element, tag: str, token: str) -> list[ET.Element]:
    return [e for e in root.iter(SVG + tag) if token in tokens(e)]


def stored_rows(root: ET.Element) -> dict[str, ET.Element]:
    defs = root.find(SVG + "defs")
    assert defs is not None
    return {g.get("id"): g for g in defs if g.tag == SVG + "g"}


def row_string(row: ET.Element, cell_width: int, cols: int) -> str:
    """The text of a stored row, rebuilt from where each run says it starts."""
    cells = [" "] * cols
    for text in row.iter(SVG + "text"):
        column = int(text.get("x")) // cell_width
        last = None
        for char in text.text or "":
            width = cell_len(char)
            if width == 0:
                if last is not None:
                    cells[last] += char
                continue
            cells[column] = char
            last = column
            for extra in range(1, width):
                cells[column + extra] = ""
            column += width
    return "".join(cells).rstrip()


def frame_lines(frame: ET.Element, rows, rc, cols: int, height: int) -> list[str]:
    lines = [""] * height
    for use in frame.iter(SVG + "use"):
        index = int(use.get("y")) // rc.LINE_HEIGHT
        lines[index] = row_string(rows[use.get("href")[1:]], rc.CELL_WIDTH, cols)
    return trimmed(lines)


def frame_pitch(rc, rows: int) -> int:
    return rows * rc.LINE_HEIGHT + 2 * rc.PAD_Y


def percent(milliseconds: int, total: int) -> str:
    """A keyframe offset: integer arithmetic, four decimals, rounded half up."""
    micro = (milliseconds * 1_000_000 + total // 2) // total
    return f"{micro // 10_000}.{micro % 10_000:04d}"


def keyframes(css: str, name: str) -> list[tuple[str, str]]:
    match = re.search(
        r"@keyframes " + re.escape(name) + r"\{((?:[^{}]|\{[^{}]*\})*)\}", css
    )
    assert match is not None, f"no @keyframes {name}"
    return re.findall(r"([0-9.]+)%\{([^}]*)\}", match.group(1))


def translate(axis: str, offset: int) -> str:
    return f"transform:translate{axis}({offset or 0}px)"


def test_the_svg_is_an_accessible_image_of_the_size_the_terminal_gives(rc, rendered):
    root = rendered.root
    width = 40 * rc.CELL_WIDTH + 2 * rc.PAD_X
    height = rc.CHROME_HEIGHT + frame_pitch(rc, 8)
    assert root.tag == SVG + "svg"
    assert root.get("viewBox") == f"0 0 {width} {height}"
    assert root.get("role") == "img"
    title, desc = root.find(SVG + "title"), root.find(SVG + "desc")
    assert title is not None and desc is not None
    assert root.get("aria-labelledby") == f"{title.get('id')} {desc.get('id')}"
    for caption in ("Check the install", "Scan the project", "Read the findings"):
        assert caption in title.text
        assert caption in desc.text
    for command in ("ash --version", "ash --scanners bandit", "ash report"):
        assert command in desc.text


def test_one_stylesheet_holds_the_font_stack_and_no_font_file_or_url(rc, rendered):
    assert rc.FONT_STACK == (
        'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace'
    )
    assert rc.FONT_STACK in rendered.css
    for banned in ("@font-face", "@import", "url(", "src:"):
        assert banned not in rendered.css


def test_the_svg_and_the_poster_pass_the_markup_check(rendered):
    assert markup_problems(rendered.rendering.svg) == []
    assert markup_problems(rendered.rendering.poster) == []


def test_each_distinct_row_is_stored_once_and_numbered_by_first_appearance(rendered):
    root = rendered.root
    rows = stored_rows(root)
    uses = [use.get("href")[1:] for use in root.iter(SVG + "use")]
    assert list(rows) == [f"r{index}" for index in range(len(rows))]
    # Every stored row is used, every use resolves, and rows are numbered in the order
    # the frames first show them.
    assert list(dict.fromkeys(uses)) == list(rows)
    # Rows repeat between frames; the markup does not.
    assert len(uses) > len(rows)
    bodies = [
        re.sub(r' id="r\d+"', "", ET.tostring(g, encoding="unicode"))
        for g in rows.values()
    ]
    assert len(set(bodies)) == len(rows)


def test_the_frames_are_stacked_in_one_strip_and_read_back_as_their_screens(
    rc, rendered
):
    root = rendered.root
    strips = find_all(root, "g", "s")
    assert len(strips) == 1
    frames = [g for g in strips[0] if g.tag == SVG + "g"]
    assert len(frames) == rendered.rendering.frames == len(rendered.timeline.frames)
    rows = stored_rows(root)
    pitch = frame_pitch(rc, 8)
    for index, (frame, expected) in enumerate(
        zip(frames, rendered.timeline.frames, strict=True)
    ):
        assert (
            frame.get("transform")
            == f"translate({rc.PAD_X} {index * pitch + rc.PAD_Y})"
        )
        assert frame_lines(frame, rows, rc, 40, 8) == expected.screen.lines()
    # One viewport the size of one frame clips the strip.
    viewports = [e for e in root.iter(SVG + "svg") if strips[0] in list(e)]
    assert len(viewports) == 1
    assert viewports[0].get("y") == str(rc.CHROME_HEIGHT)
    assert viewports[0].get("height") == str(pitch)


def test_every_text_run_is_pinned_to_the_grid(rc, rendered):
    runs = [
        text
        for row in stored_rows(rendered.root).values()
        for text in row.iter(SVG + "text")
    ]
    assert len(runs) > 8
    for text in runs:
        assert text.get("lengthAdjust") == "spacingAndGlyphs"
        assert int(text.get("x")) % rc.CELL_WIDTH == 0
        assert int(text.get("textLength")) == cell_len(text.text) * rc.CELL_WIDTH


def test_the_strip_steps_between_frames_at_each_frames_time_and_ends_on_the_poster(
    rc, rendered
):
    frames = rendered.timeline.frames
    total = rendered.recording.storyboard.total_ms
    pitch = frame_pitch(rc, 8)
    entries = keyframes(rendered.css, "s")
    # playback "once": one entry per frame, then the cut back to the poster.
    assert len(entries) == len(frames) + 1
    for index, frame in enumerate(frames):
        assert entries[index] == (
            percent(frame.time_ms, total),
            translate("Y", -index * pitch),
        )
    poster = rendered.timeline.poster_frame
    assert entries[-1] == ("100.0000", translate("Y", -poster * pitch))
    assert entries[0][0] == "0.0000"
    assert rendered.rendering.poster_frame == poster
    css = rendered.css
    assert re.search(r"\.a\{[^}]*animation-timing-function:step-end", css)
    assert f"animation-duration:{total}ms" in css
    assert "animation-iteration-count:1" in css
    assert "animation-fill-mode:forwards" in css
    strip = find_all(rendered.root, "g", "s")[0]
    assert "a" in tokens(strip)
    # The attribute is the poster; the animation overrides it while it runs.
    offset = -poster * pitch
    assert strip.get("transform") == f"translate(0 {offset or 0})"


def test_reduced_motion_turns_the_animation_off_and_leaves_the_poster(rendered):
    assert re.search(
        r"@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{\s*\.a\s*\{\s*animation:\s*none",
        rendered.css,
    )


def test_playback_loop_repeats_forever_and_never_cuts_back(rc, core):
    recording = build_recording(core, storyboard_data(playback="loop"))
    rendered = render_recording(rc, recording)
    entries = keyframes(rendered.css, "s")
    assert len(entries) == len(rendered.timeline.frames)
    assert entries[-1][0] != "100.0000"
    assert "animation-iteration-count:infinite" in rendered.css
    assert "animation-iteration-count:1" not in rendered.css


def test_the_window_title_shows_the_caption_of_the_scene_that_is_playing(rc, rendered):
    storyboard = rendered.recording.storyboard
    strips = find_all(rendered.root, "g", "k")
    assert len(strips) == 1
    captions = [text.text for text in strips[0].iter(SVG + "text")]
    assert captions == [scene.caption for scene in storyboard.scenes]
    entries = keyframes(rendered.css, "k")
    total = storyboard.total_ms
    for index, scene in enumerate(storyboard.scenes):
        assert entries[index] == (
            percent(scene.start_ms, total),
            translate("Y", -index * rc.CHROME_HEIGHT),
        )
    # playback "once" rests on the poster scene's caption, as the poster does.
    poster_scene = storyboard.scenes.index(storyboard.scene(storyboard.poster_scene))
    assert entries[-1] == (
        "100.0000",
        translate("Y", -poster_scene * rc.CHROME_HEIGHT),
    )


def test_a_typed_command_is_uncovered_by_a_step_clip_over_one_frame(rc, rendered):
    root = rendered.root
    strips = find_all(root, "g", "s")
    frames = [g for g in strips[0] if g.tag == SVG + "g"]
    covers = find_all(root, "rect", "v")
    assert len(covers) == len(rendered.timeline.reveals) == 3
    total = rendered.recording.storyboard.total_ms
    for number, (cover, reveal) in enumerate(
        zip(covers, rendered.timeline.reveals, strict=True)
    ):
        assert cover in list(frames[reveal.frame])
        assert int(cover.get("x")) == reveal.col * rc.CELL_WIDTH
        assert int(cover.get("y")) == reveal.row * rc.LINE_HEIGHT
        assert int(cover.get("width")) == reveal.chars * rc.CELL_WIDTH
        assert int(cover.get("height")) == rc.LINE_HEIGHT
        assert f"t{number}" in tokens(cover)
        entries = dict(keyframes(rendered.css, f"t{number}"))
        start = entries[percent(reveal.start_ms, total)]
        end = entries[percent(reveal.end_ms, total)]
        # The first character shows at the start of the span, one more at each step.
        assert start == (
            f"transform:translateX(0px);"
            f"animation-timing-function:steps({reveal.chars},jump-start)"
        )
        assert end == f"transform:translateX({reveal.chars * rc.CELL_WIDTH}px)"


def test_the_poster_is_the_frame_the_storyboard_names(rc, core):
    recording = build_recording(core)
    rendered = render_recording(rc, recording)
    poster = ET.fromstring(rendered.rendering.poster)
    ends = scene_end_screens(rc, recording.cast)
    expected = ends[1].lines()  # poster_scene is "scan"
    assert expected == ["$ ash --scanners bandit", "PASSED bandit"]
    uses = list(poster.iter(SVG + "use"))
    lines = [""] * 8
    rows = stored_rows(poster)
    for use in uses:
        lines[int(use.get("y")) // rc.LINE_HEIGHT] = row_string(
            rows[use.get("href")[1:]], rc.CELL_WIDTH, 40
        )
    assert trimmed(lines) == expected
    # The animated strip's resting frame holds the same screen.
    strip = find_all(rendered.root, "g", "s")[0]
    frames = [g for g in strip if g.tag == SVG + "g"]
    animated = frame_lines(
        frames[rendered.timeline.poster_frame], stored_rows(rendered.root), rc, 40, 8
    )
    assert animated == expected
    assert [
        text.text for text in poster.iter(SVG + "text") if "cap" in tokens(text)
    ] == ["Scan the project"]


def test_the_poster_is_static(rendered):
    poster = ET.fromstring(rendered.rendering.poster)
    css = style_text(poster)
    assert "@keyframes" not in css
    assert "animation" not in css
    assert not find_all(poster, "g", "s")
    assert not find_all(poster, "g", "k")
    assert not find_all(poster, "rect", "v")
    assert poster.get("role") == "img"
    assert poster.find(SVG + "title") is not None
    assert poster.find(SVG + "desc") is not None
    assert poster.get("viewBox") == rendered.root.get("viewBox")


# ---------------------------------------------------------------------------
# What the cells look like, and what output cannot do to the markup
# ---------------------------------------------------------------------------


def recording_with_output(core, text: str, *, cols: int = 40, rows: int = 8):
    """The small recording with the scan scene's output replaced by ``text``."""
    runs = mini_runs(core)
    runs["scan"] = core.SceneRun("ash scan", (core.RawChunk(0.10, text),))
    return build_recording(core, storyboard_data(cols=cols, rows=rows), runs)


def assert_frames_read_back(rc, rendered, cols: int = 40, rows: int = 8) -> None:
    strip = find_all(rendered.root, "g", "s")[0]
    frames = [g for g in strip if g.tag == SVG + "g"]
    stored = stored_rows(rendered.root)
    assert len(frames) == len(rendered.timeline.frames)
    for frame, expected in zip(frames, rendered.timeline.frames, strict=True):
        assert frame_lines(frame, stored, rc, cols, rows) == expected.screen.lines()


STYLED = (
    f"{ESC}[1;31mBOLDRED{ESC}[0m {ESC}[3mITAL{ESC}[0m {ESC}[4mUND{ESC}[0m "
    f"{ESC}[2mDIM{ESC}[0m\r\n"
    f"{ESC}[7mREV{ESC}[0m {ESC}[44mONBLUE{ESC}[0m {ESC}[38;2;255;136;0mORANGE{ESC}[0m "
    f"{ESC}[38;5;202mIDX{ESC}[0m\r\n"
)


def test_styles_reach_the_svg_as_classes_colors_and_blocks(rc, core):
    rendered = render_recording(rc, recording_with_output(core, STYLED))
    theme = rc.terminal_theme()
    root = rendered.root
    texts = {t.text: t for t in root.iter(SVG + "text") if t.text}
    colors = dict(re.findall(r"\.(c\d+)\{fill:(#[0-9a-f]{6})\}", rendered.css))
    parents = {child: parent for parent in root.iter() for child in parent}

    def fill(element):
        found = [colors[token] for token in tokens(element) if token in colors]
        return found[0] if found else None

    def blocks_behind(element):
        return [
            rect
            for rect in parents[element].iter(SVG + "rect")
            if rect.get("x") == element.get("x")
        ]

    assert "b" in tokens(texts["BOLDRED"])
    assert fill(texts["BOLDRED"]) == theme.palette[1]
    assert "i" in tokens(texts["ITAL"])
    assert "u" in tokens(texts["UND"])
    assert "d" in tokens(texts["DIM"])
    # The default foreground is the stylesheet's own; no class names it.
    assert fill(texts["ITAL"]) is None
    assert fill(texts["ORANGE"]) == "#ff8800"
    # Index 202 of the xterm cube is red 5, green 1, blue 0: #ff5f00.
    assert fill(texts["IDX"]) == "#ff5f00"
    # Reverse video swaps the two defaults and puts a block behind the text.
    assert fill(texts["REV"]) == theme.bg
    (block,) = blocks_behind(texts["REV"])
    assert fill(block) == theme.fg
    assert int(block.get("width")) == 3 * rc.CELL_WIDTH
    (block,) = blocks_behind(texts["ONBLUE"])
    assert fill(block) == theme.palette[4]
    assert int(block.get("width")) == 6 * rc.CELL_WIDTH
    assert blocks_behind(texts["ITAL"]) == []
    assert_frames_read_back(rc, rendered)


def test_the_256_color_cube_and_the_gray_ramp_follow_xterm(rc, core):
    text = (
        f"{ESC}[38;5;16mA{ESC}[38;5;231mB{ESC}[38;5;232mC{ESC}[38;5;255mD{ESC}[0m\r\n"
    )
    rendered = render_recording(rc, recording_with_output(core, text))
    colors = dict(re.findall(r"\.(c\d+)\{fill:(#[0-9a-f]{6})\}", rendered.css))
    root = rendered.root
    texts = {t.text: t for t in root.iter(SVG + "text") if t.text}
    seen = {
        letter: colors[next(t for t in tokens(texts[letter]) if t in colors)]
        for letter in "ABCD"
    }
    assert seen == {"A": "#000000", "B": "#ffffff", "C": "#080808", "D": "#eeeeee"}


def test_wide_characters_get_a_run_of_their_own_two_cells_wide(rc, core):
    text = f"ab{CJK}cd {BAR_CHART}x\r\n"
    rendered = render_recording(rc, recording_with_output(core, text))
    texts = [t for t in rendered.root.iter(SVG + "text") if t.text]
    wide = [t for t in texts if t.text in (CJK, BAR_CHART)]
    assert [int(t.get("textLength")) for t in wide] == [2 * rc.CELL_WIDTH] * 2
    assert {"ab", "cd", "x"} <= {t.text for t in texts}
    assert_frames_read_back(rc, rendered)


def test_terminal_output_cannot_become_markup(rc, core):
    hostile = '<script>alert(1)</script> & "q" </text><rect id="x"/>\r\n'
    rendered = render_recording(rc, recording_with_output(core, hostile, cols=60))
    svg = rendered.rendering.svg
    assert "<script" not in svg.lower()
    assert "&lt;script&gt;" in svg
    assert markup_problems(svg) == []
    assert markup_problems(rendered.rendering.poster) == []
    assert not any(element.get("id") == "x" for element in rendered.root.iter())
    # The text itself is not lost: it is on screen as typed.
    assert_frames_read_back(rc, rendered, cols=60)
    assert any(
        hostile.strip() in line
        for frame in rendered.timeline.frames
        for line in frame.screen.lines()
    )


def test_output_that_prints_a_url_is_text_and_passes_the_markup_check(rc, core):
    text = "see https://example.com/page and url(x) @import\r\n"
    rendered = render_recording(rc, recording_with_output(core, text, cols=60))
    assert markup_problems(rendered.rendering.svg) == []
    assert "https://example.com/page" in rendered.rendering.svg


def test_captions_with_markup_characters_are_escaped_in_every_place(rc, core):
    data = storyboard_data()
    data["scenes"][1]["caption"] = "Scan <fast> & safe"
    rendered = render_recording(rc, build_recording(core, data))
    assert "Scan &lt;fast&gt; &amp; safe" in rendered.rendering.svg
    assert "Scan <fast> & safe" in rendered.root.find(SVG + "title").text
    assert markup_problems(rendered.rendering.svg) == []
    assert markup_problems(rendered.rendering.poster) == []


# ---------------------------------------------------------------------------
# The palette
# ---------------------------------------------------------------------------


def test_the_terminal_theme_is_the_design_system_palette_with_a_fixed_rest(rc, core):
    theme = rc.terminal_theme()
    assert isinstance(theme, core.CastTheme)
    assert (theme.fg, theme.bg) == (COLORS["foreground"], COLORS["background"])
    assert len(theme.palette) == 16
    assert [theme.palette[index] for index in (1, 2, 3, 4)] == [
        COLORS[name] for name in ("error", "success", "warning", "accent")
    ]
    assert len(set(theme.palette)) == 16


def test_a_change_to_the_design_system_palette_reaches_the_svg(rc, core, monkeypatch):
    monkeypatch.setitem(COLORS, "error", "#123456")
    monkeypatch.setitem(COLORS, "background", "#0a0b0c")
    rendered = render_recording(
        rc, recording_with_output(core, f"{ESC}[31mRED{ESC}[0m\r\n")
    )
    assert "#123456" in rendered.css
    assert "#0a0b0c" in rendered.css
    assert "#ff7a7a" not in rendered.css


# ---------------------------------------------------------------------------
# Size
# ---------------------------------------------------------------------------


def live_refresh_chunks(count: int, height: int = 26, width: int = 100) -> list[str]:
    """What each refresh of a Layout in a Live writes: one chunk per refresh."""
    buffer = io.StringIO()
    console = terminal_console(buffer, width=width, height=height)
    chunks: list[str] = []
    mark = 0
    log: list[str] = []
    with Live(
        console=console,
        auto_refresh=False,
        redirect_stdout=False,
        redirect_stderr=False,
        screen=False,
        vertical_overflow="visible",
    ) as live:
        for step in range(count):
            log = [*log, f"scanner {step}: [green]ok[/green] [dim]{step * 7}[/dim]"][
                -12:
            ]
            live.update(make_layout(log, step * 100 // count), refresh=True)
            data = buffer.getvalue()
            chunks.append(data[mark:])
            mark = len(data)
    chunks.append(buffer.getvalue()[mark:])
    return [to_pty(chunk) for chunk in chunks]


def busy_recording(core, refreshes: int = 40) -> Recording:
    chunks = live_refresh_chunks(refreshes)
    runs = mini_runs(core)
    runs["scan"] = core.SceneRun(
        "ash scan",
        tuple(
            core.RawChunk(0.1 * (index + 1), chunk)
            for index, chunk in enumerate(chunks)
        ),
    )
    return build_recording(core, storyboard_data(cols=100, rows=30), runs)


def test_a_busy_live_recording_stays_under_the_size_ceiling(rc, core, record_property):
    recording = busy_recording(core)
    rendering = rc.render(recording.cast, recording.record, recording.storyboard)
    size = len(rendering.svg.encode("utf-8"))
    record_property("svg_bytes", size)
    record_property("frames", rendering.frames)
    assert rendering.frames >= 40
    assert size < rc.MAX_SVG_BYTES
    assert markup_problems(rendering.svg) == []


def test_an_svg_over_the_ceiling_is_refused_and_one_at_it_is_not(rc, recording):
    args = (recording.cast, recording.record, recording.storyboard)
    size = len(rc.render(*args).svg.encode("utf-8"))
    assert len(rc.render(*args, max_bytes=size).svg.encode("utf-8")) == size
    with pytest.raises(rc.RenderError, match="ceiling"):
        rc.render(*args, max_bytes=size - 1)


def test_the_frame_cap_reaches_the_svg(rc, recording):
    rendering = rc.render(
        recording.cast, recording.record, recording.storyboard, max_frames=7
    )
    root = ET.fromstring(rendering.svg)
    strip = find_all(root, "g", "s")[0]
    assert rendering.frames == 7
    assert len([g for g in strip if g.tag == SVG + "g"]) == 7
    assert len(keyframes(style_text(root), "s")) == 7 + 1


def test_the_default_frame_cap_is_360(rc):
    assert rc.MAX_FRAMES == 360
    assert rc.MERGE_MS == 50
    assert rc.MAX_SVG_BYTES == 512 * 1024


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def write_inputs(
    core, recording, directory: Path, data: dict | None = None
) -> dict[str, Path]:
    paths = {
        "cast": directory / "demo.cast",
        "record": directory / "demo.record.json",
        "storyboard": directory / "demo.cast.yaml",
        "svg": directory / "out" / "demo.svg",
        "poster": directory / "out" / "demo-poster.svg",
    }
    core.write_cast(paths["cast"], recording.cast)
    core.write_record(paths["record"], recording.record)
    paths["storyboard"].write_text(
        yaml.safe_dump(data or storyboard_data(), sort_keys=False), encoding="utf-8"
    )
    return paths


def cli_args(paths: dict[str, Path], *extra: str) -> list[str]:
    return [
        *extra,
        "--cast",
        str(paths["cast"]),
        "--record",
        str(paths["record"]),
        "--storyboard",
        str(paths["storyboard"]),
        "--svg",
        str(paths["svg"]),
        "--poster",
        str(paths["poster"]),
    ]


def test_the_command_line_writes_both_files_and_check_accepts_them(
    rc, core, recording, tmp_path, capsys
):
    paths = write_inputs(core, recording, tmp_path)
    assert rc.main(cli_args(paths)) == 0
    rendering = rc.render(recording.cast, recording.record, recording.storyboard)
    assert paths["svg"].read_bytes() == rendering.svg.encode("utf-8")
    assert paths["poster"].read_bytes() == rendering.poster.encode("utf-8")
    for path in (paths["svg"], paths["poster"]):
        data = path.read_bytes()
        assert b"\r" not in data
        assert data.endswith(b"\n") and not data.endswith(b"\n\n")
    capsys.readouterr()
    assert rc.main(cli_args(paths, "--check")) == 0
    assert "is up to date" in capsys.readouterr().err


def test_check_fails_with_a_diff_on_a_changed_byte_and_writes_nothing(
    rc, core, recording, tmp_path, capsys
):
    paths = write_inputs(core, recording, tmp_path)
    assert rc.main(cli_args(paths)) == 0
    text = paths["svg"].read_text(encoding="utf-8")
    assert "0.0000%" in text
    stale = text.replace("0.0000%", "0.0001%", 1)
    paths["svg"].write_text(stale, encoding="utf-8", newline="\n")
    capsys.readouterr()
    assert rc.main(cli_args(paths, "--check")) == 1
    err = capsys.readouterr().err
    assert "is stale" in err
    assert "(on disk)" in err and "(regenerated)" in err
    assert paths["svg"].read_text(encoding="utf-8") == stale
    # Writing repairs it, and then check agrees.
    assert rc.main(cli_args(paths)) == 0
    assert rc.main(cli_args(paths, "--check")) == 0


def test_check_fails_when_an_output_file_is_missing_and_creates_nothing(
    rc, core, recording, tmp_path
):
    paths = write_inputs(core, recording, tmp_path)
    assert rc.main(cli_args(paths, "--check")) == 1
    assert not paths["svg"].exists()
    assert not paths["poster"].exists()


def test_a_missing_input_exits_2_and_names_the_file(
    rc, core, recording, tmp_path, capsys
):
    paths = write_inputs(core, recording, tmp_path)
    paths["cast"] = tmp_path / "nope.cast"
    assert rc.main(cli_args(paths)) == 2
    assert "nope.cast" in capsys.readouterr().err
    assert not paths["svg"].exists()


def test_an_input_the_renderer_refuses_exits_2_with_the_sequence_and_writes_nothing(
    rc, core, recording, tmp_path, capsys
):
    events = list(recording.cast.events)
    last = events[-1]
    events.append(core.CastEvent(last.time, "o", ESC + "[?2026h"))
    cast = core.Cast(header=recording.cast.header, events=tuple(events))
    paths = write_inputs(core, recording, tmp_path)
    core.write_cast(paths["cast"], cast)
    assert rc.main(cli_args(paths)) == 2
    assert "\\x1b[?2026h" in capsys.readouterr().err
    assert not paths["svg"].exists()
    assert rc.main(cli_args(paths, "--check")) == 2


def test_the_default_paths_are_the_ones_the_recording_is_committed_under(
    rc, core, recording, tmp_path
):
    cast_dir = tmp_path / "docs" / "content" / "assets" / "images" / "cast"
    journeys = tmp_path / "docs" / "journeys"
    cast_dir.mkdir(parents=True)
    journeys.mkdir(parents=True)
    core.write_cast(cast_dir / "quick-start.cast", recording.cast)
    core.write_record(cast_dir / "quick-start.record.json", recording.record)
    (journeys / "getting-started-local.cast.yaml").write_text(
        yaml.safe_dump(storyboard_data(), sort_keys=False), encoding="utf-8"
    )
    assert rc.main(["--docs-root", str(tmp_path)]) == 0
    assert (cast_dir / "quick-start.svg").is_file()
    assert (cast_dir / "quick-start-poster.svg").is_file()
    assert rc.main(["--docs-root", str(tmp_path), "--check"]) == 0


def run_cli(args: list[str], seed: str, cwd: Path) -> subprocess.CompletedProcess:
    """The command line in a fresh interpreter, with the hash seed the test sets."""
    env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(
        [sys.executable, "-B", str(MODULE), *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        timeout=300,
    )


def test_the_svg_and_the_poster_are_byte_identical_under_two_hash_seeds(
    rc, core, tmp_path
):
    # Many colors, so that an order taken from a set would differ between seeds.
    palette = "".join(
        f"{ESC}[38;2;{20 * index};{255 - 20 * index};{index}mw{index}{ESC}[0m "
        for index in range(1, 12)
    )
    recording = recording_with_output(core, palette + "\r\n", cols=60)
    results = {}
    for seed in ("1", "4242"):
        directory = tmp_path / f"seed-{seed}"
        directory.mkdir()
        paths = write_inputs(core, recording, directory, storyboard_data(cols=60))
        done = run_cli(cli_args(paths), seed, tmp_path)
        assert done.returncode == 0, done.stderr
        results[seed] = (paths["svg"].read_bytes(), paths["poster"].read_bytes())
    assert results["1"] == results["4242"]
    # The child's bytes are the in-process render's: the command line adds nothing.
    rendering = rc.render(recording.cast, recording.record, recording.storyboard)
    assert results["1"] == (
        rendering.svg.encode("utf-8"),
        rendering.poster.encode("utf-8"),
    )
    assert len(results["1"][0]) > 1000


def test_rendering_twice_in_one_process_gives_the_same_text(rc, recording):
    args = (recording.cast, recording.record, recording.storyboard)
    first, second = rc.render(*args), rc.render(*args)
    assert first == second
