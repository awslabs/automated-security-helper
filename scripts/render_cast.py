"""Terminal emulator and SVG renderer for the quick-start recording.

The recording is an asciicast, a run record and a storyboard (see ``scripts/_cast.py``).
This script turns them into two images that need no player and no script: an animated
SVG that plays the recording once, and a still poster of the screen the storyboard names
with ``poster_scene``. The output is a pure function of its three inputs, so it is the
same on every machine, under every hash seed, and ``--check`` can compare it byte for
byte with what is committed. Nothing here touches a terminal: the module imports no
``pty``, ``termios`` or ``fcntl``, and runs, and is tested, on every platform.

What it holds
-------------
* the emulator: ``Emulator`` reads the output a program wrote to a terminal and keeps
  the screen it made. It knows the subset Rich and a shell print: text with deferred
  wrap at the last column (an exact-width line followed by CR LF adds no blank row),
  CR, LF, BS and TAB, scrolling at the bottom row, the cursor moves CUU, CUD, CUF, CUB,
  CNL, CPL, CHA and CUP, the erases ED and EL, SGR in 16 colors, 256 colors and true
  color with bold, dim, italic, underline and reverse, cursor show and hide (``?25``),
  OSC titles (ignored) and OSC 8 links (the text shows, the link does not). Cell widths
  come from ``rich.cells``: a wide character takes two columns, and a combining mark or
  a variation selector joins the cell before it. Any other sequence is refused with its
  bytes named, so a new feature in ASH's output fails loudly instead of rendering wrong.
  A recorder that scrubs a recording reads the same screens: ``emulated_screens``.
* the timeline: ``build_timeline`` follows the recording scene by scene. Output events
  closer than 50 ms merge into one frame. A typed command is one frame, the screen with
  the whole command on its row, and a reveal that says when each character shows; the
  SVG uncovers the row in as many steps as there are characters. A deterministic
  decimation caps the frames at 360 and never drops a typing frame or the last frame of
  a scene. The poster is the last frame of the scene ``poster_scene`` names.
* the images: ``render`` writes the SVG and the poster. Both are sized to what GitHub
  serves for a repository image: one stylesheet and nothing else that loads, no script,
  no font file, no URL with a scheme. Each distinct row of text is stored once in
  ``<defs>`` and each frame is a group of ``<use>`` references to rows. All the frames
  sit in one strip behind a viewport, and one ``@keyframes`` rule steps the strip from
  frame to frame at each frame's time. Every text run carries ``textLength`` and
  ``lengthAdjust="spacingAndGlyphs"``, so the grid holds in any monospace font. The
  window title shows the caption of the scene that is playing. The strip's own
  ``transform`` attribute is the poster: a browser that runs no animation, or a reader
  who asked for reduced motion, sees the end of the scan, not an empty first frame.
  The image draws no cursor.
* the command line: ``--check`` goes through ``write_or_check`` like every reference
  generator, and exits 1 with a diff when a committed image is stale. An input the
  renderer refuses exits 2 with the reason.

Palette
-------
The default colors and the four ANSI colors Rich uses most come from the design system
(``automated_security_helper.utils.ui_theme.COLORS``), read each time, so a change to
that palette reaches the images. The other twelve of the sixteen are fixed here.
``terminal_theme`` gives the same palette as the ``theme`` header of the recording.

Determinism
-----------
Rows are numbered by first appearance, color classes by sorted color, keyframe offsets
are written with integer arithmetic to four decimals, and no set or hash order reaches
the output. Files are written with Unix newlines.
"""

from __future__ import annotations

import argparse
import dataclasses
import heapq
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import NamedTuple, NoReturn
from xml.sax.saxutils import escape as _escape_text

from rich.cells import cell_len, get_character_cell_size

_SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPTS))
try:
    from _cast import (
        Cast,
        CastError,
        CastTheme,
        RunRecord,
        Storyboard,
        load_storyboard,
        read_cast,
        read_record,
    )
    from _reference_docs import add_docs_root_argument, write_or_check
finally:
    sys.path.remove(str(_SCRIPTS))

GENERATOR = "scripts/render_cast.py"

#: Where a docs tree keeps the recording and its storyboard.
CAST_DIR = Path("docs") / "content" / "assets" / "images" / "cast"
RECORDING_NAME = "quick-start"
STORYBOARD_PATH = Path("docs") / "journeys" / "getting-started-local.cast.yaml"

#: Geometry, in SVG user units (one unit is one pixel at the image's own size).
CELL_WIDTH = 9
LINE_HEIGHT = 18
PAD_X = 12
PAD_Y = 10
CHROME_HEIGHT = 36
FONT_SIZE = 15
CAPTION_SIZE = 13
#: Where the text baseline sits inside a row of ``LINE_HEIGHT``.
BASELINE = 14
#: The window title's baseline inside the title bar.
CAPTION_BASELINE = 23

#: Output events less than this many milliseconds after the first event of a frame
#: belong to that frame.
MERGE_MS = 50
#: The most frames an animation holds; the decimation drops down to it.
MAX_FRAMES = 360
#: The largest SVG, in bytes. GitHub serves a repository image under a content
#: security policy and a reader loads the whole file; a larger file is refused.
MAX_SVG_BYTES = 512 * 1024

TAB_WIDTH = 8
#: Longer than any control sequence the subset holds; a longer one is refused.
MAX_CSI_LENGTH = 64
MAX_OSC_LENGTH = 4096

FONT_STACK = 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace'
CAPTION_FONT_STACK = (
    'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif'
)

#: The twelve ANSI colors the design system does not name: black and the four bright
#: ones are lifted so they read on its dark background. Indexes follow xterm's order.
_FIXED_PALETTE = {
    0: "#2b3240",
    5: "#c792ea",
    6: "#4dd0e1",
    7: "#c6c6cd",
    8: "#6b7280",
    9: "#ff9a9a",
    10: "#5fd068",
    11: "#fff08a",
    12: "#7cc8ff",
    13: "#dcb3f5",
    14: "#7fe3ee",
    15: "#ffffff",
}
#: Levels of the 6x6x6 color cube (indexes 16 to 231), as xterm draws them.
_CUBE_LEVELS = (0, 95, 135, 175, 215, 255)

_ESC = "\x1b"
_ZWJ = chr(0x200D)


class RenderError(CastError):
    """Every refusal this module makes; the message names what it refused."""


class UnsupportedSequence(RenderError):
    """The output holds a sequence, a control or a character outside the subset.

    ``sequence`` is the text that was refused, as it was read.
    """

    def __init__(self, sequence: str, reason: str = "") -> None:
        self.sequence = sequence
        shown = repr(sequence) if len(sequence) <= 80 else repr(sequence[:77]) + "..."
        detail = f": {reason}" if reason else ""
        super().__init__(f"unsupported terminal sequence {shown}{detail}")


# ---------------------------------------------------------------------------
# Cells and screens
# ---------------------------------------------------------------------------

#: A color is None (the default), an index 0 to 255 into the 256-color palette, or an
#: (r, g, b) triple.
Color = int | tuple[int, int, int] | None


@dataclasses.dataclass(frozen=True, slots=True)
class Style:
    """What SGR sets for the cells written after it."""

    fg: Color = None
    bg: Color = None
    bold: bool = False
    dim: bool = False
    italic: bool = False
    underline: bool = False
    reverse: bool = False


class Cell(NamedTuple):
    """One cell: the text it starts and its style.

    ``text`` is a character or a cluster (a base with combining marks). A wide
    character's first cell holds it, and the cell to its right holds ``""``.
    """

    text: str
    style: Style


BLANK = Cell(" ", Style())


@dataclasses.dataclass(frozen=True)
class Screen:
    """An immutable snapshot of the emulated screen.

    Rows are tuples of cells and are shared between snapshots when nothing changed in
    them, so a long recording holds each distinct row once.
    """

    rows: tuple[tuple[Cell, ...], ...]
    cursor_row: int
    cursor_col: int
    cursor_visible: bool

    def row_text(self, index: int) -> str:
        """The text of one row as written, with no right strip."""
        return "".join(cell.text for cell in self.rows[index])

    def lines(self) -> list[str]:
        """The rows as text: each right-stripped, the blank rows at the bottom dropped."""
        lines = [self.row_text(index).rstrip() for index in range(len(self.rows))]
        while lines and not lines[-1]:
            lines.pop()
        return lines

    def text(self) -> str:
        return "\n".join(self.lines())


def _drawable(char: str) -> bool:
    """A printable character that an XML document can hold."""
    code = ord(char)
    if code < 0x20 or 0x7F <= code <= 0x9F:
        return False
    return not (0xD800 <= code <= 0xDFFF or code in (0xFFFE, 0xFFFF))


# ---------------------------------------------------------------------------
# The emulator
# ---------------------------------------------------------------------------

_GROUND, _ESCAPE, _CSI, _OSC, _OSC_ESCAPE = range(5)
_PRIVATE_MARKERS = "<=>?"
_INTERMEDIATES = " !\"#$%&'()*+,-./"


class Emulator:
    """A terminal screen of ``cols`` by ``rows`` cells, fed the text a program wrote.

    ``feed`` takes text in pieces of any size: a sequence may be split between two
    calls. ``screen`` snapshots the grid. A sequence outside the subset raises
    ``UnsupportedSequence``; the emulator is then back at the start of a sequence and
    can go on, but what it showed since the last good call is not to be trusted.
    """

    def __init__(self, cols: int, rows: int) -> None:
        if cols < 2 or rows < 1:
            raise RenderError(
                f"a terminal needs at least 2 columns and 1 row, not {cols}x{rows}"
            )
        self.cols = cols
        self.rows = rows
        self._grid: list[list[Cell]] = [[BLANK] * cols for _ in range(rows)]
        self._frozen: list[tuple[Cell, ...] | None] = [None] * rows
        self._row = 0
        self._col = 0
        #: Set when a character filled the last column: the next one wraps first.
        self._pending = False
        self._style = Style()
        self._visible = True
        self._state = _GROUND
        self._buffer: list[str] = []
        #: Row, column and width of the cluster written last, which a combining mark
        #: joins; any control or sequence ends it.
        self._cluster: tuple[int, int, int] | None = None
        self._joining = False

    # -- reading ----------------------------------------------------------------

    @property
    def pending_sequence(self) -> str:
        """The part of a sequence fed so far, or ``""`` between sequences."""
        return "".join(self._buffer) if self._state != _GROUND else ""

    def screen(self) -> Screen:
        rows = []
        for index, frozen in enumerate(self._frozen):
            if frozen is None:
                frozen = tuple(self._grid[index])
                self._frozen[index] = frozen
            rows.append(frozen)
        return Screen(tuple(rows), self._row, self._col, self._visible)

    # -- feeding ----------------------------------------------------------------

    def feed(self, data: str) -> None:
        for char in data:
            state = self._state
            if state == _GROUND:
                self._ground(char)
            elif state == _ESCAPE:
                self._escape(char)
            elif state == _CSI:
                self._csi(char)
            else:
                self._osc(char)

    def _refuse(self, sequence: str, reason: str) -> NoReturn:
        self._state = _GROUND
        self._buffer = []
        self._detach()
        raise UnsupportedSequence(sequence, reason)

    def _detach(self) -> None:
        self._cluster = None
        self._joining = False

    # -- the ground state -------------------------------------------------------

    def _ground(self, char: str) -> None:
        if char == _ESC:
            self._buffer = [char]
            self._state = _ESCAPE
        elif ord(char) < 0x20:
            self._control(char)
        elif not _drawable(char):
            self._refuse(char, "this character cannot be shown")
        else:
            self._print(char)

    def _control(self, char: str) -> None:
        if char == "\r":
            self._col = 0
            self._pending = False
        elif char == "\n":
            self._line_feed()
        elif char == "\b":
            self._col = max(self._col - 1, 0)
            self._pending = False
        elif char == "\t":
            self._col = min((self._col // TAB_WIDTH + 1) * TAB_WIDTH, self.cols - 1)
            self._pending = False
        else:
            self._refuse(char, "a control character outside the subset")
        self._detach()

    def _line_feed(self) -> None:
        self._pending = False
        if self._row == self.rows - 1:
            del self._grid[0]
            self._grid.append([BLANK] * self.cols)
            del self._frozen[0]
            self._frozen.append(None)
        else:
            self._row += 1

    def _wrap(self) -> None:
        self._col = 0
        self._line_feed()

    def _blank(self) -> Cell:
        """What an erase leaves: a space with the current background and nothing else."""
        bg = self._style.bg
        return BLANK if bg is None else Cell(" ", Style(bg=bg))

    def _clear_halves(self, cells: list[Cell], col: int, width: int) -> None:
        """Before ``width`` cells from ``col`` are overwritten, blank the other half of
        any wide character they cut in two."""
        if col > 0 and cells[col].text == "":
            cells[col - 1] = self._blank()
        end = col + width
        if end < self.cols and cells[end].text == "":
            cells[end] = self._blank()

    def _print(self, char: str) -> None:
        width = get_character_cell_size(char)
        cluster = self._cluster
        if cluster is not None and (width == 0 or self._joining):
            self._attach(char, cluster)
            return
        if width == 0:
            # A combining mark with nothing before it has nothing to join.
            return
        if self._pending:
            self._wrap()
        if width == 2 and self._col == self.cols - 1:
            # One cell is left and the character needs two: it starts the next row.
            self._grid[self._row][self._col] = BLANK
            self._frozen[self._row] = None
            self._wrap()
        row, col = self._row, self._col
        cells = self._grid[row]
        self._clear_halves(cells, col, width)
        cells[col] = Cell(char, self._style)
        if width == 2:
            cells[col + 1] = Cell("", self._style)
        self._frozen[row] = None
        self._cluster = (row, col, width)
        self._joining = False
        self._advance(col + width)

    def _advance(self, end: int) -> None:
        """Put the cursor after a cluster that ends before column ``end``."""
        if end >= self.cols:
            self._col = self.cols - 1
            self._pending = True
        else:
            self._col = end
            self._pending = False

    def _attach(self, char: str, cluster: tuple[int, int, int]) -> None:
        """Join ``char`` to the cluster written last, as rich.cells measures it."""
        row, col, width = cluster
        cells = self._grid[row]
        old = cells[col]
        text = old.text + char
        cells[col] = Cell(text, old.style)
        self._frozen[row] = None
        self._joining = char == _ZWJ
        if width == 1 and cell_len(text) > 1 and col + 1 < self.cols:
            # A variation selector made a narrow emoji wide.
            self._clear_halves(cells, col + 1, 1)
            cells[col + 1] = Cell("", old.style)
            self._cluster = (row, col, 2)
            self._advance(col + 2)

    # -- escape sequences -------------------------------------------------------

    def _escape(self, char: str) -> None:
        self._buffer.append(char)
        if char == "[":
            self._state = _CSI
        elif char == "]":
            self._state = _OSC
        else:
            self._refuse("".join(self._buffer), "an escape sequence outside the subset")

    def _csi(self, char: str) -> None:
        self._buffer.append(char)
        code = ord(char)
        if 0x20 <= code <= 0x3F:
            if len(self._buffer) > MAX_CSI_LENGTH:
                self._refuse(
                    "".join(self._buffer), "longer than any sequence the subset holds"
                )
        elif 0x40 <= code <= 0x7E:
            sequence = "".join(self._buffer)
            self._state = _GROUND
            self._buffer = []
            self._dispatch_csi(sequence, sequence[2:-1], char)
            self._detach()
        else:
            self._refuse(
                "".join(self._buffer), "a control or non-ASCII character inside it"
            )

    def _params(self, sequence: str, body: str) -> list[int | None]:
        if not body:
            return []
        values: list[int | None] = []
        for part in body.split(";"):
            if not part:
                values.append(None)
            elif part.isascii() and part.isdigit() and len(part) <= 5:
                values.append(int(part))
            else:
                self._refuse(sequence, "parameters outside the subset")
        return values

    def _count(self, sequence: str, params: list[int | None]) -> int:
        """The one repeat count of a cursor move: 1 when it is absent or 0."""
        if len(params) > 1:
            self._refuse(sequence, "more parameters than the move takes")
        return params[0] or 1 if params else 1

    def _mode(self, sequence: str, params: list[int | None]) -> int:
        if len(params) > 1:
            self._refuse(sequence, "more parameters than the erase takes")
        mode = params[0] or 0 if params else 0
        if mode > 2:
            self._refuse(sequence, "an erase mode outside the subset")
        return mode

    def _dispatch_csi(self, sequence: str, body: str, final: str) -> None:
        private = ""
        if body and body[0] in _PRIVATE_MARKERS:
            private, body = body[0], body[1:]
        if any(char in _INTERMEDIATES for char in body) or ":" in body:
            self._refuse(sequence, "a form outside the subset")
        params = self._params(sequence, body)
        if private:
            if private == "?" and final in "hl" and params == [25]:
                self._visible = final == "h"
                return
            self._refuse(sequence, "a private mode outside the subset")
        if final == "m":
            self._sgr(sequence, params)
        elif final in "ABCDEFG":
            count = self._count(sequence, params)
            self._move_cursor(final, count)
        elif final == "H":
            if len(params) > 2:
                self._refuse(sequence, "more parameters than the move takes")
            row = (params[0] or 1) if params else 1
            col = (params[1] or 1) if len(params) > 1 else 1
            self._place(row - 1, col - 1)
        elif final == "J":
            self._erase_display(self._mode(sequence, params))
        elif final == "K":
            self._erase_line(self._mode(sequence, params))
        else:
            self._refuse(sequence, "a control sequence outside the subset")

    def _place(self, row: int, col: int) -> None:
        self._row = min(max(row, 0), self.rows - 1)
        self._col = min(max(col, 0), self.cols - 1)
        self._pending = False

    def _move_cursor(self, final: str, count: int) -> None:
        row, col = self._row, self._col
        if final == "A":
            self._place(row - count, col)
        elif final == "B":
            self._place(row + count, col)
        elif final == "C":
            self._place(row, col + count)
        elif final == "D":
            self._place(row, col - count)
        elif final == "E":
            self._place(row + count, 0)
        elif final == "F":
            self._place(row - count, 0)
        else:
            self._place(row, count - 1)

    def _blank_cells(self, row: int, start: int, stop: int) -> None:
        """Blank the cells of ``row`` from ``start`` up to, not including, ``stop``."""
        if start >= stop:
            return
        cells = self._grid[row]
        if start > 0 and cells[start].text == "":
            cells[start - 1] = self._blank()
        if stop < self.cols and cells[stop].text == "":
            cells[stop] = self._blank()
        blank = self._blank()
        for col in range(start, stop):
            cells[col] = blank
        self._frozen[row] = None

    def _erase_line(self, mode: int) -> None:
        if mode == 0:
            self._blank_cells(self._row, self._col, self.cols)
        elif mode == 1:
            self._blank_cells(self._row, 0, self._col + 1)
        else:
            self._blank_cells(self._row, 0, self.cols)

    def _erase_display(self, mode: int) -> None:
        if mode == 0:
            self._blank_cells(self._row, self._col, self.cols)
            for row in range(self._row + 1, self.rows):
                self._blank_cells(row, 0, self.cols)
        elif mode == 1:
            for row in range(self._row):
                self._blank_cells(row, 0, self.cols)
            self._blank_cells(self._row, 0, self._col + 1)
        else:
            for row in range(self.rows):
                self._blank_cells(row, 0, self.cols)

    def _sgr(self, sequence: str, params: list[int | None]) -> None:
        codes = [0 if value is None else value for value in params] or [0]
        style = self._style
        index = 0
        while index < len(codes):
            code = codes[index]
            if code == 0:
                style = Style()
            elif code == 1:
                style = dataclasses.replace(style, bold=True)
            elif code == 2:
                style = dataclasses.replace(style, dim=True)
            elif code == 3:
                style = dataclasses.replace(style, italic=True)
            elif code == 4:
                style = dataclasses.replace(style, underline=True)
            elif code == 7:
                style = dataclasses.replace(style, reverse=True)
            elif code == 22:
                style = dataclasses.replace(style, bold=False, dim=False)
            elif code == 23:
                style = dataclasses.replace(style, italic=False)
            elif code == 24:
                style = dataclasses.replace(style, underline=False)
            elif code == 27:
                style = dataclasses.replace(style, reverse=False)
            elif 30 <= code <= 37:
                style = dataclasses.replace(style, fg=code - 30)
            elif code == 39:
                style = dataclasses.replace(style, fg=None)
            elif 40 <= code <= 47:
                style = dataclasses.replace(style, bg=code - 40)
            elif code == 49:
                style = dataclasses.replace(style, bg=None)
            elif 90 <= code <= 97:
                style = dataclasses.replace(style, fg=code - 90 + 8)
            elif 100 <= code <= 107:
                style = dataclasses.replace(style, bg=code - 100 + 8)
            elif code in (38, 48):
                color, index = self._extended_color(sequence, codes, index)
                if code == 38:
                    style = dataclasses.replace(style, fg=color)
                else:
                    style = dataclasses.replace(style, bg=color)
            else:
                self._refuse(sequence, "an SGR attribute outside the subset")
            index += 1
        self._style = style

    def _extended_color(
        self, sequence: str, codes: list[int], index: int
    ) -> tuple[Color, int]:
        """The color after a 38 or 48 at ``index``, and the index of its last code."""
        mode = codes[index + 1] if index + 1 < len(codes) else None
        if mode == 5 and index + 2 < len(codes):
            if codes[index + 2] <= 255:
                return codes[index + 2], index + 2
        elif mode == 2 and index + 4 < len(codes):
            red, green, blue = codes[index + 2 : index + 5]
            if max(red, green, blue) <= 255:
                return (red, green, blue), index + 4
        self._refuse(sequence, "an extended color outside the subset")

    def _osc(self, char: str) -> None:
        self._buffer.append(char)
        if self._state == _OSC_ESCAPE:
            if char == "\\":
                self._finish_osc(2)
            else:
                self._refuse("".join(self._buffer), "an escape inside a string sequence")
        elif char == "\x07":
            self._finish_osc(1)
        elif char == _ESC:
            self._state = _OSC_ESCAPE
        elif ord(char) < 0x20 or len(self._buffer) > MAX_OSC_LENGTH:
            self._refuse(
                "".join(self._buffer), "a control character or a string too long"
            )

    def _finish_osc(self, terminator: int) -> None:
        sequence = "".join(self._buffer)
        payload = sequence[2 : len(sequence) - terminator]
        self._state = _GROUND
        self._buffer = []
        code, separator, rest = payload.partition(";")
        # Titles are ignored. A link shows its text, and the link itself is dropped.
        if separator and (code in ("0", "1", "2") or (code == "8" and ";" in rest)):
            self._detach()
            return
        self._refuse(sequence, "an operating system command outside the subset")


def emulated_screens(cast: Cast) -> Iterator[Screen]:
    """The screen after each output event of ``cast``.

    A recorder scrubs a recording by reading every screen it made, which finds a token
    that color changes or two events split. A resize event, a sequence outside the
    subset, and a cast that ends inside a sequence are refused.
    """
    emulator = Emulator(cast.header.width, cast.header.height)
    for event in cast.events:
        if event.code == "o":
            emulator.feed(event.data)
            yield emulator.screen()
        elif event.code == "r":
            raise RenderError(
                "a cast with a resize event is not drawn; a recording has one window size"
            )
    _require_finished(emulator)


def _require_finished(emulator: Emulator) -> None:
    pending = emulator.pending_sequence
    if pending:
        raise RenderError(
            f"the cast ends inside an escape sequence ({pending!r}); the recording is cut"
        )


# ---------------------------------------------------------------------------
# The timeline
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Frame:
    """A screen, the millisecond it appears at, and the scene it belongs to."""

    time_ms: int
    screen: Screen
    scene: int


@dataclasses.dataclass(frozen=True)
class Reveal:
    """A typed command that one frame shows whole.

    The command sits on ``row`` from column ``col``. Its ``chars`` characters show one
    by one from ``start_ms`` to ``end_ms``, the first at ``start_ms``.
    """

    frame: int
    scene: int
    row: int
    col: int
    chars: int
    start_ms: int
    end_ms: int


@dataclasses.dataclass(frozen=True)
class Timeline:
    """What the animation shows and when.

    ``scene_frames`` holds, for each scene, the index of its last frame. Frame times
    never go backwards; two frames share a time only when the last output of a scene
    came at the very end of it.
    """

    frames: tuple[Frame, ...]
    reveals: tuple[Reveal, ...]
    scene_frames: tuple[int, ...]
    poster_frame: int
    total_ms: int


@dataclasses.dataclass
class _Draft:
    time_ms: int
    screen: Screen
    scene: int
    #: A frame the decimation never drops.
    protected: bool
    #: Row, column, characters, start and end of the typed command this frame shows.
    reveal: tuple[int, int, int, int, int] | None = None


Events = list[tuple[int, str]]


def _split_scenes(cast: Cast, storyboard: Storyboard) -> list[Events]:
    """The output events of each scene, as (milliseconds, text), cut at the markers.

    The markers must be the storyboard's captions, at the storyboard's start times.
    """
    expected = storyboard.scenes
    scenes: list[Events] = []
    for event in cast.events:
        milliseconds = round(event.time * 1000)
        if event.code == "m":
            index = len(scenes)
            if index >= len(expected):
                raise RenderError(
                    f"the cast has more scene markers than the storyboard's "
                    f"{len(expected)} scenes"
                )
            scene = expected[index]
            if event.data != scene.caption:
                raise RenderError(
                    f"scene marker {index} is {event.data!r}; the storyboard's caption "
                    f"for scene {scene.scene_id!r} is {scene.caption!r}"
                )
            if milliseconds != scene.start_ms:
                raise RenderError(
                    f"scene {scene.scene_id!r} starts at {milliseconds} ms in the cast "
                    f"and at {scene.start_ms} ms in the storyboard"
                )
            scenes.append([])
        elif event.code == "o":
            if not scenes:
                raise RenderError("the cast has output before the first scene marker")
            scenes[-1].append((milliseconds, event.data))
        elif event.code == "r":
            raise RenderError(
                "a cast with a resize event is not drawn; a recording has one window size"
            )
    if len(scenes) != len(expected):
        raise RenderError(
            f"the cast has {len(scenes)} scene markers and the storyboard "
            f"{len(expected)} scenes"
        )
    return scenes


def _typing_parts(
    scene_id: str, events: Events, span, command: str
) -> tuple[Events, Events, Events]:
    """A scene's events cut into what comes before the typed characters, the typed
    characters, and the line feed and output after them.

    The record's typing span says where the typing ends and how many characters it
    holds; the cast has to agree, and has to type what the record says it ran.
    """
    after = next(
        (index for index, (ms, _) in enumerate(events) if ms >= span.end_ms), None
    )
    if after is None or events[after][1] != "\r\n":
        raise RenderError(
            f"scene {scene_id!r}: the cast has no line feed at {span.end_ms} ms, where "
            "the record says the typing ends"
        )
    start = after - span.chars
    typed = events[start:after] if start >= 0 else []
    if start < 0 or any(
        len(data) != 1 or not span.start_ms <= ms < span.end_ms for ms, data in typed
    ):
        raise RenderError(
            f"scene {scene_id!r}: the record says {span.chars} typed characters and "
            "the cast does not hold that many one-character events in the typing span"
        )
    text = "".join(data for _, data in typed)
    if text != command:
        raise RenderError(
            f"scene {scene_id!r}: the cast types {text!r} and the record says "
            f"{command!r}"
        )
    return events[:start], typed, events[after:]


def _groups(events: Events, merge_ms: int) -> list[Events]:
    """Events cut into frames: one starts at the first event that is not closer than
    ``merge_ms`` to the first event of the frame before it."""
    groups: list[Events] = []
    for ms, data in events:
        if groups and ms - groups[-1][0][0] < merge_ms:
            groups[-1].append((ms, data))
        else:
            groups.append([(ms, data)])
    return groups


def _scene_drafts(
    emulator: Emulator, index: int, scene, entry, events: Events, merge_ms: int
) -> list[_Draft]:
    span, command = entry.typing, entry.command
    if any(get_character_cell_size(char) != 1 for char in command):
        raise RenderError(
            f"scene {scene.scene_id!r}: the typed command {command!r} holds characters "
            "that are not one cell wide; a command is revealed one cell at a time"
        )
    before, typed, after = _typing_parts(scene.scene_id, events, span, command)
    for _, data in before:
        emulator.feed(data)
    start = emulator.screen()
    row, col = start.cursor_row, start.cursor_col
    for _, data in typed:
        emulator.feed(data)
    screen = emulator.screen()
    shown = "".join(cell.text for cell in screen.rows[row][col : col + span.chars])
    if shown != command:
        raise RenderError(
            f"scene {scene.scene_id!r}: the typed command does not stay on one row of "
            f"the terminal (it starts at column {col} and holds {span.chars} characters)"
        )
    # One frame shows the whole command from the start of the scene; the reveal
    # uncovers it as it is typed.
    drafts = [
        _Draft(
            scene.start_ms,
            screen,
            index,
            True,
            (row, col, span.chars, span.start_ms, span.end_ms),
        )
    ]
    for group in _groups(after, merge_ms):
        for _, data in group:
            emulator.feed(data)
        drafts.append(_Draft(group[0][0], emulator.screen(), index, False))
    drafts[-1].protected = True
    return drafts


def _decimate(drafts: list[_Draft], max_frames: int) -> list[_Draft]:
    """Drop frames, the one shown for the least time first, until ``max_frames`` stay.

    A dropped frame's update is skipped: the frame before it stays up until the next
    one. A protected frame is never dropped, and ties go to the earlier frame, so the
    result depends on the input alone.
    """
    count = len(drafts)
    if count <= max_frames:
        return drafts
    previous = list(range(-1, count - 1))
    following = list(range(1, count + 1))
    alive = [True] * count
    version = [0] * count

    def dwell(index: int) -> int:
        return drafts[following[index]].time_ms - drafts[index].time_ms

    heap = [
        (dwell(index), index, 0)
        for index, draft in enumerate(drafts)
        if not draft.protected
    ]
    heapq.heapify(heap)
    remaining = count
    while remaining > max_frames:
        if not heap:
            raise RenderError(
                f"the recording needs {remaining} frames that cannot be dropped (every "
                "typed command and the end of every scene), more than the cap of "
                f"{max_frames} frames"
            )
        _, index, seen = heapq.heappop(heap)
        if not alive[index] or version[index] != seen:
            continue
        alive[index] = False
        remaining -= 1
        before, after = previous[index], following[index]
        following[before] = after
        previous[after] = before
        if not drafts[before].protected:
            version[before] += 1
            heapq.heappush(heap, (dwell(before), before, version[before]))
    return [draft for draft, keep in zip(drafts, alive, strict=True) if keep]


def build_timeline(
    cast: Cast,
    record: RunRecord,
    storyboard: Storyboard,
    *,
    merge_ms: int = MERGE_MS,
    max_frames: int = MAX_FRAMES,
) -> Timeline:
    """The frames, reveals and poster of a recording.

    The cast, the record and the storyboard have to agree: the same terminal size,
    scene markers that are the storyboard's captions at its start times, a record that
    lists the storyboard's scenes in order, and typed characters in the cast that are
    the record's command. Any difference is refused with what differs.
    """
    header = cast.header
    terminal = storyboard.terminal
    if (header.width, header.height) != (terminal.cols, terminal.rows):
        raise RenderError(
            f"the cast is {header.width}x{header.height} and the storyboard's terminal "
            f"is {terminal.cols}x{terminal.rows}"
        )
    events = _split_scenes(cast, storyboard)
    wanted = [scene.scene_id for scene in storyboard.scenes]
    have = [scene.scene_id for scene in record.scenes]
    if have != wanted:
        raise RenderError(f"the record has scenes {have}; the storyboard has {wanted}")
    emulator = Emulator(header.width, header.height)
    drafts: list[_Draft] = []
    for index, scene in enumerate(storyboard.scenes):
        drafts += _scene_drafts(
            emulator, index, scene, record.scenes[index], events[index], merge_ms
        )
    _require_finished(emulator)
    drafts = _decimate(drafts, max_frames)
    last: dict[int, int] = {}
    reveals: list[Reveal] = []
    for position, draft in enumerate(drafts):
        last[draft.scene] = position
        if draft.reveal is not None:
            row, col, chars, start_ms, end_ms = draft.reveal
            reveals.append(
                Reveal(position, draft.scene, row, col, chars, start_ms, end_ms)
            )
    scene_frames = tuple(last[index] for index in range(len(storyboard.scenes)))
    return Timeline(
        frames=tuple(Frame(d.time_ms, d.screen, d.scene) for d in drafts),
        reveals=tuple(reveals),
        scene_frames=scene_frames,
        poster_frame=scene_frames[wanted.index(storyboard.poster_scene)],
        total_ms=storyboard.total_ms,
    )


# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------


def _ui_colors() -> Mapping[str, str]:
    """The design system's palette, read when it is needed so a change reaches us."""
    try:
        from automated_security_helper.utils.ui_theme import COLORS
    except ImportError as exc:
        raise RenderError(
            "the design-system palette (automated_security_helper.utils.ui_theme) "
            "cannot be imported; run this where ASH is installed"
        ) from exc
    return COLORS


def terminal_theme() -> CastTheme:
    """The recording's colors: the design system's foreground and background, its
    error, success, warning and accent as ANSI red, green, yellow and blue, and a fixed
    rest. It is the ``theme`` header a recorder writes into the cast."""
    colors = _ui_colors()
    named = {
        1: colors["error"],
        2: colors["success"],
        3: colors["warning"],
        4: colors["accent"],
    }
    palette = tuple(
        (named[index] if index in named else _FIXED_PALETTE[index]).lower()
        for index in range(16)
    )
    return CastTheme(
        fg=colors["foreground"].lower(), bg=colors["background"].lower(), palette=palette
    )


@dataclasses.dataclass(frozen=True)
class _Look:
    """The colors of an image: the terminal's, and the window's own."""

    theme: CastTheme
    surface: str
    border: str
    muted: str
    close: str
    minimize: str
    zoom: str


def _look() -> _Look:
    colors = _ui_colors()
    return _Look(
        theme=terminal_theme(),
        surface=colors["surface"].lower(),
        border=colors["border"].lower(),
        muted=colors["muted"].lower(),
        close=colors["error"].lower(),
        minimize=colors["warning"].lower(),
        zoom=colors["success"].lower(),
    )


def _color_hex(color: int | tuple[int, int, int], palette: Sequence[str]) -> str:
    """A color as ``#rrggbb``: the 256-color palette as xterm draws it, with its first
    sixteen entries taken from the theme."""
    if isinstance(color, tuple):
        red, green, blue = color
    elif color < 16:
        return palette[color]
    elif color < 232:
        index = color - 16
        red = _CUBE_LEVELS[index // 36]
        green = _CUBE_LEVELS[index // 6 % 6]
        blue = _CUBE_LEVELS[index % 6]
    else:
        red = green = blue = 8 + 10 * (color - 232)
    return f"#{red:02x}{green:02x}{blue:02x}"


def _resolve(style: Style, theme: CastTheme) -> tuple[str | None, str | None]:
    """The text color and the block color a style draws, each None for the default.

    Reverse video swaps the two, with the theme's own colors standing in for a default.
    """
    fg = None if style.fg is None else _color_hex(style.fg, theme.palette)
    bg = None if style.bg is None else _color_hex(style.bg, theme.palette)
    if style.reverse:
        fg, bg = (bg or theme.bg), (fg or theme.fg)
    if fg == theme.fg:
        fg = None
    if bg == theme.bg:
        bg = None
    return fg, bg


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------


class _Run(NamedTuple):
    """Text drawn in one style: where it starts, the cells it spans and its look."""

    col: int
    text: str
    cells: int
    color: str | None
    flags: str


def _analyze_row(
    row: tuple[Cell, ...], theme: CastTheme
) -> tuple[list[tuple[int, int, str]], list[_Run]]:
    """The color blocks and the text runs that draw a row.

    A block is a stretch of cells with a background. A run is a stretch of cells in one
    style, cut where the style changes and wherever two or more blank cells in a row
    leave a gap; a wide character is a run of its own, so that the grid holds around it.
    Blank cells that draw nothing are not drawn.
    """
    blocks: list[list] = []
    runs: list[_Run] = []
    current: list | None = None
    gap = 0
    col = 0
    while col < len(row):
        cell = row[col]
        if cell.text == "":
            col += 1
            continue
        wide = col + 1 < len(row) and row[col + 1].text == ""
        width = 2 if wide else 1
        style = cell.style
        color, block = _resolve(style, theme)
        if block is not None:
            if blocks and blocks[-1][2] == block and blocks[-1][0] + blocks[-1][1] == col:
                blocks[-1][1] += width
            else:
                blocks.append([col, width, block])
        if cell.text == " " and not style.underline:
            gap += 1
            col += width
            continue
        flags = "".join(
            letter
            for letter, on in (
                ("b", style.bold),
                ("i", style.italic),
                ("u", style.underline),
                ("d", style.dim),
            )
            if on
        )
        look = (color, flags)
        if current is not None and not wide and not current[4] and current[3] == look and gap <= 1:
            current[1] += " " * gap + cell.text
            current[2] += gap + width
        else:
            if current is not None:
                runs.append(_Run(current[0], current[1], current[2], *current[3]))
            current = [col, cell.text, width, look, wide]
        gap = 0
        col += width
    if current is not None:
        runs.append(_Run(current[0], current[1], current[2], *current[3]))
    return [(col, cells, color) for col, cells, color in blocks], runs


def _row_markup(
    row_id: str,
    blocks: Sequence[tuple[int, int, str]],
    runs: Sequence[_Run],
    classes: Mapping[str, str],
) -> str:
    parts = [f'<g id="{row_id}">']
    for col, cells, color in blocks:
        parts.append(
            f'<rect x="{col * CELL_WIDTH}" width="{cells * CELL_WIDTH}" '
            f'height="{LINE_HEIGHT}" class="{classes[color]}"/>'
        )
    for run in runs:
        names = ([classes[run.color]] if run.color is not None else []) + list(run.flags)
        attribute = f' class="{" ".join(names)}"' if names else ""
        parts.append(
            f'<text x="{run.col * CELL_WIDTH}" y="{BASELINE}" '
            f'textLength="{run.cells * CELL_WIDTH}" lengthAdjust="spacingAndGlyphs"'
            f"{attribute}>{_escape_text(run.text)}</text>"
        )
    parts.append("</g>")
    return "".join(parts)


class _Rows:
    """The distinct rows of one document that draw anything, numbered by first use."""

    def __init__(self, theme: CastTheme) -> None:
        self._theme = theme
        self._ids: dict[tuple[Cell, ...], str | None] = {}
        self._stored: list[tuple[str, list, list]] = []

    def use(self, row: tuple[Cell, ...]) -> str | None:
        """The id of ``row``'s stored markup, or None for a row that draws nothing."""
        if row in self._ids:
            return self._ids[row]
        blocks, runs = _analyze_row(row, self._theme)
        if not blocks and not runs:
            self._ids[row] = None
            return None
        row_id = f"r{len(self._stored)}"
        self._ids[row] = row_id
        self._stored.append((row_id, blocks, runs))
        return row_id

    def uses(self, screen: Screen) -> str:
        """The ``<use>`` references that draw ``screen``, one per row that draws."""
        parts = []
        for index, row in enumerate(screen.rows):
            row_id = self.use(row)
            if row_id is not None:
                parts.append(f'<use href="#{row_id}" y="{index * LINE_HEIGHT}"/>')
        return "".join(parts)

    def classes(self) -> dict[str, str]:
        """A class name for each color the rows use, numbered in sorted color order."""
        used: set[str] = set()
        for _, blocks, runs in self._stored:
            used.update(color for _, _, color in blocks)
            used.update(run.color for run in runs if run.color is not None)
        return {color: f"c{number}" for number, color in enumerate(sorted(used))}

    def markup(self, classes: Mapping[str, str]) -> list[str]:
        return [
            _row_markup(row_id, blocks, runs, classes)
            for row_id, blocks, runs in self._stored
        ]


# ---------------------------------------------------------------------------
# The documents
# ---------------------------------------------------------------------------


def _micro(milliseconds: int, total: int) -> int:
    """A time as millionths of the total, in integer arithmetic, rounded half up."""
    return (milliseconds * 1_000_000 + total // 2) // total


def _percent(micro: int) -> str:
    return f"{micro // 10_000}.{micro % 10_000:04d}"


def _shift(axis: str, offset: int) -> str:
    return f"transform:translate{axis}({offset}px)"


def _keyframes(name: str, entries: Sequence[tuple[int, str]]) -> str:
    """One ``@keyframes`` rule from (millionths, declarations); when two entries land
    on the same offset, the later one wins."""
    merged: dict[int, str] = {}
    for micro, declaration in entries:
        merged[micro] = declaration
    body = "".join(
        f"{_percent(micro)}%{{{declaration}}}"
        for micro, declaration in sorted(merged.items())
    )
    return f"@keyframes {name}{{{body}}}"


def _animation_rules(
    timeline: Timeline, storyboard: Storyboard, pitch: int
) -> list[str]:
    """The CSS that plays the strip, the window title and each typed command."""
    total = timeline.total_ms
    once = storyboard.playback == "once"
    rules = [
        f".a{{animation-duration:{total}ms;animation-timing-function:step-end;"
        f"animation-iteration-count:{'1' if once else 'infinite'};"
        "animation-fill-mode:forwards}",
        ".s{animation-name:s}.k{animation-name:k}",
    ]
    rules.extend(
        f".t{number}{{animation-name:t{number}}}"
        for number in range(len(timeline.reveals))
    )
    strip = [
        (_micro(frame.time_ms, total), _shift("Y", -index * pitch))
        for index, frame in enumerate(timeline.frames)
    ]
    titles = [
        (_micro(scene.start_ms, total), _shift("Y", -index * CHROME_HEIGHT))
        for index, scene in enumerate(storyboard.scenes)
    ]
    if once:
        # After the last scene the animation cuts back to the poster and rests there.
        poster_scene = _poster_scene(storyboard)
        strip.append((1_000_000, _shift("Y", -timeline.poster_frame * pitch)))
        titles.append((1_000_000, _shift("Y", -poster_scene * CHROME_HEIGHT)))
    rules.append(_keyframes("s", strip))
    rules.append(_keyframes("k", titles))
    for number, reveal in enumerate(timeline.reveals):
        distance = reveal.chars * CELL_WIDTH
        # The first character shows at the start of the typing, one more at each step.
        steps = f"{_shift('X', 0)};animation-timing-function:steps({reveal.chars},jump-start)"
        rules.append(
            _keyframes(
                f"t{number}",
                [
                    (0, _shift("X", 0)),
                    (_micro(reveal.start_ms, total), steps),
                    (_micro(reveal.end_ms, total), _shift("X", distance)),
                    (1_000_000, _shift("X", distance)),
                ],
            )
        )
    rules.append("@media (prefers-reduced-motion:reduce){.a{animation:none}}")
    return rules


def _poster_scene(storyboard: Storyboard) -> int:
    return [scene.scene_id for scene in storyboard.scenes].index(storyboard.poster_scene)


def _stylesheet(look: _Look, classes: Mapping[str, str], extra: Sequence[str]) -> str:
    theme = look.theme
    rules = [
        f"text{{font-family:{FONT_STACK};font-size:{FONT_SIZE}px;"
        f"fill:{theme.fg};white-space:pre}}",
        f".cap{{font-family:{CAPTION_FONT_STACK};font-size:{CAPTION_SIZE}px;"
        f"fill:{look.muted}}}",
        ".b{font-weight:700}.i{font-style:italic}.u{text-decoration:underline}"
        ".d{opacity:.6}",
        f".w,.v{{fill:{theme.bg}}}.h{{fill:{look.surface}}}.l{{fill:{look.border}}}",
        f".x1{{fill:{look.close}}}.x2{{fill:{look.minimize}}}.x3{{fill:{look.zoom}}}",
    ]
    rules.extend(f".{name}{{fill:{color}}}" for color, name in classes.items())
    rules.extend(extra)
    return "\n".join(rules)


def _title(storyboard: Storyboard) -> str:
    return "Terminal recording: " + ", ".join(
        scene.caption for scene in storyboard.scenes
    )


def _description(storyboard: Storyboard, record: RunRecord) -> str:
    played = "once" if storyboard.playback == "once" else "in a loop"
    scenes = "; ".join(
        f"Scene {number}: {scene.caption} ({entry.command})"
        for number, (scene, entry) in enumerate(
            zip(storyboard.scenes, record.scenes, strict=True), start=1
        )
    )
    return (
        f"A terminal recording in {len(storyboard.scenes)} scenes, "
        f"{storyboard.total_s:g} seconds long, played {played}. Typing is synthetic "
        f"and pauses are shortened. {scenes}."
    )


def _window(width: int, height: int) -> list[str]:
    """The window chrome that does not move: its body, title bar and three dots."""
    return [
        f'<rect class="w" width="{width}" height="{height}"/>',
        f'<rect class="h" width="{width}" height="{CHROME_HEIGHT}"/>',
        f'<rect class="l" y="{CHROME_HEIGHT - 1}" width="{width}" height="1"/>',
        '<circle class="x1" cx="18" cy="18" r="6"/>',
        '<circle class="x2" cx="38" cy="18" r="6"/>',
        '<circle class="x3" cx="58" cy="18" r="6"/>',
    ]


def _caption(text: str, width: int, row: int = 0) -> str:
    return (
        f'<text class="cap" x="{width / 2:g}" y="{row * CHROME_HEIGHT + CAPTION_BASELINE}" '
        f'text-anchor="middle">{_escape_text(text)}</text>'
    )


def _root(width: int, height: int) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="t d">'
    )


def _animated_svg(
    timeline: Timeline,
    storyboard: Storyboard,
    record: RunRecord,
    cast: Cast,
    look: _Look,
) -> str:
    cols, rows = cast.header.width, cast.header.height
    width = cols * CELL_WIDTH + 2 * PAD_X
    pitch = rows * LINE_HEIGHT + 2 * PAD_Y
    height = CHROME_HEIGHT + pitch
    store = _Rows(look.theme)
    covered = {reveal.frame: (number, reveal) for number, reveal in enumerate(timeline.reveals)}
    frames = []
    for index, frame in enumerate(timeline.frames):
        cover = ""
        if index in covered:
            number, reveal = covered[index]
            cover = (
                f'<rect class="a v t{number}" x="{reveal.col * CELL_WIDTH}" '
                f'y="{reveal.row * LINE_HEIGHT}" width="{reveal.chars * CELL_WIDTH}" '
                f'height="{LINE_HEIGHT}"/>'
            )
        frames.append(
            f'<g transform="translate({PAD_X} {index * pitch + PAD_Y})">'
            f"{store.uses(frame.screen)}{cover}</g>"
        )
    classes = store.classes()
    css = _stylesheet(look, classes, _animation_rules(timeline, storyboard, pitch))
    poster_scene = _poster_scene(storyboard)
    captions = "".join(
        _caption(scene.caption, width, index)
        for index, scene in enumerate(storyboard.scenes)
    )
    parts = [
        _root(width, height),
        f'<title id="t">{_escape_text(_title(storyboard))}</title>',
        f'<desc id="d">{_escape_text(_description(storyboard, record))}</desc>',
        f"<style>{css}</style>",
        "<defs>",
        *store.markup(classes),
        "</defs>",
        *_window(width, height),
        f'<svg x="0" y="0" width="{width}" height="{CHROME_HEIGHT}">'
        f'<g class="a k" transform="translate(0 {-poster_scene * CHROME_HEIGHT})">'
        f"{captions}</g></svg>",
        f'<svg x="0" y="{CHROME_HEIGHT}" width="{width}" height="{pitch}">'
        f'<rect class="w" width="{width}" height="{pitch}"/>',
        f'<g class="a s" transform="translate(0 {-timeline.poster_frame * pitch})">',
        *frames,
        "</g>",
        "</svg>",
        "</svg>",
    ]
    return "\n".join(parts) + "\n"


def _poster_svg(
    timeline: Timeline,
    storyboard: Storyboard,
    record: RunRecord,
    cast: Cast,
    look: _Look,
) -> str:
    cols, rows = cast.header.width, cast.header.height
    width = cols * CELL_WIDTH + 2 * PAD_X
    pitch = rows * LINE_HEIGHT + 2 * PAD_Y
    height = CHROME_HEIGHT + pitch
    store = _Rows(look.theme)
    uses = store.uses(timeline.frames[timeline.poster_frame].screen)
    classes = store.classes()
    caption = storyboard.scenes[_poster_scene(storyboard)].caption
    parts = [
        _root(width, height),
        f'<title id="t">{_escape_text(_title(storyboard))}</title>',
        f'<desc id="d">{_escape_text(_description(storyboard, record))}</desc>',
        f"<style>{_stylesheet(look, classes, [])}</style>",
        "<defs>",
        *store.markup(classes),
        "</defs>",
        *_window(width, height),
        _caption(caption, width),
        f'<g transform="translate({PAD_X} {CHROME_HEIGHT + PAD_Y})">{uses}</g>',
        "</svg>",
    ]
    return "\n".join(parts) + "\n"


@dataclasses.dataclass(frozen=True)
class Rendering:
    """The two images and what went into them."""

    svg: str
    poster: str
    frames: int
    poster_frame: int


def render(
    cast: Cast,
    record: RunRecord,
    storyboard: Storyboard,
    *,
    max_bytes: int = MAX_SVG_BYTES,
    max_frames: int = MAX_FRAMES,
    merge_ms: int = MERGE_MS,
) -> Rendering:
    """The animated SVG and the poster for a recording.

    A pure function of its inputs. The animated SVG may not be larger than
    ``max_bytes``; ``max_frames`` and ``merge_ms`` are the timeline's.
    """
    timeline = build_timeline(
        cast, record, storyboard, merge_ms=merge_ms, max_frames=max_frames
    )
    look = _look()
    svg = _animated_svg(timeline, storyboard, record, cast, look)
    poster = _poster_svg(timeline, storyboard, record, cast, look)
    for name, text in (("animated SVG", svg), ("poster", poster)):
        size = len(text.encode("utf-8"))
        if size > max_bytes:
            raise RenderError(
                f"the {name} is {size} bytes, over the {max_bytes}-byte ceiling; a "
                "shorter recording, a smaller terminal or fewer frames bring it down"
            )
    return Rendering(svg, poster, len(timeline.frames), timeline.poster_frame)


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def _read(path: Path, what: str, load):
    try:
        return load(path)
    except OSError as exc:
        raise RenderError(f"{path}: the {what} cannot be read: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise RenderError(f"{path}: the {what} is not UTF-8 text: {exc}") from exc
    except CastError as exc:
        raise RenderError(f"{path}: the {what} is refused: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 with a diff if a committed image is stale, instead of writing it.",
    )
    defaults = {
        "--cast": ("the asciicast to read", CAST_DIR / f"{RECORDING_NAME}.cast"),
        "--record": (
            "the run record to read",
            CAST_DIR / f"{RECORDING_NAME}.record.json",
        ),
        "--storyboard": ("the storyboard to read", STORYBOARD_PATH),
        "--svg": (
            "the animated SVG to write or check",
            CAST_DIR / f"{RECORDING_NAME}.svg",
        ),
        "--poster": (
            "the poster to write or check",
            CAST_DIR / f"{RECORDING_NAME}-poster.svg",
        ),
    }
    for flag, (what, default) in defaults.items():
        parser.add_argument(
            flag, default=None, help=f"Path of {what}. Default: <docs root>/{default}."
        )
    add_docs_root_argument(parser)
    args = parser.parse_args(argv)
    root = Path(args.docs_root).resolve()
    cast_dir = root / CAST_DIR
    cast_path = Path(args.cast) if args.cast else cast_dir / f"{RECORDING_NAME}.cast"
    record_path = (
        Path(args.record) if args.record else cast_dir / f"{RECORDING_NAME}.record.json"
    )
    storyboard_path = Path(args.storyboard) if args.storyboard else root / STORYBOARD_PATH
    svg_path = Path(args.svg) if args.svg else cast_dir / f"{RECORDING_NAME}.svg"
    poster_path = (
        Path(args.poster) if args.poster else cast_dir / f"{RECORDING_NAME}-poster.svg"
    )
    try:
        cast = _read(cast_path, "asciicast", read_cast)
        record = _read(record_path, "run record", read_record)
        storyboard = _read(
            storyboard_path, "storyboard", lambda path: load_storyboard(path, None)
        )
        rendering = render(cast, record, storyboard)
    except CastError as exc:
        print(f"{GENERATOR} refused its input: {exc}", file=sys.stderr)
        return 2
    status = 0
    for path, text in ((svg_path, rendering.svg), (poster_path, rendering.poster)):
        summary = f"{rendering.frames} frames, {len(text.encode('utf-8'))} bytes."
        status |= write_or_check(path, text, args.check, GENERATOR, summary)
    return status


if __name__ == "__main__":
    sys.exit(main())
