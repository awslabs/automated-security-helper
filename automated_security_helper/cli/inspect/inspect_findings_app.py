"""`ash inspect findings`: an interactive explorer for a scan's findings.

A finding's rule id, file, message, suppression reason and code snippet come from
the scanned repository or a scanner's output, and so does a scanner's name. None
of it is markup or markdown here: each value reaches a widget through _shown,
_shown_prose, _text, _cell, _snippet or _metadata_table, as text with its
terminal controls shown as escapes. Built into a markup string, "[@click=app.quit]" in a rule id was
an action a click ran (Textual's app actions include screenshot, which writes a
file) and "[link=...]" a hyperlink; built into a Markdown document, a message's
markdown link opened a browser and a "```" in a snippet ended its code fence.
tests/unit/cli/inspect/test_finding_text_is_not_markup.py fails when a module here
hands text to a markup-reading API any other way.
"""

import re
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, BinaryIO, Callable, Dict, List, Optional

import typer
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.geometry import Size
from textual.containers import (
    Container,
    HorizontalGroup,
    ScrollableContainer,
    VerticalGroup,
)
from textual.content import Content
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
)
from textual.widgets.data_table import ColumnKey

from automated_security_helper.config.ash_config import add_suppression_to_config
from automated_security_helper.core.exceptions import ASHConfigSourceError
from automated_security_helper.utils.console import echo, secho
from automated_security_helper.config.resolve_config import find_config_file
from automated_security_helper.core.constants import (
    ASH_CONFIG_SOURCES_DESCRIPTION,
    ASH_DEFAULT_CONFIG_FILE_NAME,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import (
    AshSuppression,
    expiration_date_problem,
    expiration_has_passed,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import Result
from automated_security_helper.utils.error_text import error_text
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.path_matching import (
    PathNotExpressible,
    literal_path_pattern,
)
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    open_in_scanned_tree,
)
from automated_security_helper.utils.secret_masking import source_snippet_masker
from automated_security_helper.utils.severity_ladder import result_severity
from automated_security_helper.utils.terminal_text import (
    controls_shown,
    only_controls_shown,
)
from automated_security_helper.utils.undecodable_text import undecodable_of_text
from automated_security_helper.utils.ui_theme import (
    COLORS,
    FOOTER_CREDIT,
    severity_color,
    textual_theme,
)

#: The most of a code snippet the detail view shows: lines, and characters of each
#: line. A snippet cut to it ends with a SNIPPET_TRUNCATED line. Textual draws every
#: styled character of the view on each resize: 200 lines of 2,000 characters took
#: 3.8 s per resize on a loaded host, 200 of 500 took 1.3 s. A snippet is context
#: around a finding, and 500 columns hold a line of real code; a minified line is
#: cut, as it should be.
SNIPPET_LINES = 200
SNIPPET_LINE_CHARS = 500
SNIPPET_TRUNCATED = "(truncated)"

#: The most characters of a finding's message the detail view shows: as much text
#: as a snippet at its cap holds. A message is prose, which the view wraps, so the
#: cap is on the whole text and not on each line (``_shown_prose``).
MESSAGE_CHARS = SNIPPET_LINES * SNIPPET_LINE_CHARS

#: What the detail view's Code section says for a finding that names a file whose
#: lines are not shown: the results hold no snippet, and the file is not one the
#: TUI reads (see _source_excerpt).
SOURCE_NOT_SHOWN = "(source not shown)"

#: The key of a finding whose code the TUI read from a file (``_show_detail``):
#: the path it read. The detail view says so above the lines, because they are
#: the file as it is now, not as the scan read it, and the file is the one under
#: the scanned directory the results' layout names (``scanned_directory``).
SNIPPET_READ_FROM = "code_snippet_read_from"

#: The key of a finding whose code snippet was read from a file: the characters
#: of each snippet line the detail view shows, SNIPPET_LINE_CHARS of source after
#: the line's number and marker (``_excerpt_line_chars``).
SNIPPET_LINE_CHARS_KEY = "code_snippet_line_chars"

#: The most bytes read from a finding's file to reach the lines around it. A
#: finding deep in a large file shows nothing rather than keep the TUI reading.
SOURCE_READ_LIMIT = 64 * 1024 * 1024

#: Lines shown on each side of a finding's line when they are read from its file.
_CONTEXT_LINES = 5

#: The bytes of each line kept while reading. A line longer than this is not shown
#: at all (SOURCE_LINE_NOT_SHOWN): its head alone would reach the masker without
#: the rest, so a value that started inside the shown part and ended past the head
#: was not matched, and its start was shown. Nothing the masker could not check
#: whole is shown. 64 KiB holds any line of code or prose (a paragraph of CJK text,
#: a long log line) and leaves out only minified bundles and data blobs; the lines
#: around a finding then take at most (2 * _CONTEXT_LINES + 1) times this. A head
#: of (SNIPPET_LINE_CHARS + 1) * 4 bytes, enough for the shown part alone, hid
#: every line over about 2,000 bytes, a Markdown paragraph among them.
_LINE_HEAD_BYTES = 64 * 1024

#: What an excerpt shows in place of a line longer than _LINE_HEAD_BYTES, or one
#: the read limit ended inside. Not the head of the line: see _LINE_HEAD_BYTES.
SOURCE_LINE_NOT_SHOWN = "(line too long to show)"

#: The most bytes asked of the file at a time.
_READ_CHUNK = 64 * 1024


def scanned_directory(report_file: Path) -> Optional[Path]:
    """The directory a scan wrote *report_file* for, by ASH's output layout, or None.

    A scan writes its results to ``<scanned directory>/.ash/ash_output`` unless told
    to put them elsewhere, and the results record no absolute path for the
    directory (``metadata.scan_source`` is relative to a git repository's root,
    and names no directory on another host). For results anywhere else, None: the
    TUI then reads no file for a finding the results give no snippet.
    """
    output_dir = Path(report_file).absolute().parent
    if output_dir.name == "ash_output" and output_dir.parent.name == ".ash":
        return output_dir.parent.parent
    return None


def _line_text(head: bytes) -> str:
    """A line's kept bytes as text, without its line end.

    Not cut to the cap here: the lines are masked first (``mask_source``) and cut
    to SNIPPET_LINE_CHARS + 1 characters after (``_cut_excerpt_lines``). Cut before
    the masking, a secret value or shape that started inside the cap and ended past
    it was no longer whole, so the masker did not match it and its head was shown.
    The head is at most _LINE_HEAD_BYTES bytes, and a line that did not fit in it
    is replaced by SOURCE_LINE_NOT_SHOWN (``_read_lines``) for the same reason.
    """
    text = head.decode("utf-8", errors="replace")
    return text.removesuffix("\n").removesuffix("\r")


#: The most characters of a source line kept in an excerpt, after its number and
#: marker: one more than the cap, so _capped still reads it as cut.
_EXCERPT_LINE_CHARS = SNIPPET_LINE_CHARS + 1


def _cut_excerpt_lines(excerpt: str) -> str:
    """*excerpt* (``_source_excerpt``'s text) with each line cut to its number,
    its marker and _EXCERPT_LINE_CHARS characters of source.

    After the masking, so a value the masker replaces is matched whole; see
    ``_line_text``. A line the masker replaced is shorter than the cap already."""
    cut = []
    for line in excerpt.split("\n"):
        marker, separator, text = line.partition(": ")
        if separator and len(text) > _EXCERPT_LINE_CHARS:
            line = f"{marker}{separator}{text[:_EXCERPT_LINE_CHARS]}"
        cut.append(line)
    return "\n".join(cut)


def _excerpt_line_chars(excerpt: str) -> int:
    """The characters of each line of *excerpt* the detail view shows: the line's
    number and marker, then SNIPPET_LINE_CHARS of source.

    The cap is on the source (``SNIPPET_LINE_CHARS``), and the number and marker
    are the view's own layout, so they are added to it: counted inside the cap,
    a source line of 491 to 500 characters lost its last characters to the
    "→ 123: " before it and was shown "(truncated)". Every line of an excerpt has
    a number of the same width (``_source_excerpt``), so the first line's prefix
    measures them all.
    """
    prefix, separator, _text = excerpt.split("\n", 1)[0].partition(": ")
    return SNIPPET_LINE_CHARS + len(prefix) + len(separator)


#: The line ends a finding's line number counts: universal newlines, as the
#: scanners number lines and as the masker counts them
#: (utils/secret_masking.py's _LINE_BREAK). Counted by ``\n`` alone, a file with
#: a lone carriage return numbered its lines differently from the finding that
#: names one, so the arrow marked another line.
_LINE_END = re.compile(rb"\r\n|\n|\r")


def _line_ends(chunk: bytes) -> int:
    """How many line ends *chunk* holds, a ``\\r\\n`` counted once."""
    return chunk.count(b"\n") + chunk.count(b"\r") - chunk.count(b"\r\n")


def _read_chunk(handle: BinaryIO, budget: int, after_cr: bool) -> tuple[bytes, int]:
    """Up to _READ_CHUNK bytes of *handle*, within *budget*, and how many of them
    were dropped: when the chunk before ended on ``\\r`` (*after_cr*) and this one
    starts with ``\\n``, that byte is the second half of a ``\\r\\n`` whose first half
    was already counted as a line end, so it is dropped and never counted again.
    A ``\\r\\n`` split by a chunk is then one line end whatever the chunk holds.
    Reading one more byte after a ``\\r`` instead still split ``\\r\\r\\n``, and the
    lines after it were numbered one more than the finding numbers them.

    An empty chunk with nothing dropped is the end of the file or of the budget.
    """
    chunk = handle.read(min(budget, _READ_CHUNK))
    if after_cr and chunk.startswith(b"\n"):
        return chunk[1:], 1
    return chunk, 0


def _offset_of_line(handle: BinaryIO, line: int, budget: int) -> Optional[int]:
    """The byte offset where line *line* (counted from 1) of *handle* starts, or None
    when the file, or *budget* bytes, end first.

    The line ends before it are counted in _READ_CHUNK reads, not read a line at a
    time: a file of 40 million short lines took 18.9 s to reach its end one
    readline at a time, on the UI thread, though the byte budget bounds the read.
    The ends are counted (``_line_ends``) and only the chunk holding the wanted
    line is scanned end by end.
    """
    to_skip = line - 1
    offset = 0
    after_cr = False
    while to_skip > 0:
        chunk, dropped = _read_chunk(handle, budget - offset, after_cr)
        offset += dropped
        if not chunk:
            if dropped:
                after_cr = False
                continue
            return None
        ends = _line_ends(chunk)
        if ends >= to_skip:
            for match in _LINE_END.finditer(chunk):
                to_skip -= 1
                if to_skip == 0:
                    end = offset + match.end()
                    if (
                        match.end() == len(chunk)
                        and chunk.endswith(b"\r")
                        and end < budget
                        and handle.read(1) == b"\n"
                    ):
                        # The wanted line ends on the chunk's last byte, a lone
                        # carriage return so far: a newline right after it is
                        # the same line end, and the next line starts past it.
                        end += 1
                    return end
        to_skip -= ends
        offset += len(chunk)
        after_cr = chunk.endswith(b"\r")
    return offset


def _read_lines(handle: BinaryIO, first: int, last: int) -> list[str]:
    """Lines *first* to *last* (counted from 1) of *handle*, each whole (its line
    end removed, _line_text) or replaced by SOURCE_LINE_NOT_SHOWN.

    At most SOURCE_READ_LIMIT bytes are read, the lines before *first* only counted
    (_offset_of_line), and only the head of each wanted line is kept, so a line
    that never ends (minified code, a sparse file) costs that many bytes of reading
    and no more memory than its head. A line longer than its head
    (_LINE_HEAD_BYTES), or one the limit ended inside, is replaced by
    SOURCE_LINE_NOT_SHOWN: shown as its head alone, a value that started in the
    shown part and ended past the head reached the masker cut, was not matched, and
    its start was shown. Fewer lines when the file, or the limit, ends first.
    *handle* is a regular file, so it can seek back to where *first* starts.
    """
    start = _offset_of_line(handle, first, SOURCE_READ_LIMIT)
    if start is None:
        return []
    handle.seek(start)
    kept: list[str] = []
    budget = SOURCE_READ_LIMIT - start
    number = first
    head = bytearray()
    overflowed = False
    after_cr = False

    def keep(segment: bytes) -> None:
        nonlocal overflowed
        room = _LINE_HEAD_BYTES - len(head)
        if len(segment) > room:
            overflowed = True
        head.extend(segment[:room])

    while number <= last and budget > 0:
        # Read in chunks and split at every line end (_LINE_END), not readline:
        # readline ends a line at "\n" alone, so a lone "\r" stayed inside a
        # line and the lines after it were numbered one less than the finding
        # numbers them.
        chunk, dropped = _read_chunk(handle, budget, after_cr)
        budget -= len(chunk) + dropped
        if not chunk:
            if dropped:
                after_cr = False
                continue
            break
        after_cr = chunk.endswith(b"\r")
        position = 0
        for match in _LINE_END.finditer(chunk):
            keep(chunk[position : match.start()])
            kept.append(
                SOURCE_LINE_NOT_SHOWN if overflowed else _line_text(bytes(head))
            )
            head.clear()
            overflowed = False
            number += 1
            position = match.end()
            if number > last:
                break
        else:
            keep(chunk[position:])
    if head and number <= last:
        # The last line read: the file or the limit ended inside it. Past the limit
        # the line goes on unread, so it is not shown either; at the file's end it
        # is whole.
        if overflowed or (budget <= 0 and handle.read(1)):
            kept.append(SOURCE_LINE_NOT_SHOWN)
        else:
            kept.append(_line_text(bytes(head)))
    return kept


def _source_path(file_value: object, scan_root: Path) -> Path:
    """The file under *scan_root* a finding's recorded URI names.

    The URI is the results' text: a name that is not UTF-8 is recorded in its
    record form (utils/undecodable_text.py, ``\\udcNN`` for each byte), so the
    name is read back before the file is opened, as every reader of a recorded
    name does. Opened as the six characters of the record form, the file was
    never found and the view said "(source not shown)" for a file that exists.
    """
    return scan_root / undecodable_of_text(str(file_value))


def _excerpt_start(line_number: int, read_from: Optional[int]) -> int:
    """The first line ``_source_excerpt`` reads: the window's, or the earlier line
    the masker asked to read from (``earliest_reported_line``)."""
    first = max(1, line_number - _CONTEXT_LINES)
    return first if read_from is None else min(first, max(1, read_from))


def _drop_lines_before(excerpt: str, count: int) -> str:
    """*excerpt* without its first *count* lines (each ends with a newline)."""
    return excerpt if count <= 0 else "\n".join(excerpt.split("\n")[count:])


def _source_excerpt(
    finding: dict, scan_root: Optional[Path], read_from: Optional[int] = None
) -> Optional[str]:
    """The lines around a finding's line, read from its file, or None.

    With *read_from*, an earlier line than the window starts at, the lines run
    from there: the masker needs the BEGIN line of a key block to find the
    block, and the caller cuts the lines before the window off after masking.

    The file and line are the results', so a scanner's and the scanned repository's
    to name. The file is read only when it is a regular file inside *scan_root*, as
    utils/scanned_tree.py decides: it is opened without waiting on a FIFO, checked
    as a regular file on the descriptor it is read from, and a symlink is followed
    only while it stays inside the tree. A path outside the tree, "../" included,
    a device such as /dev/zero, a FIFO or a link out is not read. Neither is any
    file when there is no scan root, and reading stops at SOURCE_READ_LIMIT. Each
    line is marked with its number, right-aligned so every prefix is as wide as
    the last line's, the finding's with an arrow.
    """
    file_value = finding.get("file")
    try:
        line_number = int(finding.get("line"))
    except (TypeError, ValueError):
        return None
    if scan_root is None or not file_value or line_number < 1:
        return None
    first = _excerpt_start(line_number, read_from)
    try:
        with open_in_scanned_tree(
            _source_path(file_value, scan_root), scan_root, follow_links_inside=True
        ) as handle:
            lines = _read_lines(handle, first, line_number + _CONTEXT_LINES)
    except TreeInputRefused as refused:
        ASH_LOGGER.debug(f"Not showing the source of {refused.path}: {refused.reason}")
        return None
    except (OSError, ValueError) as exc:
        # ValueError: a NUL in the name.
        ASH_LOGGER.debug(f"Could not read the source of {file_value}: {exc}")
        return None
    if not first <= line_number < first + len(lines):
        return None
    width = len(str(first + len(lines) - 1))
    return "".join(
        f"{'→ ' if number == line_number else '  '}{number:>{width}}: {text}\n"
        for number, text in enumerate(lines, start=first)
    )


def _suppression_path(file_value: object) -> str:
    """The suppression ``path`` that names the file of a finding, and no other.

    The finding's file is the results' recorded URI, written as the scanner wrote
    it: ``./src/x.py`` or ``src//x.py``. The scan matches a suppression against the
    folded spelling (utils/sarif_utils.py's ``_matched_path_text``: ``.``
    components and repeated separators folded, ``..`` kept), so the recorded
    spelling is folded the same way here, or the saved entry never matched its
    finding. A URI with a scheme and an authority is left as written, as the scan
    leaves it.

    Then written as a pattern that matches that one path
    (``path_matching.literal_path_pattern``): ``[``, ``*`` and ``?`` in a file name
    are glob syntax in a pattern, so ``x[1].py`` as a pattern matched ``x1.py``
    and ``a*b.py`` matched every file between. A path holding a backslash has no
    pattern of its own (``PathNotExpressible``, raised to the caller).
    """
    return literal_path_pattern(_folded_file(file_value))


def _folded_file(file_value: object) -> str:
    """A finding's recorded file in the spelling the scan matches a suppression
    against: ``.`` components and repeated separators folded, ``..`` kept, a URI
    with a scheme and an authority left as written (see ``_suppression_path``)."""
    text = str(file_value)
    if "://" not in text:
        text = PurePosixPath(text).as_posix()
    return text


#: A character of a rule id that is glob syntax in a suppression's ``rule_id``, as
#: a class matching only itself. fnmatch has no escape character; a class is how a
#: pattern spells one of these literally.
_GLOB_LITERAL = {"[": "[[]", "*": "[*]", "?": "[?]"}


def _suppression_rule_id(rule_id: object) -> str:
    """The suppression ``rule_id`` that names a finding's rule and no other.

    The scan reads the field as a case-insensitive glob (models/core.py's
    ``AshSuppression.matches``, ``fnmatch``), so a rule id written as it is did not
    name itself when it held ``[``, ``*`` or ``?``: ``CKV[1]`` as a pattern matched
    ``CKV1`` and not ``CKV[1]``, and ``rule*`` matched every rule beginning
    ``rule``. Each such character is written as a class holding only itself.
    """
    return "".join(_GLOB_LITERAL.get(char, char) for char in str(rule_id))


def _suppression_for(
    finding: dict, reason: str, expiration: Optional[str] = None
) -> AshSuppression:
    """The entry the suppress dialog saves for *finding*: its rule as a pattern
    naming that rule alone (``_suppression_rule_id``), its file as a pattern
    naming that file alone (``_suppression_path``, which raises
    PathNotExpressible for a file that has none), and the one line it reports as
    both ends of the line range, or no range when it reports none.

    The one place the entry's shape is written: the dialog saves what this
    returns, ``_findings_suppressed_by`` marks what it covers, and
    ``_suppression_scope_note`` describes it, so the three cannot drift apart.
    """
    line = finding.get("line")
    line_number = int(line) if line else None
    return AshSuppression(
        rule_id=_suppression_rule_id(finding["rule_id"]),
        path=_suppression_path(finding["file"]),
        reason=reason,
        expiration=expiration,
        line_start=line_number,
        line_end=line_number,
    )


def _as_scanned(finding: dict) -> Optional[FlatVulnerability]:
    """*finding* as the record a suppression is matched against during a scan,
    or None for a finding that names no file, which no saved entry covers.

    The file is folded as the scan folds it before matching (``_folded_file``).
    A line that is not a number is no line.
    """
    file_value = finding.get("file")
    if not file_value:
        return None
    try:
        line_number = int(finding.get("line"))
    except (TypeError, ValueError):
        line_number = None
    rule_id = finding.get("rule_id")
    return FlatVulnerability(
        id="",
        title="",
        description="",
        severity=str(finding.get("severity") or ""),
        scanner=str(finding.get("scanner") or ""),
        scanner_type="",
        rule_id=None if rule_id is None else str(rule_id),
        file_path=_folded_file(file_value),
        line_start=line_number,
        line_end=line_number,
    )


def _findings_suppressed_by(
    findings: List[dict], suppression: AshSuppression
) -> List[dict]:
    """Every finding of *findings* the scan will suppress with *suppression*,
    decided by the matcher the scan uses (``AshSuppression.matches``) over each
    finding as the scan sees it (``_as_scanned``).

    Matched by key equality on the rule id, the folded file and the line, the
    marking disagreed with the scan: an entry saved for a finding with no line
    covers its rule anywhere in the file, and the scan reads the rule id without
    regard to case, so findings the entry covers stayed Active in the table, and
    the summary's counts wrong, until a rescan.
    """
    covered = []
    for candidate in findings:
        scanned = _as_scanned(candidate)
        if scanned is not None and suppression.matches(scanned):
            covered.append(candidate)
    return covered


def _suppression_scope_note(finding: dict) -> str:
    """What the saved suppression covers, for the dialog: the finding's rule at
    its file, and the one line the finding reports, or the whole file when the
    result reports no line (a region without a startLine, or no region), since an
    entry with no line range applies to that rule anywhere in the file. The test
    is the one ``_suppression_for`` saves by, so the note describes the entry."""
    if not finding.get("line"):
        return (
            "This finding reports no line, so the suppression covers this rule "
            "anywhere in this file. It will be excluded from actionable findings."
        )
    return "This rule and location will be excluded from actionable findings."


def _text(value: object) -> str:
    """*value* as text for the screen, with its terminal controls as escapes.

    For an API that takes a str, which must then be told it is not markup
    (App.notify's markup=False). Everything else gets _shown or _cell.
    """
    return controls_shown(str(value))


def _shown(value: object) -> Content:
    """*value* as Textual content: text, never markup, its controls shown."""
    return Content(_text(value))


def _shown_prose(value: object) -> Content:
    """*value* as Textual content for a prose field, a finding's message: its
    controls shown as escapes, then cut to MESSAGE_CHARS characters, with a
    SNIPPET_TRUNCATED line after the cut when anything was cut.

    Prose wraps, so a line of it has no cap of its own: capped as a snippet is
    (``_capped``), a message written as one paragraph lost everything past its
    first SNIPPET_LINE_CHARS characters while a message of short lines kept
    SNIPPET_LINES of them. And that cut came before the escaping, so a message
    of control characters was drawn as four times the cap, the same shape
    ``_snippet`` escapes first for. The escapes are written here before the cut,
    so the cap bounds what is drawn.
    """
    text = controls_shown(str(value))
    if len(text) > MESSAGE_CHARS:
        text = f"{text[:MESSAGE_CHARS]}\n{SNIPPET_TRUNCATED}"
    return Content(text)


def _shown_one_line(value: object) -> Content:
    """*value* as one line of Textual content: every control as its escape,
    the layout characters included.

    For a one-line widget showing a value inside the module's own words, such
    as the status bar's "Selected: <rule id> ..." line: a newline the value
    carries draws as its escape instead of clipping the rest of the line off
    the widget."""
    return Content(_one_line(value))


def _cell(value: object, *, style: str = "", wrap: bool = False) -> Text:
    """*value* as a table cell. DataTable and Rich's Table read a str cell as
    markup; a Text is drawn as it is."""
    return Text(_text(value), style=style, no_wrap=not wrap, end="")


def _one_line(value: object) -> str:
    """*value*'s text with every control shown, the layout characters included.

    A newline a value carries draws as its escape instead of adding a screen
    line, so a line the layout owns (the location's "line N", a strip's second
    row) cannot be displaced by a value's own text."""
    return controls_shown(str(value), keep_layout=False)


def _named_finding(finding: dict, *, status: bool) -> Content:
    """The finding named on two layout lines: the rule id (with the scanner and
    suppression state when *status*), then its location.

    Each value goes through _one_line, so the one newline here is the layout's
    own. For the selected-finding strip and the suppress dialog, which show one
    line per field row whatever a value holds."""
    first = _one_line(_display_value(finding.get("rule_id")))
    if status:
        state = "Suppressed" if finding.get("suppressed") else "Active"
        first += f"  ·  {_one_line(finding.get('scanner', 'N/A'))}  ·  {state}"
    return Content(
        f"{first}\n"
        f"{_one_line(_display_value(finding.get('file')))}"
        f"  ·  line {_one_line(_display_value(finding.get('line')))}"
    )


def _capped(code: str, line_chars: int = SNIPPET_LINE_CHARS) -> str:
    """*code* cut to SNIPPET_LINES lines of *line_chars* characters, ending with a
    SNIPPET_TRUNCATED line when anything was cut.

    A line ends at ``\\n`` or ``\\r\\n``: counted toward the characters, the ``\\r``
    of a CRLF snippet made a line of exactly the cap read as one over it, and the
    snippet was marked truncated though no visible character was cut. A lone
    ``\\r`` is no line end here, as it is none for the terminal: it stays in the
    text, and ``_snippet`` shows it as its escape.
    """
    lines = code.replace("\r\n", "\n").split("\n", SNIPPET_LINES)
    # The piece after the last split: the rest of the code, or "" when the code
    # ends with the newline that ends line SNIPPET_LINES.
    rest = lines[SNIPPET_LINES:]
    lines = lines[:SNIPPET_LINES]
    cut = rest not in ([], [""])
    for index, line in enumerate(lines):
        if len(line) > line_chars:
            lines[index] = line[:line_chars]
            cut = True
    if cut:
        lines.append(SNIPPET_TRUNCATED)
    elif rest == [""]:
        lines.append("")
    return "\n".join(lines)


def _snippet(
    code: str, lexer: Optional[str], line_chars: int = SNIPPET_LINE_CHARS
) -> Text:
    """A finding's code, highlighted as code: never markdown, so no fence to end.

    A snippet is a scanner's, and minified code reaches it whole, so it is cut to
    the cap (_capped) and highlighted once, here, into a Text: a resize wraps the
    Text again but does not lex it again. As a Syntax, every render lexed and
    wrapped all of it, and a 1 MB line took 36.5 s per resize with no input taken.

    Only its raw controls become escapes. Its backslashes stay as written, so a
    "\\x00" spelled out in the source reads as the source has it. The escapes
    are written before the cut, so the cap bounds what is drawn: cut first, a
    line of 500 control characters was drawn as 2,000 characters of escapes, and
    one of characters beyond U+FFFF as 5,000, which the cap was sized against.

    *line_chars* is the cap on each line, SNIPPET_LINE_CHARS unless the snippet
    was read from a file, where the view's own line numbers are added to it
    (``_excerpt_line_chars``).
    """
    shown = _capped(only_controls_shown(code), line_chars)
    syntax = Syntax(shown, lexer or "text", word_wrap=True, background_color="default")
    # As Syntax renders it: the lexer gets a final newline, and tabs are expanded.
    ends_on_a_newline = shown.endswith("\n")
    text = syntax.highlight(
        (shown if ends_on_a_newline else shown + "\n").expandtabs(syntax.tab_size)
    )
    if not ends_on_a_newline:
        text.remove_suffix("\n")
    return text


class SuppressDialog(ModalScreen[Optional[str]]):
    """Modal dialog for creating a suppression from a finding.

    Dismissed with SAVED when the suppression was written, ALREADY_SUPPRESSED
    when the config file already holds an identical one (nothing is written),
    and None when it was cancelled. When a save fails the dialog stays open
    with the error shown, keeping the input for another try.
    """

    SAVED = "saved"
    ALREADY_SUPPRESSED = "already-suppressed"

    CSS = """
    SuppressDialog {
        align: center middle;
        background: $background 75%;
    }

    #suppress-dialog {
        width: 70;
        max-width: 94%;
        height: 26;
        max-height: 90%;
        background: $surface;
        border: round $border-blurred;
        padding: 1 2;
    }

    #suppress-dialog Label {
        margin: 1 0 0 0;
    }

    #suppress-dialog Input {
        margin: 0 0 1 0;
    }

    #suppression-fields {
        height: 1fr;
        overflow-x: hidden;
    }

    #suppress-dialog .button-row {
        margin: 1 0 0 0;
        height: 3;
        align-horizontal: right;
    }

    #suppression-title {
        color: $primary;
        text-style: bold;
        margin: 0 0 1 0;
    }

    #suppression-error {
        display: none;
        color: $error;
        height: auto;
        margin: 1 0;
    }

    #suppression-destination {
        color: $text-muted;
        height: auto;
        margin: 1 0;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, finding: dict, config_path: Path | None = None):
        super().__init__()
        self.finding = finding
        self.config_path = config_path or Path.cwd() / ASH_DEFAULT_CONFIG_FILE_NAME

    def compose(self) -> ComposeResult:
        with Container(id="suppress-dialog"):
            yield Label("Save a suppression", id="suppression-title")
            with ScrollableContainer(id="suppression-fields"):
                yield Static(
                    _named_finding(self.finding, status=False),
                    id="suppression-finding",
                )
                yield Label("Reason *")
                yield Input(
                    placeholder="Explain why this finding is safe to accept",
                    id="reason_input",
                )
                yield Static("", id="suppression-error", markup=False)
                # The format is in the label, not only the placeholder: a
                # placeholder disappears once the operator types.
                yield Label("Expiration date (optional, YYYY-MM-DD)")
                yield Input(placeholder="YYYY-MM-DD", id="expiration_input")
                yield Static(
                    _cell(
                        f"Save to:\n{self.config_path}\n"
                        f"{_suppression_scope_note(self.finding)}",
                        wrap=True,
                    ),
                    id="suppression-destination",
                )
            with HorizontalGroup(classes="button-row"):
                yield Button("Cancel", variant="default", id="btn_cancel")
                yield Button("Save suppression", variant="primary", id="btn_suppress")

    def on_mount(self) -> None:
        self.query_one("#reason_input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_cancel":
            self.dismiss(None)
            return

        if event.button.id == "btn_suppress":
            reason_input = self.query_one("#reason_input", Input)
            reason = reason_input.value.strip()
            if not reason:
                error = self.query_one("#suppression-error", Static)
                error.update("Add a reason so your team can understand this decision.")
                error.display = True
                reason_input.focus()
                return

            expiration_input = self.query_one("#expiration_input", Input)
            expiration = expiration_input.value.strip() or None

            # The date is checked here, before the model sees it, so a
            # mistyped date reads as the rule (models/core.py's one wording)
            # rather than a pydantic dump flattened into the error field. A
            # date that has been reached is refused too: the entry would stop
            # applying at the start of that day (models/core.py's
            # ``is_expired``), so saving it would write a suppression no scan
            # applies while the table marked the row suppressed.
            if expiration is not None:
                problem = expiration_date_problem(expiration)
                if problem is None and expiration_has_passed(expiration):
                    problem = (
                        "The expiration date has been reached, so this "
                        "suppression would not apply. Use a later date, or "
                        "leave the date empty."
                    )
                if problem is not None:
                    error = self.query_one("#suppression-error", Static)
                    error.update(_shown(problem))
                    error.display = True
                    expiration_input.focus()
                    return

            # A suppression is a rule at a path. A finding with no file was
            # written with the path "*", and one with no rule id with no rule:
            # an entry that never applied to the finding it was saved for and
            # suppressed the rule in every file, or every rule at the path. The
            # path is the file's own pattern (_suppression_path), so the entry
            # matches that file as the scan spells it and no other.
            if not self.finding.get("rule_id"):
                problem = (
                    "This finding reports no rule id, so no suppression names it: "
                    "one saved without a rule would suppress every rule at this "
                    "path. Suppress it in the scanner's own configuration instead."
                )
            elif not self.finding.get("file"):
                problem = (
                    "This finding reports no file, so no suppression names it: "
                    "one saved without a path would suppress this rule in every "
                    "file. Suppress it in the scanner's own configuration instead."
                )
            else:
                problem = None
                try:
                    _suppression_path(self.finding["file"])
                except PathNotExpressible as exc:
                    problem = f"Could not save the suppression. {exc}"
            if problem is not None:
                error = self.query_one("#suppression-error", Static)
                error.update(_shown(problem))
                error.display = True
                return

            try:
                # The rule as a pattern naming this rule alone, the file as the
                # path checked above (_suppression_for).
                suppression = _suppression_for(self.finding, reason, expiration)
                saved = add_suppression_to_config(self.config_path, suppression)
                # The reason the entry carries, so the detail view shows it for
                # the finding it was saved for: read from the results, a finding
                # suppressed in the dialog had none and the view said "Not
                # specified". An identical entry already in the file carries the
                # same reason (add_suppression_to_config's identity).
                self.finding["suppression_reason"] = reason
                self.dismiss(self.SAVED if saved else self.ALREADY_SUPPRESSED)
            except Exception as exc:
                ASH_LOGGER.error(f"Failed to create or write suppression: {exc}")
                error = self.query_one("#suppression-error", Static)
                # error_text, not str(exc): a ValidationError's own text quotes
                # the refused input and pydantic's docs URL, flattened here
                # onto one line.
                error.update(
                    _shown(f"Could not save the suppression. {error_text(exc)}")
                )
                error.display = True
                self.app.notify(
                    "Suppression was not saved. Your input has been kept.",
                    severity="error",
                    timeout=8,
                    markup=False,
                )

    def action_cancel(self) -> None:
        self.dismiss(None)


def _display_value(value) -> str:
    """Render a finding's rule id, file or line, using the module's N/A for a
    missing one.

    Findings come from SARIF results, and a result is not required to have a
    rule id or a location: extract_findings then sets no "file" or "line" key, a
    location without a region leaves "line" unset, and a result without a ruleId
    gives "rule_id" the value None. A dict default does not replace a None that
    is present, so the None was drawn as the word "None" in the table, the
    selected-finding strip, the status bar and the detail view's title.
    """
    if value is None or value == "":
        return "N/A"
    return str(value)


def _summary_line(findings: list) -> Text:
    """The findings-summary line: counts by severity, styled by the theme.

    Built from counts and this module's own words alone - no finding text
    reaches it - and listed with the vetted text builders so the markup guard
    can hold every widget to them.
    """
    summary = Text()
    active = [finding for finding in findings if not finding.get("suppressed")]
    summary.append(f"{len(active)} active", style=f"bold {COLORS['foreground']}")
    for level in ("critical", "high", "medium", "low", "info"):
        count = sum(finding.get("severity", "").lower() == level for finding in active)
        if count:
            summary.append("  ·  ", style=COLORS["muted"])
            summary.append(f"{count} {level}", style=severity_color(level))
    suppressed_count = len(findings) - len(active)
    if suppressed_count:
        summary.append(f"  ·  {suppressed_count} suppressed", style=COLORS["muted"])
    return summary


def _finding_cells(finding: dict, fields: list) -> List[Text]:
    """One table row's cells for *finding*, in *fields* order.

    Each value's text goes through _one_line, so a terminal control, an
    invisible character or a newline in a finding's own text draws as its
    escape; the two-row layout and theming are the redesign's. The newline
    between the title's rows and before "line" is the layout's own, added
    after the values are escaped, and a value cannot add a row of its own.
    """
    is_suppressed = finding.get("suppressed", False)
    color = COLORS["muted"] if is_suppressed else severity_color(finding["severity"])
    title = Text(
        _one_line(_display_value(finding.get("rule_id"))),
        style=COLORS["foreground"],
    )
    title.append(
        "\n" + _one_line(finding.get("message") or ""),
        style=COLORS["muted"],
    )
    title.no_wrap = True
    title.overflow = "ellipsis"
    location = _one_line(_display_value(finding.get("file")))
    if finding.get("line") is not None:
        location += "\nline " + _one_line(finding["line"])
    cells = {
        # The severity is a results file's value like the others, so it goes
        # through _one_line too; only the SUPPRESSED marker is this module's
        # own word.
        "severity": Text(
            "SUPPRESSED" if is_suppressed else _one_line(finding["severity"].upper()),
            style=color,
        ),
        "finding": title,
        "scanner": Text(
            _one_line(finding.get("scanner", "N/A")),
            style=COLORS["muted"],
        ),
        "location": Text(
            location, style=COLORS["muted"], no_wrap=True, overflow="ellipsis"
        ),
    }
    return [cells[field] for field in fields]


def _metadata_table(finding: dict) -> Table:
    """The detail view's finding-context metadata, each value a text cell."""
    table = Table("Key", "Value", show_lines=True, expand=True)
    for key, value in (
        ("Severity", finding["severity"]),
        ("Scanner", finding["scanner"]),
        ("File", _display_value(finding.get("file"))),
        ("Line", _display_value(finding.get("line"))),
    ):
        table.add_row(_cell(key), _cell(value, wrap=True))
    return table


class FindingDetailScreen(Screen):
    """Screen for displaying detailed information about a finding."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("q", "app.pop_screen", "Back"),
    ]

    def __init__(self, finding):
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        # A result without a location has no "file" or "line" key at all.
        file_value = self.finding.get("file")
        snippet_path = Path(file_value) if file_value else None
        file_ext = (
            None
            if snippet_path is None
            else snippet_path.suffix.lstrip(".")
            if snippet_path.suffix != ""
            else snippet_path.name
        )
        if file_ext == "yml":
            file_ext = "yaml"
        yield Header(show_clock=False, icon="A")

        # Each value is the repository's or a scanner's, so the view is built
        # from text widgets, never a Markdown document: a Markdown document
        # leaks even with every markdown character escaped, because escaping
        # does not stop a raw OSC 52 from reaching the render, markdown-it's
        # linkify turns bare URLs into live click actions, and invisible
        # characters draw as nothing. Each value reaches its widget through
        # _shown, _metadata_table or _snippet, with its terminal controls
        # shown as escapes; the section layout and theming are the redesign's.
        with ScrollableContainer(id="finding_details"):
            yield Static(
                _cell(
                    self.finding["severity"].upper(),
                    style=f"bold {severity_color(self.finding['severity'])}",
                ),
                classes="detail-severity",
            )
            # One line: a rule id's own newline would draw a second title line.
            yield Static(
                _shown_one_line(_display_value(self.finding.get("rule_id"))),
                classes="title",
            )
            yield Static("What to review", classes="heading")
            # Capped: a message is a scanner's text too, and a view draws every
            # character of it on each resize (MESSAGE_CHARS).
            yield Static(_shown_prose(self.finding.get("message") or ""))
            yield Static("Finding context", classes="heading")
            yield Static(_metadata_table(self.finding))
            if self.finding.get("suppressed"):
                # `or`: a SARIF suppression's justification can be present and
                # null, which the dict default does not replace.
                reason = self.finding.get("suppression_reason") or "Not specified"
                yield Static("Suppression", classes="heading")
                yield Static(
                    _shown(
                        "This finding is suppressed. Suppression justification: "
                        f"{reason}"
                    )
                )
            if self.finding.get("code_snippet"):
                yield Static("Code", classes="heading")
                read_from = self.finding.get(SNIPPET_READ_FROM)
                if read_from:
                    # The lines are the file's now, not the scan's: an edit since
                    # the scan, or results made at another commit, moves them.
                    yield Static(
                        _shown(
                            f"Read from {read_from} as it is now, which may differ "
                            "from what the scan read."
                        ),
                        classes="notice",
                    )
                yield Static(
                    _snippet(
                        self.finding["code_snippet"],
                        file_ext,
                        self.finding.get(SNIPPET_LINE_CHARS_KEY, SNIPPET_LINE_CHARS),
                    ),
                    classes="code",
                )
            elif file_value:
                yield Static("Code", classes="heading")
                yield Static(_shown(SOURCE_NOT_SHOWN), classes="notice")
        with VerticalGroup(classes="ash-footer"):
            yield Footer(show_command_palette=False)
            yield Static(_shown(FOOTER_CREDIT), classes="footer-credit")


class FindingsExplorerApp(App):
    """Interactive findings explorer application."""

    BINDINGS = [
        # Its own action, not "quit": under the suppress dialog the q key is refused
        # (check_action), and refusing the "quit" action there refused every key
        # bound to it, Textual's own ctrl+q included.
        Binding("q", "quit_from_table", "Quit"),
        Binding("f", "toggle_filters", "Filters"),
        Binding("j", "next_finding", "Next Finding", show=False),
        Binding("k", "previous_finding", "Previous Finding", show=False),
        Binding("v", "view_selected", "Details", show=False),
        Binding("s", "toggle_search", "Search", show=False),
        Binding("/", "toggle_search", "Search"),
        Binding("escape", "exit_search", "Exit Search", show=False),
        Binding("h", "toggle_suppressed", "Suppressed"),
        Binding("r", "reset_filters", "Reset"),
        Binding("x", "suppress_selected", "Suppress"),
    ]

    CSS = """
    Screen {
        background: $background;
        color: $foreground;
    }

    Header {
        background: $surface;
        color: $foreground;
        text-style: bold;
    }

    HeaderIcon {
        display: none;
    }

    Footer {
        background: $surface;
    }

    .ash-footer {
        dock: bottom;
        height: 2;
    }

    .ash-footer Footer {
        dock: none;
        height: 1;
    }

    .footer-credit {
        height: 1;
        content-align: center middle;
        background: $surface;
        color: $text-muted;
    }

    #findings_summary {
        height: auto;
        min-height: 3;
        padding: 1 2;
    }

    .findings-table {
        height: 1fr;
        margin: 0 1;
        border: round $border-blurred;
        background: $background;
    }

    DataTable > .datatable--header {
        background: $surface;
        color: $foreground;
        text-style: bold;
    }

    DataTable > .datatable--cursor {
        background: $primary 25%;
        color: $foreground;
        text-style: none;
    }

    DataTable > .datatable--hover {
        background: $primary 8%;
    }

    #empty_findings {
        display: none;
        height: 1fr;
        margin: 0 1;
        border: round $border-blurred;
        content-align: center middle;
        color: $text-muted;
    }

    #selected_finding {
        height: 3;
        padding: 0 2;
        margin-top: 1;
        color: $text-muted;
    }

    #status_bar {
        height: 1;
        margin: 0 2 1 2;
        color: $text-muted;
    }

    .filters {
        height: 7;
        margin: 0 1 1 1;
        display: none;
        background: $surface;
        border: round $border-blurred;
        padding: 0 1;
    }

    .filters-visible {
        display: block;
    }

    .filters VerticalGroup {
        width: 1fr;
        height: auto;
        margin: 0 1;
    }

    .filters Label {
        margin-top: 1;
        color: $text-muted;
    }

    Select {
        width: 1fr;
        height: 3;
        margin: 0;
    }

    #search_container {
        layout: horizontal;
        height: 3;
        margin: 0 1 1 1;
        background: $surface;
    }

    .search-bar {
        display: none;
    }

    .title {
        text-style: bold;
        color: $primary;
        text-align: center;
        margin: 1 0;
    }

    .heading {
        text-style: bold;
        margin: 1 0 0 0;
    }

    .search-bar-visible {
        display: block;
    }

    #search_container .label {
        width: 9;
        height: 1;
        margin: 1;
        color: $text-muted;
    }

    #search_input {
        width: 1fr;
        height: 3;
    }

    #finding_details {
        height: 1fr;
        margin: 1 2;
        padding: 1 2;
        border: round $border-blurred;
    }

    .detail-severity {
        height: 1;
        margin: 0 0 1 0;
    }

    .error {
        color: $error;
    }
    """

    def __init__(
        self,
        findings,
        title="ASH findings",
        config_path: Path | None = None,
        mask_source: Optional[Callable[[Any, Optional[int], str], str]] = None,
        scan_root: Path | None = None,
    ):
        """*scan_root* is the scanned directory (scanned_directory): the only one a
        finding's file is read from, for a finding the results give no snippet.
        None reads no file."""
        super().__init__()
        # The header draws it as Content, which reads no markup but keeps most
        # controls: _text shows them as escapes.
        self.title = _text(title)
        self.config_path = config_path or Path.cwd() / ASH_DEFAULT_CONFIG_FILE_NAME
        # Masks the lines read from a finding's file when the results hold no
        # snippet for it, as the results' own snippets are masked
        # (utils/secret_masking.source_snippet_masker). findings_command builds it
        # from the results it shows.
        self.mask_source = mask_source
        self.scan_root = scan_root
        self.findings = findings
        self.filtered_findings = findings
        self.current_filter = "all"
        self.severity_filter = "all"
        self.scanner_filter = "all"
        self.suppression_filter = "all"
        self.current_sort = "severity"
        self.show_filters = False  # Hide filters by default
        self.search_mode = False
        self.search_query = ""
        self.sort_reverse = False
        self.sort_column = "Severity"
        self.show_suppressed = False  # Hide suppressed findings by default
        self._table_layout: Optional[tuple] = None
        self._table_fields: list = []
        self._selected_finding = None
        self.sub_title = "Findings explorer"

    def _get_unique_scanners(self) -> list:
        """Get a list of unique scanner names."""
        return sorted({f["scanner"] for f in self.findings if "scanner" in f})

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False, icon="")
        yield Static("", id="findings_summary")

        # Filter container (hidden by default)
        with HorizontalGroup(id="filters_container", classes="filters"):
            with VerticalGroup():
                yield Label("Severity")
                yield Select(
                    name="Severity",
                    options=[
                        ("All", "all"),
                        ("Critical", "severity:critical"),
                        ("High", "severity:high"),
                        ("Medium", "severity:medium"),
                        ("Low", "severity:low"),
                        ("Info", "severity:info"),
                    ],
                    value="all",
                    id="severity_select",
                    prompt="Select severity",
                )

            with VerticalGroup():
                yield Label("Scanner")
                yield Select(
                    name="Scanner",
                    # One line: the option and the select's current label are
                    # each a line high, and a scanner's name is the results'.
                    options=[("All", "all")]
                    + [
                        (_shown_one_line(scanner), f"scanner:{scanner}")
                        for scanner in self._get_unique_scanners()
                    ],
                    value="all",
                    id="scanner_select",
                    prompt="Select scanner",
                )

            with VerticalGroup():
                yield Label("Show")
                yield Select(
                    name="Show",
                    options=[
                        ("All findings", "all"),
                        ("Only active", "not_suppressed"),
                        ("Only suppressed", "suppressed"),
                    ],
                    value="all" if self.show_suppressed else "not_suppressed",
                    id="suppressed_select",
                    prompt="Filter suppressed",
                )

        # Search bar (hidden by default)
        with Container(id="search_container", classes="search-bar"):
            yield Static("Search:", classes="label")
            yield Input(
                placeholder="Type to search... (ESC to exit search)", id="search_input"
            )

        yield DataTable(id="findings_table", classes="findings-table")
        yield Static("", id="empty_findings", markup=False)
        yield Static("", id="selected_finding", markup=False)
        yield Static(
            _shown(
                f"Total findings: {len(self.findings)} | Showing: {len(self.filtered_findings)} | Press s or / to search | f to toggle filters | h to toggle suppressed"
            ),
            id="status_bar",
            markup=False,
        )
        with VerticalGroup(classes="ash-footer"):
            yield Footer(show_command_palette=False, compact=True)
            yield Static(_shown(FOOTER_CREDIT), classes="footer-credit")

    def on_mount(self) -> None:
        """Set up the table when the app is mounted."""
        table = self.query_one("#findings_table", DataTable)
        self.register_theme(textual_theme())
        self.theme = "ash"
        self._configure_table()

        # Enable sorting on columns
        table.cursor_type = "row"
        table.can_focus = True

        self._populate_table()
        table.focus()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        # The app's bindings stay live under a screen it pushed, so under the
        # detail screen and the suppress dialog they are refused: a j or k
        # that reached the hidden table moved its cursor, and the dialog's
        # result then marked the row the cursor had moved to; an x opened a
        # second dialog over the first. Under the dialog q is refused too: a
        # key the operator typed with the Save button focused would otherwise
        # quit the app with the reason they typed. The q key has its own action
        # (quit_from_table) so that only it is refused: check_action sees actions,
        # not keys, and refusing "quit" refused Textual's ctrl+q with it.
        if self.screen_stack and isinstance(
            self.screen, (FindingDetailScreen, SuppressDialog)
        ):
            if action in {
                "toggle_filters",
                "toggle_search",
                "exit_search",
                "toggle_suppressed",
                "reset_filters",
                "view_selected",
                "next_finding",
                "previous_finding",
                "suppress_selected",
            }:
                return False
            if action == "quit_from_table" and isinstance(self.screen, SuppressDialog):
                return False
        return True

    @staticmethod
    def _column_plan(width: int) -> tuple[str, Dict[str, int]]:
        """The layout bucket for a terminal *width*, and each column's width."""
        layout = "wide" if width >= 110 else "standard" if width >= 70 else "compact"
        location_width = min(38, max(22, width // 4))
        # Allow for borders, cell padding, and the vertical scrollbar.
        finding_width = max(20, width - 22)
        if layout != "compact":
            finding_width -= location_width + 2
        if layout == "wide":
            finding_width -= 16
        widths = {"Severity": 10, "Finding": finding_width}
        if layout == "wide":
            widths["Scanner"] = 14
        if layout != "compact":
            widths["Location"] = location_width
        return layout, widths

    def _configure_table(self, width: Optional[int] = None) -> bool:
        """Keep the finding and its severity readable at narrow terminal widths.

        True when the columns were rebuilt, so the caller repopulates the rows.
        A width change inside one layout bucket keeps the columns and the rows
        and fits the column widths in place instead: a terminal drag is a
        stream of Resize events, and rebuilding on each one re-filtered,
        re-sorted and re-added every row (see the resize timings in _snippet
        and SNIPPET_LINES), and wrote over the status bar.
        """
        if width is None:
            width = self.size.width
        layout, widths = self._column_plan(width)
        if self._table_layout == (layout, width):
            return False
        table = self.query_one("#findings_table", DataTable)
        same_bucket = self._table_layout is not None and self._table_layout[0] == layout
        self._table_layout = (layout, width)
        if same_bucket:
            # The bucket holds the same columns: only their widths move.
            # Textual has no column-resize API, so this does what DataTable's
            # own width-changing watchers (watch_cell_padding) do: set the
            # widths, recompute the virtual (scrollable) size, and drop the
            # cached renders.
            for key, column_width in widths.items():
                table.columns[ColumnKey(key)].width = column_width
            data_width = sum(
                column.get_render_width(table) for column in table.columns.values()
            )
            table.virtual_size = Size(
                data_width + table._row_label_column_width,
                table.virtual_size.height,
            )
            table._clear_caches()
            table.refresh(layout=True)
            return False
        table.clear(columns=True)
        self._table_fields = ["severity", "finding"]
        table.add_column("Severity", key="Severity", width=widths["Severity"])
        table.add_column("Finding", key="Finding", width=widths["Finding"])
        if layout == "wide":
            table.add_column("Scanner", key="Scanner", width=widths["Scanner"])
            self._table_fields.append("scanner")
        if layout != "compact":
            table.add_column("Location", key="Location", width=widths["Location"])
            self._table_fields.append("location")
        return True

    def on_resize(self, event: events.Resize) -> None:
        # The event's size, not self.size: when this handler runs, self.size
        # can still hold the previous event's value, which skipped the resize
        # and then applied it one event late.
        if self._table_layout is not None and self._configure_table(event.size.width):
            self._populate_table()

    def _populate_table(self) -> None:
        """Populate the table with findings."""
        table = self.query_one("#findings_table", DataTable)
        table.clear()

        # Apply filtering and sorting
        self._apply_filters()
        self._apply_search()
        self._apply_sorting()

        # Update status bar
        status_bar = self.query_one("#status_bar", Static)
        if self.search_mode:
            status_bar.update(
                _shown_one_line(
                    f"{len(self.filtered_findings)} results for '{self.search_query}' · Esc clears search"
                )
            )
        else:
            suppressed_status = "visible" if self.show_suppressed else "hidden"
            status_bar.update(
                _shown(
                    f"Showing {len(self.filtered_findings)} of {len(self.findings)}"
                    f" · Suppressed {suppressed_status}"
                    " · Enter: details"
                )
            )

        self.query_one("#findings_summary", Static).update(_summary_line(self.findings))

        empty = self.query_one("#empty_findings", Static)
        empty.display = not self.filtered_findings
        table.display = bool(self.filtered_findings)
        if not self.filtered_findings:
            reset_hint = (
                "Press Esc to leave search, then r to reset filters."
                if self.search_mode
                else "Press r to reset filters and search."
            )
            empty.update(
                _shown(
                    f"No findings match this view.\n\n{reset_hint}"
                    if self.findings
                    else "No findings are available in this report.\n\nPress q to return to your terminal."
                )
            )
            self.query_one("#selected_finding", Static).update("")

        # Each cell goes through _finding_cells, which shows every value's
        # controls and invisible characters as escapes.
        for i, finding in enumerate(self.filtered_findings):
            table.add_row(*_finding_cells(finding, self._table_fields), key=i, height=2)

        if self.filtered_findings:
            selected_index = next(
                (
                    index
                    for index, finding in enumerate(self.filtered_findings)
                    if finding is self._selected_finding
                ),
                0,
            )
            table.move_cursor(row=selected_index)
            self._selected_finding = self.filtered_findings[selected_index]

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        index = event.row_key.value
        if not isinstance(index, int) or index >= len(self.filtered_findings):
            return
        finding = self.filtered_findings[index]
        self._selected_finding = finding
        self.query_one("#selected_finding", Static).update(
            _named_finding(finding, status=True)
        )

    def action_next_finding(self) -> None:
        """Select the next finding in the table."""
        table = self.query_one("#findings_table", DataTable)
        if table.row_count > 0:
            # Get current cursor position or default to 0
            current_row = table.cursor_row if table.cursor_row is not None else 0
            next_row = min(current_row + 1, table.row_count - 1)
            table.move_cursor(row=next_row)

            # Update status bar with selected finding info
            if 0 <= next_row < len(self.filtered_findings):
                finding = self.filtered_findings[next_row]
                status_bar = self.query_one("#status_bar", Static)
                status_bar.update(
                    _shown_one_line(
                        f"Selected: {_display_value(finding.get('rule_id'))}"
                        " · Enter: details"
                    )
                )

    def action_quit_from_table(self) -> None:
        """Quit on the q key. The app's own action, refused under the suppress
        dialog (check_action) while Textual's ctrl+q, bound to "quit", stays."""
        self.exit()

    def action_toggle_suppressed(self) -> None:
        """Toggle showing/hiding suppressed findings."""
        self.show_suppressed = not self.show_suppressed

        # Update the suppressed select widget if it exists
        try:
            suppressed_select = self.query_one("#suppressed_select")
            suppressed_select.value = (
                "all" if self.show_suppressed else "not_suppressed"
            )
        except Exception:  # nosec B110 — UI widget query failure is non-critical
            pass

        self._populate_table()

    def action_suppress_selected(self) -> None:
        """Open the suppression dialog for the selected finding."""
        table = self.query_one("#findings_table", DataTable)
        if table.row_count > 0 and table.cursor_row is not None:
            finding_idx = table.cursor_row
            if 0 <= finding_idx < len(self.filtered_findings):
                finding = self.filtered_findings[finding_idx]
                self.push_screen(
                    SuppressDialog(finding, self.config_path),
                    lambda result: self._on_suppress_result(result, finding),
                )

    def _on_suppress_result(
        self, result: Optional[str], finding: Optional[dict] = None
    ) -> None:
        """Handle the result from the suppression dialog.

        *finding* is the one the dialog was opened for, and the one marked
        suppressed, with every other listed finding the saved entry covers too,
        read by the scan's own matcher (``_findings_suppressed_by``). Marking the
        row under the table's cursor instead marked whatever row the cursor had
        moved to while the dialog was open; marking that row alone left the other
        findings the entry covers Active, and the summary's counts wrong, until a
        rescan.
        """
        if result in (SuppressDialog.SAVED, SuppressDialog.ALREADY_SUPPRESSED):
            status_bar = self.query_one("#status_bar", Static)
            if finding is None:
                table = self.query_one("#findings_table", DataTable)
                idx = table.cursor_row
                if idx is not None and idx < len(self.filtered_findings):
                    finding = self.filtered_findings[idx]
            if finding is not None:
                # The entry as the dialog saved it; the reason is the one the
                # dialog kept on the finding. The dialog saved it, so it has a
                # rule, a file and a path pattern.
                saved_entry = _suppression_for(
                    finding, finding.get("suppression_reason") or "Not specified"
                )
                for covered in _findings_suppressed_by(self.findings, saved_entry):
                    covered["suppressed"] = True
                    if "suppression_reason" in finding:
                        covered["suppression_reason"] = finding["suppression_reason"]
                self._populate_table()

            # After the repopulate, which writes the view's counts to the
            # status bar: written before it, the outcome was never seen.
            if result == SuppressDialog.SAVED:
                status_bar.update(
                    _shown_one_line(f"Suppression saved to {self.config_path}")
                )
            else:
                status_bar.update(
                    _shown_one_line(
                        f"Already suppressed: {self.config_path} has an identical "
                        "suppression, so nothing was written"
                    )
                )

    def action_previous_finding(self) -> None:
        """Select the previous finding in the table."""
        table = self.query_one("#findings_table", DataTable)
        if table.row_count > 0:
            # Get current cursor position or default to 0
            current_row = table.cursor_row if table.cursor_row is not None else 0
            prev_row = max(current_row - 1, 0)
            table.move_cursor(row=prev_row)

            # Update status bar with selected finding info
            if 0 <= prev_row < len(self.filtered_findings):
                finding = self.filtered_findings[prev_row]
                status_bar = self.query_one("#status_bar", Static)
                status_bar.update(
                    _shown_one_line(
                        f"Selected: {_display_value(finding.get('rule_id'))}"
                        " · Enter: details"
                    )
                )

    def action_view_selected(self) -> None:
        """View the currently selected finding."""
        table = self.query_one("#findings_table", DataTable)
        if table.row_count > 0 and table.cursor_row is not None:
            finding_idx = table.cursor_row
            if 0 <= finding_idx < len(self.filtered_findings):
                self._show_detail(self.filtered_findings[finding_idx])

    def on_data_table_row_selected(self, event) -> None:
        """Handle row selection in the findings table.

        The row key is checked as on_data_table_row_highlighted checks it: a key
        that is no row of the current list (the table is repopulated while a
        selection event is in flight) is no finding to show.
        """
        index = event.row_key.value
        if not isinstance(index, int) or not 0 <= index < len(self.filtered_findings):
            return
        self._show_detail(self.filtered_findings[index])

    def _show_detail(self, finding: dict) -> None:
        """Open *finding*'s detail view, with the lines around it from its file when
        the results hold no snippet and the file is one the TUI reads.

        The lines come from disk, not from the masked results, so they are masked
        as the results' own snippets are (``mask_source``) before they are shown;
        a line a secret finding reports is replaced whole, its display prefix
        included. The finding records where the lines came from
        (SNIPPET_READ_FROM) and the width of each shown line (SNIPPET_LINE_CHARS_KEY)
        for the detail view.

        The width is read from the excerpt as read, before the masking: measured
        after it, a masked first line, which has no number or marker, read as a
        prefix of its whole length, and every line of the excerpt was allowed
        that many characters more than the cap. The path the view names is the
        file as the results record it, under the scanned directory; the file is
        opened by the name read back from its record form (``_source_path``)."""
        if not finding.get("code_snippet"):
            try:
                line_number = int(finding["line"])
            except (KeyError, TypeError, ValueError):
                line_number = None
            window = (
                max(1, line_number - _CONTEXT_LINES)
                if line_number is not None
                else None
            )
            # A key block is found from its BEGIN line. When a secret finding
            # reports a line above the window, the lines are read from there, so
            # a finding deep in a key body is masked as the block it is in, and
            # the lines above the window are cut off after the masking.
            earliest = getattr(self.mask_source, "earliest_reported_line", None)
            read_from = (
                earliest(finding.get("file"), window)
                if callable(earliest) and window is not None
                else None
            )
            if not isinstance(read_from, int):
                read_from = None
            excerpt = _source_excerpt(finding, self.scan_root, read_from)
            if excerpt is not None:
                line_chars = _excerpt_line_chars(excerpt)
                if self.mask_source is not None:
                    first = (
                        _excerpt_start(line_number, read_from)
                        if line_number is not None
                        else None
                    )
                    excerpt = self.mask_source(finding.get("file"), first, excerpt)
                    if first is not None and window is not None:
                        excerpt = _drop_lines_before(excerpt, window - first)
                # Cut after the masking, so a value that straddles the cap is
                # masked whole (_line_text).
                finding["code_snippet"] = _cut_excerpt_lines(excerpt)
                finding[SNIPPET_LINE_CHARS_KEY] = line_chars
                # The file as the results record it, under the scanned directory:
                # the spelling the table and the results file show. The path the
                # file was OPENED by holds the name read back from its record form
                # (_source_path), and shown it drew that name's escape where the
                # results spell the six characters of the record form.
                if self.scan_root is not None:
                    finding[SNIPPET_READ_FROM] = str(
                        self.scan_root / str(finding.get("file"))
                    )
        self.push_screen(FindingDetailScreen(finding))

    def on_select_changed(self, event) -> None:
        """Handle changes to filter or sort selects."""
        if event.select.id == "severity_select":
            self.current_filter = event.value
            self.severity_filter = event.value
            self._populate_table()
        elif event.select.id == "scanner_select":
            self.current_filter = event.value
            self.scanner_filter = event.value
            self._populate_table()
        elif event.select.id == "suppressed_select":
            self.suppression_filter = event.value
            if self.current_filter in ("suppressed", "not_suppressed"):
                self.current_filter = "all"
            if event.value == "all":
                self.show_suppressed = True
            elif event.value == "not_suppressed":
                self.show_suppressed = False
            elif event.value == "suppressed":
                self.show_suppressed = True
                self.current_filter = "suppressed"
            self._populate_table()

    def action_reset_filters(self) -> None:
        """Restore the active findings view without leaving the explorer."""
        self.current_filter = "all"
        self.severity_filter = "all"
        self.scanner_filter = "all"
        self.suppression_filter = "all"
        self.show_suppressed = False
        self.search_query = ""
        self.query_one("#search_input", Input).value = ""
        self.query_one("#severity_select", Select).value = "all"
        self.query_one("#scanner_select", Select).value = "all"
        self.query_one("#suppressed_select", Select).value = "not_suppressed"
        self._populate_table()
        self.query_one("#findings_table", DataTable).focus()

    def action_toggle_filters(self) -> None:
        """Toggle the visibility of filters."""
        self.show_filters = not self.show_filters
        filters = self.query_one("#filters_container")

        if self.show_filters:
            filters.add_class("filters-visible")

            # Update status bar
            status_bar = self.query_one("#status_bar", Static)
            status_bar.update("Filters visible | Press 'f' to hide filters")
        else:
            filters.remove_class("filters-visible")

            # Update status bar
            self._populate_table()  # This will update the status bar

    def action_toggle_search(self) -> None:
        """Toggle search mode."""
        self.search_mode = not self.search_mode
        search_container = self.query_one("#search_container")

        if self.search_mode:
            # Show search bar and focus it
            search_container.remove_class("search-bar")
            search_container.add_class("search-bar-visible")
            search_input = self.query_one("#search_input", Input)
            search_input.focus()

            # Update status bar
            status_bar = self.query_one("#status_bar", Static)
            status_bar.update("SEARCH MODE: Type to filter | Press ESC to exit search")
        else:
            # Hide search bar and clear search
            search_container.remove_class("search-bar-visible")
            search_container.add_class("search-bar")
            self.search_query = ""
            self.query_one("#search_input", Input).value = ""
            self._populate_table()

            # Return focus to table
            table = self.query_one("#findings_table", DataTable)
            table.focus()

    def action_exit_search(self) -> None:
        """Exit search mode."""
        if self.search_mode:
            self.search_mode = False
            search_container = self.query_one("#search_container")
            search_container.remove_class("search-bar-visible")
            search_container.add_class("search-bar")

            # Clear search if ESC is pressed
            self.search_query = ""
            self.query_one("#search_input", Input).value = ""
            self._populate_table()

            # Return focus to table
            table = self.query_one("#findings_table", DataTable)
            table.focus()

    def _apply_filters(self) -> None:
        """Apply filters to the findings."""
        # First, filter by suppressed status
        if not self.show_suppressed:
            self.filtered_findings = [
                f for f in self.findings if not f.get("suppressed")
            ]
        else:
            self.filtered_findings = list(self.findings)

        # Severity, scanner, and suppression criteria compose instead of replacing
        # one another. current_filter remains available to programmatic callers.
        for criterion in {
            self.current_filter,
            self.severity_filter,
            self.scanner_filter,
            self.suppression_filter,
        }:
            if not isinstance(criterion, str) or criterion == "all":
                continue
            if criterion == "suppressed":
                self.filtered_findings = [
                    f for f in self.filtered_findings if f.get("suppressed")
                ]
            elif criterion == "not_suppressed":
                self.filtered_findings = [
                    f for f in self.filtered_findings if not f.get("suppressed")
                ]
            elif ":" in criterion:
                filter_type, filter_value = criterion.split(":", 1)
                if filter_type in ("severity", "scanner"):
                    self.filtered_findings = [
                        f
                        for f in self.filtered_findings
                        if f.get(filter_type) == filter_value
                    ]

    def _apply_sorting(self) -> None:
        """Sort the filtered findings."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        if self.current_sort == "severity":
            self.filtered_findings.sort(
                key=lambda f: severity_order.get(f["severity"], 5),
                reverse=self.sort_reverse,
            )
        elif self.current_sort == "file":
            self.filtered_findings.sort(
                key=lambda f: f.get("file") or "", reverse=self.sort_reverse
            )
        elif self.current_sort == "scanner":
            self.filtered_findings.sort(
                key=lambda f: f.get("scanner", ""), reverse=self.sort_reverse
            )
        elif self.current_sort == "line":
            self.filtered_findings.sort(
                key=lambda f: (
                    int(f.get("line", 0))
                    if f.get("line") and str(f.get("line")).isdigit()
                    else 0
                ),
                reverse=self.sort_reverse,
            )
        # `or ""` on both: a None rule id or message text (see _apply_search)
        # cannot be ordered against a str, and the sort raised TypeError.
        elif self.current_sort == "message":
            self.filtered_findings.sort(
                key=lambda f: f.get("message") or "", reverse=self.sort_reverse
            )
        elif self.current_sort == "rule_id":
            self.filtered_findings.sort(
                key=lambda f: f.get("rule_id") or "", reverse=self.sort_reverse
            )

    def _apply_search(self) -> None:
        """Apply search filter to the findings."""
        if not self.search_query:
            return

        # Each field `or ""`: a result without a ruleId, or whose message has no
        # text, gives the finding a None there (extract_findings), which the
        # dict default does not replace, and .lower() on it ended the explorer.
        # The line is searched as its digits or not at all: str(None) is "None",
        # so a search for "n", "no" or "none" matched every finding without a line.
        search_term = self.search_query.lower()
        self.filtered_findings = [
            f
            for f in self.filtered_findings
            if (
                search_term in (f.get("message") or "").lower()
                or search_term in (f.get("rule_id") or "").lower()
                or search_term in (f.get("file") or "").lower()
                or search_term in (f.get("scanner") or "").lower()
                or search_term
                in ("" if f.get("line") is None else str(f["line"])).lower()
            )
        ]

    def on_input_changed(self, event) -> None:
        """Handle changes to the search input."""
        if event.input.id == "search_input":
            self.search_query = event.value
            self._populate_table()

    def on_data_table_header_selected(self, event) -> None:
        """Handle column header selection for sorting."""
        # In Textual 3.2.0, the event already contains the label
        # Convert the Text object to a string
        column_name = str(event.label)

        # Toggle sort direction if clicking the same column
        if self.sort_column == column_name:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column_name
            self.sort_reverse = False

        # Map column name to sort key
        column_to_sort = {
            "Severity": "severity",
            "Scanner": "scanner",
            "File": "file",
            "Line": "line",
            "Message": "message",
            "Finding": "message",
            "Location": "file",
            "Rule ID": "rule_id",
        }.get(column_name, "severity")

        self.current_sort = column_to_sort
        self._populate_table()


def _first_code_flow_snippet(result: Result) -> Optional[str]:
    """The text of the first snippet a location of one of *result*'s code flows
    carries, in order, or None.

    A location's physicalLocation is the schema's RootModel; the region is on
    its root. Asked of the wrapper, every code flow had no region.
    """
    for code_flow in result.codeFlows or []:
        for thread_flow in code_flow.threadFlows:
            for flow_location in thread_flow.locations:
                location = flow_location.location
                physical = location.physicalLocation if location else None
                region = physical.root.region if physical else None
                if region and region.snippet and region.snippet.text is not None:
                    return region.snippet.text
    return None


def _scanner_name(result: Result) -> str:
    """The scanner shown for *result*: ``properties.scanner_name``, then
    ``properties.scanner_details.tool_name``, then "unknown".

    properties is optional in SARIF and its values are the results file's
    own: ``scanner_details`` can be present as an explicit null or as
    something other than a mapping, and reading ``tool_name`` from either
    raised AttributeError, which findings_command turned into "Error loading
    model or report" for the whole explorer. The dump also ran twice per
    result; once is enough.
    """
    if not result.properties:
        return "unknown"
    properties = result.properties.model_dump(by_alias=True)
    details = properties.get("scanner_details")
    tool_name = details.get("tool_name") if isinstance(details, dict) else None
    # A name is text. A scanner_name or tool_name of another shape (a list, a
    # mapping, a number) is the results file's own and names no scanner; returned
    # as it was, it was put in a set (unhashable) and sorted against the other
    # names (TypeError), which ended the explorer at start or on a sort.
    scanner_name = properties.get("scanner_name")
    if not isinstance(scanner_name, str):
        scanner_name = None
    if not isinstance(tool_name, str):
        tool_name = None
    return scanner_name or tool_name or "unknown"


def _applies(suppression: Any) -> bool:
    """Whether a SARIF suppression suppresses its result: one whose ``state`` is
    ``rejected`` or ``underReview`` does not (SARIF 2.1.0, 3.35.3), and one with
    no state, or ``accepted``, does. ``bool(result.suppressions)`` counted every
    entry, so a result whose suppressions were all rejected or under review was
    shown suppressed and hidden from the default view."""
    state = getattr(suppression, "state", None)
    return getattr(state, "value", state) not in ("rejected", "underReview")


def extract_findings(model: AshAggregatedResults) -> List[Dict[str, Any]]:
    """Extract findings from the AshAggregatedResults."""
    findings: List[Dict[str, Any]] = []

    # Extract findings from SARIF reports
    if model.sarif and model.sarif.runs:
        for run in model.sarif.runs:
            if run.results:
                result: Result
                for result in run.results:
                    # Extract basic info
                    finding: Dict[str, Any] = {
                        # 0 is the first rule in the driver's rules array, not a
                        # missing index; `or -1` turned it into -1.
                        "id": (
                            result.ruleIndex if result.ruleIndex is not None else -1
                        ),
                        "rule_id": result.ruleId,
                        # `or ""`: a message given by id alone has a root with a
                        # None text, which the table drew as the word "None".
                        "message": (
                            (result.message.root.text or "")
                            if result.message.root
                            else ""
                        ),
                        "level": result.level,
                        "kind": result.kind,
                        # The gate's reading, so a finding inspect shows as
                        # high is not one the scan failed as critical.
                        "severity": result_severity(result).lower(),
                        # The scanner's own name is preferred;
                        # scanner_details' tool_name is the fallback
                        # (_scanner_name).
                        "scanner": _scanner_name(result),
                    }

                    # Suppressed by the entries that apply (_applies), whose first
                    # justification is shown. `or "Not specified"`: a justification
                    # can be present and null, and the detail view's dict default
                    # does not replace a None that is there.
                    applying = [
                        suppression
                        for suppression in (getattr(result, "suppressions", None) or [])
                        if _applies(suppression)
                    ]
                    finding["suppressed"] = bool(applying)
                    if applying:
                        finding["suppression_reason"] = (
                            getattr(applying[0], "justification", None)
                            or "Not specified"
                        )

                    # Extract location info
                    if result.locations:
                        for location in result.locations:
                            if (
                                location.physicalLocation
                                and location.physicalLocation.root.artifactLocation
                            ):
                                finding["file"] = (
                                    location.physicalLocation.root.artifactLocation.uri
                                )
                                if location.physicalLocation.root.region:
                                    finding["line"] = (
                                        location.physicalLocation.root.region.startLine
                                    )
                                    finding["column"] = (
                                        location.physicalLocation.root.region.startColumn
                                    )

                                    # Extract code snippet if available in SARIF
                                    if location.physicalLocation.root.region.snippet:
                                        finding["code_snippet"] = (
                                            location.physicalLocation.root.region.snippet.text
                                        )
                                break

                    # If no snippet was found in locations, try to extract from codeFlows if available
                    # codeFlows is always an attribute of Result, so hasattr() said
                    # nothing; an explicit `"codeFlows": null` made it None and the
                    # loop raised TypeError.
                    if not finding.get("code_snippet") and result.codeFlows:
                        snippet = _first_code_flow_snippet(result)
                        if snippet is not None:
                            finding["code_snippet"] = snippet

                    findings.append(finding)

    return findings


def map_level_to_severity(level):
    """Map a SARIF level alone to a severity, as the gate does (error is critical).

    For a whole result, use ``result_severity``, which honors
    ``properties.issue_severity`` first.
    """
    return result_severity({"level": level}).lower()


def _resolve_suppression_config_path(
    config: Path | None = None, search_dir: Path | None = None
) -> Path:
    """Return the config file that should receive new suppressions.

    *config* when given; else the config a scan of *search_dir* reads
    (``find_config_file``), else a new default file there. *search_dir* is the
    scanned directory when the results' layout names one (``scanned_directory``),
    and the current directory otherwise: found from the current directory, a
    suppression saved while inspecting another project's results went to a config
    the next scan of that project never read.

    A discovery that fails (a config directory that cannot be read, a pyproject
    that does not parse) is reported and the default path is used, so the
    explorer still opens: raised, it was reported as "Error loading model or
    report", a problem with the results the results did not have.
    """
    if config:
        return config
    if search_dir is None:
        search_dir = Path.cwd()
    try:
        found = find_config_file(search_dir)
    except (ASHConfigSourceError, OSError) as exc:
        secho(
            f"Could not find a config file for suppressions in {search_dir}: "
            f"{error_text(exc)}. Suppressions saved here go to "
            f"{search_dir / ASH_DEFAULT_CONFIG_FILE_NAME}.",
            fg="yellow",
            err=True,
        )
        found = None
    return found or search_dir / ASH_DEFAULT_CONFIG_FILE_NAME


def findings_command(
    output_dir: Path = typer.Option(
        None,
        help="Path to the output directory containing an ASH Aggregated Results JSON report file to analyze.",
    ),
    report_file: str = typer.Option(
        "ash_aggregated_results.json",
        help="Name of the report file to analyze. Defaults to 'ash_aggregated_results.json'.",
    ),
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help=(
                "Path to the configuration file where suppressions should be "
                f"saved. By default, ASH searches for {ASH_CONFIG_SOURCES_DESCRIPTION} "
                "in the scanned directory (the one holding the results' "
                ".ash/ash_output), or in the current directory when the results "
                f"sit elsewhere. With none found, suppressions go to a new "
                f"{ASH_DEFAULT_CONFIG_FILE_NAME} there."
            ),
            envvar="ASH_CONFIG",
        ),
    ] = None,
):
    """Interactively explore security findings.

    A finding's code is the code snippet the results hold, wherever the results
    file is. For a finding with none, its lines are read from its file only when
    the results file sits in <root>/.ash/ash_output, and only from a regular file
    inside <root> (a hard link inside the tree counts as a file in it, as it does
    for the scanners); otherwise the detail view says "(source not shown)".

    Exits 1 when there are no results to show or they do not load: the command
    produced no view, as a scan that produced no results exits 1, and a pipeline
    reading 0 would take the missing report for an inspected one.
    """
    # Try to load the model from the output directory
    try:
        # Resolve cwd-based default at call time (not import time).
        if output_dir is None:
            output_dir = Path.cwd().joinpath(".ash", "ash_output")

        output_dir_path = Path(output_dir)

        # Search multiple candidate paths for the report file
        candidate_paths = [
            output_dir_path.joinpath(".ash", "ash_output", report_file),
            output_dir_path.joinpath("ash_output", report_file),
            output_dir_path.joinpath(report_file),
        ]

        report_file_actual = None
        for candidate in candidate_paths:
            if candidate.exists():
                report_file_actual = candidate
                break

        if report_file_actual is None:
            echo(
                "No model or report file available. Please run a scan first or provide a report file."
            )
            raise typer.Exit(1)

        model = AshAggregatedResults.load_model(Path(report_file_actual))
        if model is None:
            echo(
                "No model or report file available. Please run a scan first or provide a report file."
            )
            raise typer.Exit(1)

        # Extract findings from the model
        findings = extract_findings(model)

        if not findings:
            echo("No findings to display.")
            return

        scan_root = scanned_directory(report_file_actual)
        config_path = _resolve_suppression_config_path(config, scan_root)

        # Launch the Textual app
        app = FindingsExplorerApp(
            findings,
            config_path=config_path,
            mask_source=source_snippet_masker(model),
            scan_root=scan_root,
        )
        app.run()
    except typer.Exit:
        raise
    except Exception as e:
        # A record that does not load is described by field, not by its input
        # (utils/error_text.py).
        secho(f"Error loading model or report: {error_text(e)}", fg="red")
        raise typer.Exit(1) from None
