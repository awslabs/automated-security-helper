"""Own a region of a hand-written Markdown file.

A page written by hand gives one table, list or sentence to a generator by putting two
marker lines around the region, each alone on its line and starting in the first
column::

    <!-- BEGIN generated: support/modes (scripts/generate_support_matrices.py) -->
    ...whatever the generator renders...
    <!-- END generated: support/modes -->

The name (``support/modes``) identifies the block in its file; the parenthesis names the
script that writes it. Everything outside a pair of markers is hand-written and is never
changed, byte for byte. This module only fills markers that are already in the file; it
never adds one.

A generator calls ``write_blocks`` to rewrite its blocks and ``check_blocks`` to find
the ones that drifted::

    bodies = {"support/modes": ["| Mode | Runs |", "| --- | --- |", ...]}
    write_blocks(REPO_ROOT, "README.md", bodies, "scripts/generate_x.py")
    drifts = check_blocks(REPO_ROOT, "README.md", bodies, "scripts/generate_x.py")

What it refuses, each time with a ``MarkerError`` that names the file and the block, and
before it writes anything:

- a block with no begin or no end marker, a repeated begin or end for one name, an end
  before its begin, blocks nested in one another, an end with no begin (an orphan), and
  a begin whose end names another block. The whole file is read, so a broken block that
  belongs to another generator refuses a write of a healthy one too;
- a begin marker that names a different generator than the caller;
- a line that starts like a marker and is not one (a missing generator, a lower-case
  word, an indented marker): a typo is an error, never a block that quietly goes
  missing;
- CRLF or any carriage return, in the file or in a body. Files are written with LF only
  and never converted;
- a body that holds ``{{VERSION}}`` or ``{{RELEASE}}``, a marker of its own, or a code
  fence it leaves open.

A marker inside a fenced code block is text, not a marker, so a page can show an example
of one. The fence rule is the one ``scripts/docs_checks.py`` applies to the same pages.

A page that is rendered from a template (README.md from README.md.template, by
``scripts/version_template_manager.py``) is one unit with it: ``write_blocks`` and
``check_blocks`` take either file and handle both, with identical block bytes. The
manager renders the two placeholders and nothing else, so a body free of them keeps
``render(template) == page`` true. Both files are checked before either is written.

``check_blocks`` returns one ``Drift`` per block that differs from its body, with a
unified diff that names the block, and writes nothing. A second ``write_blocks`` reports
``unchanged`` and does not touch the file.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "PLACEHOLDERS",
    "TEMPLATE_SUFFIX",
    "UNCHANGED",
    "WRITTEN",
    "Body",
    "Drift",
    "GeneratedBlock",
    "MarkerError",
    "WriteResult",
    "begin_marker",
    "check_blocks",
    "diff_blocks",
    "end_marker",
    "parse_blocks",
    "replace_blocks",
    "twin_files",
    "write_blocks",
]

#: What a template carries where the page rendered from it carries the release number.
#: scripts/version_template_manager.py renders exactly these two and nothing else, so a
#: body free of them is the same bytes in a template and in its page. They are written
#: out here, not imported, so this module needs only the standard library;
#: tests/unit/test_generated_blocks.py fails if the manager's pair ever changes.
PLACEHOLDERS = ("{{VERSION}}", "{{RELEASE}}")
#: A page rendered from a template sits beside it as ``<page>.template``.
TEMPLATE_SUFFIX = ".template"
#: ``WriteResult.status`` for a file this call rewrote, and for one it left alone.
WRITTEN = "written"
UNCHANGED = "unchanged"

#: What a generator hands over for one block: the lines, or the text of them.
Body = str | Sequence[str]

_NAME = r"[A-Za-z0-9][A-Za-z0-9._/-]*"
_NAME_RULE = "starts with a letter or digit and holds only letters, digits and . _ / -"
_GENERATOR = r"[^\s()]+"
_NAME_RE = re.compile(_NAME)
_GENERATOR_RE = re.compile(_GENERATOR)
_BEGIN = re.compile(
    rf"<!-- BEGIN generated: (?P<name>{_NAME}) \((?P<generator>{_GENERATOR})\) -->"
)
_END = re.compile(rf"<!-- END generated: (?P<name>{_NAME}) -->")
_BEGIN_SHAPE = "<!-- BEGIN generated: <name> (<generator>) -->"
_END_SHAPE = "<!-- END generated: <name> -->"
#: A line that starts like a marker. Either it is one, or it is a near miss, which is an
#: error: a block whose marker has a typo would otherwise go missing without a word.
_LOOKS_LIKE_MARKER = re.compile(r"\s*<!--\s*(?:BEGIN|END)\s+generated\b", re.IGNORECASE)
#: The opening of a fenced code block, as scripts/docs_checks.py reads it (_FENCE_OPEN
#: there): three or more backticks or tildes, any indent, and for backticks an info
#: string with no backtick in it.
_FENCE_OPEN = re.compile(r"(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,})(?P<info>.*)")


class MarkerError(Exception):
    """A block cannot be read or written; the message names the file and the block.

    ``file`` is the path as the caller gave it. ``block`` is the block's name, several
    names joined with ``, `` when the problem is the whole request's, or None when no
    block is involved. ``reason`` says what is wrong.
    """

    def __init__(self, file: str, block: str | None, reason: str) -> None:
        self.file = file
        self.block = block
        self.reason = reason
        where = file if block is None else f"{file}: block `{block}`"
        super().__init__(f"{where}: {reason}")


@dataclass(frozen=True)
class GeneratedBlock:
    """One marked region of a file, as found.

    ``begin`` and ``end`` are the indexes of the two marker lines in
    ``text.split("\\n")``; ``body`` is the lines between them.
    """

    name: str
    generator: str
    begin: int
    end: int
    body: tuple[str, ...]


@dataclass(frozen=True)
class Drift:
    """A block whose lines differ from what the generator renders, with the diff."""

    file: str
    block: str
    diff: str


@dataclass(frozen=True)
class WriteResult:
    """What a write did to one file: ``status`` is WRITTEN or UNCHANGED, and
    ``blocks`` names the blocks whose lines changed (none when unchanged)."""

    file: str
    status: str
    blocks: tuple[str, ...]


def _require_name(name: str) -> None:
    if not _NAME_RE.fullmatch(name):
        raise ValueError(f"{name!r} is not a valid block name: a name {_NAME_RULE}")


def _require_generator(generator: str) -> None:
    if not _GENERATOR_RE.fullmatch(generator):
        raise ValueError(
            f"generator {generator!r} must be the script's path: one word with no "
            "whitespace or parentheses"
        )


def begin_marker(name: str, generator: str) -> str:
    """The begin marker line of block ``name``, written by ``generator``."""
    _require_generator(generator)
    _require_name(name)
    return f"<!-- BEGIN generated: {name} ({generator}) -->"


def end_marker(name: str) -> str:
    """The end marker line of block ``name``."""
    _require_name(name)
    return f"<!-- END generated: {name} -->"


# --- reading a file ---------------------------------------------------------------


@dataclass(frozen=True)
class _Marker:
    kind: str  # "begin" or "end"
    name: str
    generator: str  # of a begin marker; empty for an end marker
    index: int


def _fence_opened_by(line: str) -> str | None:
    """The fence ``line`` opens (three or more backticks or tildes), else None."""
    opened = _FENCE_OPEN.fullmatch(line)
    if opened is None:
        return None
    if opened["fence"][0] == "`" and "`" in opened["info"]:
        return None
    return opened["fence"]


def _fence_closed_by(line: str, fence: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(fence[0] * len(fence)) and set(stripped) == {fence[0]}


def _markers(
    lines: Sequence[str], file: str, block: str | None, label: str
) -> tuple[list[_Marker], int | None]:
    """Every marker line outside a code fence, and the line a fence is left open at.

    A line that starts like a marker and is not one raises MarkerError; ``label`` says
    which kind of line it is in the message ("line" of a file, "body line" of a body).
    """
    found: list[_Marker] = []
    fence = ""
    fence_line = 0
    for index, line in enumerate(lines):
        if fence:
            if _fence_closed_by(line, fence):
                fence = ""
            continue
        opened = _fence_opened_by(line)
        if opened is not None:
            fence, fence_line = opened, index + 1
            continue
        text = line.rstrip()
        begin = _BEGIN.fullmatch(text)
        end = _END.fullmatch(text)
        if begin is not None:
            found.append(_Marker("begin", begin["name"], begin["generator"], index))
        elif end is not None:
            found.append(_Marker("end", end["name"], "", index))
        elif _LOOKS_LIKE_MARKER.match(line):
            raise MarkerError(
                file,
                block,
                f"{label} {index + 1} looks like a generated-block marker but is not "
                f"one: `{line.strip()}`; a marker is exactly `{_BEGIN_SHAPE}` or "
                f"`{_END_SHAPE}`, alone on its line and starting in its first column",
            )
    return found, (fence_line if fence else None)


def _fence_hint(unclosed: int | None) -> str:
    """What to add to a message about a missing marker when a fence hid the rest."""
    if unclosed is None:
        return ""
    return (
        f"; the file ends inside the code fence opened at line {unclosed}, and a "
        "marker inside a code fence is text, not a marker"
    )


def _pair(
    markers: Sequence[_Marker], lines: Sequence[str], file: str, unclosed: int | None
) -> list[GeneratedBlock]:
    """The blocks the markers make, in file order; refuse the first thing wrong."""
    first_begin: dict[str, _Marker] = {}
    for marker in markers:
        if marker.kind == "begin":
            first_begin.setdefault(marker.name, marker)
    seen_begin: dict[str, _Marker] = {}
    seen_end: dict[str, _Marker] = {}
    blocks: list[GeneratedBlock] = []
    opened: _Marker | None = None
    for marker in markers:
        line = marker.index + 1
        name = marker.name
        if marker.kind == "begin":
            if name in seen_begin:
                raise MarkerError(
                    file,
                    name,
                    f"the begin marker is repeated (lines {seen_begin[name].index + 1} "
                    f"and {line}); a block has exactly one begin and one end",
                )
            if opened is not None:
                raise MarkerError(
                    file,
                    name,
                    f"begins at line {line} inside block `{opened.name}` (begun at "
                    f"line {opened.index + 1}); blocks do not nest",
                )
            seen_begin[name] = marker
            opened = marker
            continue
        if name in seen_end:
            raise MarkerError(
                file,
                name,
                f"the end marker is repeated (lines {seen_end[name].index + 1} and "
                f"{line}); a block has exactly one begin and one end",
            )
        if opened is None:
            if name in first_begin:
                raise MarkerError(
                    file,
                    name,
                    f"the end marker at line {line} comes before the begin marker at "
                    f"line {first_begin[name].index + 1}",
                )
            raise MarkerError(
                file, name, f"the end marker at line {line} has no begin marker"
            )
        if opened.name != name:
            raise MarkerError(
                file,
                opened.name,
                f"the begin marker at line {opened.index + 1} is closed at line "
                f"{line} by the end marker of block `{name}`",
            )
        seen_end[name] = marker
        body = tuple(lines[opened.index + 1 : marker.index])
        blocks.append(
            GeneratedBlock(name, opened.generator, opened.index, marker.index, body)
        )
        opened = None
    if opened is not None:
        raise MarkerError(
            file,
            opened.name,
            f"the begin marker at line {opened.index + 1} has no end marker"
            + _fence_hint(unclosed),
        )
    return blocks


@dataclass(frozen=True)
class _Scan:
    lines: list[str]
    blocks: list[GeneratedBlock]
    unclosed_fence: int | None


def _names(names: Sequence[str]) -> str | None:
    return ", ".join(names) or None


def _scan(text: str, file: str, requested: Sequence[str] = ()) -> _Scan:
    """Read every block of ``text``; refuse CR and a bad pair of markers."""
    if "\r" in text:
        line = text.count("\n", 0, text.index("\r")) + 1
        raise MarkerError(
            file,
            _names(requested),
            f"line {line} holds a carriage return; generated blocks are LF only, so "
            "the file is refused and not converted",
        )
    lines = text.split("\n")
    markers, unclosed = _markers(lines, file, None, "line")
    return _Scan(lines, _pair(markers, lines, file, unclosed), unclosed)


def parse_blocks(text: str, file: str) -> list[GeneratedBlock]:
    """Every block in ``text``, in file order, whichever generator owns it.

    The same refusals as a write, for the whole file; ``file`` only labels them.
    """
    return _scan(text, file).blocks


# --- the text a generator hands over ----------------------------------------------


def _body_lines(file: str, name: str, body: Body) -> list[str]:
    """``body`` as lines, or a MarkerError when it is not fit to be written.

    A string is its lines joined with ``\\n``, with one trailing ``\\n`` ignored.
    """
    if isinstance(body, str):
        text = body[:-1] if body.endswith("\n") else body
        lines = text.split("\n") if body else []
    else:
        lines = list(body)
    for number, line in enumerate(lines, start=1):
        if "\n" in line:
            raise MarkerError(
                file,
                name,
                f"body line {number} holds a newline; pass one string per line",
            )
        if "\r" in line:
            raise MarkerError(
                file,
                name,
                f"the body holds a carriage return at body line {number}; blocks are "
                "LF only",
            )
        for placeholder in PLACEHOLDERS:
            if placeholder in line:
                raise MarkerError(
                    file,
                    name,
                    f"the body holds {placeholder} at body line {number}; a block "
                    "holds no placeholder, so a template and the page rendered from "
                    "it carry the same bytes",
                )
    markers, unclosed = _markers(lines, file, name, "body line")
    if markers:
        raise MarkerError(
            file,
            name,
            "the body holds a generated-block marker at body line "
            f"{markers[0].index + 1}; a block cannot hold a marker of its own",
        )
    if unclosed is not None:
        raise MarkerError(
            file,
            name,
            f"the body leaves the code fence opened at body line {unclosed} unclosed, "
            "which would hide the end marker",
        )
    return lines


def _wanted(
    file: str, bodies: Mapping[str, Body], generator: str
) -> dict[str, list[str]]:
    """The lines to write, by block name in name order, each checked."""
    _require_generator(generator)
    wanted: dict[str, list[str]] = {}
    for name in sorted(bodies):
        if not _NAME_RE.fullmatch(name):
            raise MarkerError(
                file, name, f"{name!r} is not a valid block name: a name {_NAME_RULE}"
            )
        wanted[name] = _body_lines(file, name, bodies[name])
    return wanted


def _choose(
    scan: _Scan, file: str, wanted: Mapping[str, list[str]], generator: str
) -> list[GeneratedBlock]:
    """The file's blocks that ``wanted`` names, in file order; refuse a missing one."""
    by_name = {block.name: block for block in scan.blocks}
    for name in wanted:
        block = by_name.get(name)
        if block is None:
            raise MarkerError(
                file,
                name,
                "neither marker is in the file; put "
                f"`{begin_marker(name, generator)}` and `{end_marker(name)}` around "
                "the region it owns" + _fence_hint(scan.unclosed_fence),
            )
        if block.generator != generator:
            raise MarkerError(
                file,
                name,
                "its begin marker says it is generated by "
                f"`{block.generator}`, not `{generator}`",
            )
    return [block for block in scan.blocks if block.name in wanted]


# --- rewriting and checking text --------------------------------------------------


def replace_blocks(
    text: str, file: str, bodies: Mapping[str, Body], generator: str
) -> str:
    """``text`` with each named block's lines replaced; every other byte as it was.

    ``bodies`` maps block names to their lines (or to the text of them); ``generator``
    is the script that owns the blocks. Raises MarkerError, naming ``file`` and the
    block, for anything the module docstring lists, and returns nothing then.
    """
    wanted = _wanted(file, bodies, generator)
    scan = _scan(text, file, tuple(wanted))
    lines = list(scan.lines)
    for block in reversed(_choose(scan, file, wanted, generator)):
        lines[block.begin + 1 : block.end] = wanted[block.name]
    return "\n".join(lines)


def diff_blocks(
    text: str, file: str, bodies: Mapping[str, Body], generator: str
) -> list[Drift]:
    """The named blocks of ``text`` that differ from ``bodies``, in file order.

    Each ``Drift`` carries a unified diff, committed text against generated text, that
    names the block. The same refusals as ``replace_blocks``.
    """
    wanted = _wanted(file, bodies, generator)
    scan = _scan(text, file, tuple(wanted))
    drifts: list[Drift] = []
    for block in _choose(scan, file, wanted, generator):
        want = wanted[block.name]
        if list(block.body) == want:
            continue
        diff = difflib.unified_diff(
            block.body,
            want,
            fromfile=f"{file} ({block.name}, committed)",
            tofile=f"{file} ({block.name}, generated)",
            lineterm="",
        )
        drifts.append(Drift(file, block.name, "\n".join(diff)))
    return drifts


# --- files, and a template with its page ------------------------------------------


def twin_files(root: Path, file: str) -> list[str]:
    """``[template, page]`` when ``file`` is either half of a pair, else ``[file]``.

    A pair is ``<page>`` and ``<page>.template``, both present under ``root``.
    """
    if file.endswith(TEMPLATE_SUFFIX):
        template, page = file, file[: -len(TEMPLATE_SUFFIX)]
    else:
        template, page = file + TEMPLATE_SUFFIX, file
    if (root / template).is_file() and (root / page).is_file():
        return [template, page]
    return [file]


def _read(root: Path, file: str, names: Sequence[str]) -> str:
    try:
        raw = (root / file).read_bytes()
    except FileNotFoundError:
        raise MarkerError(file, _names(names), "the file does not exist") from None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MarkerError(
            file,
            _names(names),
            f"the file is not valid UTF-8 ({error.reason} at byte {error.start}); it "
            "is left as it is",
        ) from None


def write_blocks(
    root: Path, file: str, bodies: Mapping[str, Body], generator: str
) -> list[WriteResult]:
    """Rewrite the named blocks of ``root / file`` and of its template or page twin.

    Returns one ``WriteResult`` per file, the template first. Every file is read and
    checked before the first is written, so a refusal leaves both as they were, and a
    file whose blocks are already current is not touched.
    """
    names = sorted(bodies)
    plan = []
    for member in twin_files(root, file):
        text = _read(root, member, names)
        plan.append((member, text, replace_blocks(text, member, bodies, generator)))
    results = []
    for member, text, new in plan:
        if new == text:
            results.append(WriteResult(member, UNCHANGED, ()))
            continue
        changed = [d.block for d in diff_blocks(text, member, bodies, generator)]
        (root / member).write_bytes(new.encode("utf-8"))
        results.append(WriteResult(member, WRITTEN, tuple(changed)))
    return results


def check_blocks(
    root: Path, file: str, bodies: Mapping[str, Body], generator: str
) -> list[Drift]:
    """The drift of the named blocks in ``root / file`` and its twin; writes nothing."""
    names = sorted(bodies)
    drifts: list[Drift] = []
    for member in twin_files(root, file):
        text = _read(root, member, names)
        drifts += diff_blocks(text, member, bodies, generator)
    return drifts
