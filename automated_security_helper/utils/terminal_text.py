# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Text ASH did not write, made safe to show on a terminal or in a CI log.

Log messages and refusals quote text from the scanned repository, a results file
or a tool: paths, keys, exception text. Written as is, a terminal acts on the
controls in it (OSC 8 plants a hyperlink, OSC 52 sets the clipboard, a carriage
return or CSI 2K overwrites the line before it, a bidirectional override shows
text in an order other than the one it holds, a line separator ends a line in
some viewers), and a CI runner reads a line of it as a command: GitHub Actions a
line that starts, after whitespace, with "::" (``::add-mask::``, ``::error``,
``::stop-commands::``), its legacy ``##[cmd]`` form anywhere in a line, Azure
Pipelines ``##vso[`` and TeamCity ``##teamcity[``. A "##" with no name and "["
after it, a Markdown heading's ("## Scan Metadata"), is no command and is left
as it is.

One definition says which characters are shown rather than printed
(:func:`is_shown_as_escape`): those of Unicode's control (Cc) and format (Cf)
categories, the line and paragraph separators (Zl, Zp), a lone surrogate (Cs),
and the private-use (Co) and unassigned (Cn) code points. That covers C0, DEL and
C1, the bidirectional controls, the zero-width characters and joiners, the byte
order mark, the soft hyphen, the tag block and the noncharacters. Which code
points are unassigned is the running Python's Unicode version's answer. Each is
written as an escape (:func:`escape_for`): ``\\xNN`` up to U+00FF, ``\\uNNNN``
up to U+FFFF, ``\\UNNNNNNNN`` beyond. Every function here, ash report's terminal
escape (cli/report.py) and ash merge's shard text (core/sharding.py) use it.

Some ordinary text is written out too, and that is accepted: the zero-width
joiner (U+200D) inside an emoji sequence, the zero-width non-joiner (U+200C)
Persian writes between letters, and the soft hyphen (U+00AD) are format
characters, shown as their escapes like the others of their category. They
can hide text or change how it reads as well, and an exception for them between
letters or emoji would carve a policy hole into a sink that exists for safety.

:func:`controls_shown` writes each such character as its escape, and doubles a
run of backslashes that would read as one, so the output decodes back to the
input exactly: an odd run of backslashes before ``xNN``, ``uNNNN`` or
``UNNNNNNNN`` ends in an escape, an even one is text. That holds for a Windows
path too: a segment that reads as an escape, such as ``\\x64`` in
``C:\\Python\\x64\\Lib`` (a frame of a traceback on a Windows runner), is shown
with its backslash doubled. Any other backslash is left as it is. Tab and
newline lay text out and are kept, and so is a carriage return before a newline.
:func:`shown_not_obeyed` also breaks each command form, with the same escapes
(``\\x3a`` for the first colon of a line-start "::", ``\\x23`` for the first "#"
of "##name[" anywhere, the name optional and in any case). An ARN's "::" is
mid-line and stays readable.

``ash report`` on a terminal shows the report itself, so it breaks no command
and doubles a backslash run only before the text of an escape this module
writes (``lookalikes="written"``): a Windows path's ``\\x64`` is left as it is.
A sink that then puts the text in ASCII (utils/log.py's WindowsSafeFilter, through
:func:`shown_in_ascii`) doubles a run only before the text of an escape one of
the two would write there (``lookalikes="ascii"``): JSON's ``\\u00e9`` in a
suggested command is left as it is, since the ASCII form of "é" is ``\\xe9``.
In JSON it writes JSON's own escapes instead (:func:`json_controls_shown`).

:func:`shown_not_obeyed` and :func:`shown_on_one_line`, which also writes tab,
newline and carriage return as escapes, return a :class:`ShownText`: text shown
once. Each sink that shows the text it is given (the log handlers, ash.log, the
console's echo, escape_markup) leaves a ShownText as it is, so a call site can
show a value itself and hand the sink the result: shown again, each escape in it
would have its backslash doubled, and a newline written as ``\\x0a`` would read
as that text. Only those two functions make one from text, and
:func:`shown_in_ascii` one from a ShownText, for a stream that takes only ASCII.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from typing import Literal

#: The Unicode categories of the characters shown as escapes, not printed: control
#: (Cc), format (Cf), surrogate (Cs, only ever lone in a str), private use (Co),
#: unassigned (Cn, the noncharacters such as U+FFFE included), line separator (Zl)
#: and paragraph separator (Zp). A private-use or unassigned character has no
#: meaning the reader can see, and a terminal or font may give it one.
SHOWN_AS_ESCAPES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def is_shown_as_escape(character: str) -> bool:
    """Whether *character* is one a terminal or a log viewer acts on, not shows."""
    return unicodedata.category(character) in SHOWN_AS_ESCAPES


def escape_for(character: str) -> str:
    """The escape *character* is shown as: ``\\xNN``, ``\\uNNNN`` or ``\\UNNNNNNNN``."""
    code = ord(character)
    if code <= 0xFF:
        return "\\x%02x" % code
    if code <= 0xFFFF:
        return "\\u%04x" % code
    return "\\U%08x" % code


#: The text after a backslash that reads as one of those escapes.
_ESCAPE_TEXT = re.compile(r"x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}")

#: Where a character may need its escape: each one outside printable ASCII, or a
#: whole run of backslashes, matched only from its first, before text that reads as
#: an escape or before such a character. A run matched from anywhere in it was
#: retried at every position, in time that grew with the square of its length.
_CANDIDATES = re.compile(
    r"(?<!\\)(\\+)(?=x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[^\x20-\x7e])"
    r"|[^\x20-\x7e]"
)

#: Each character outside printable ASCII.
_OUTSIDE_PRINTABLE_ASCII = re.compile(r"[^\x20-\x7e]")


def _escaped(text: str, index: int, keep_layout: bool) -> bool:
    """Whether the character at *index* of *text* is written as its escape."""
    character = text[index]
    if keep_layout:
        if character in "\t\n":
            return False
        if character == "\r" and text.startswith("\n", index + 1):
            return False
    return is_shown_as_escape(character)


def _reads_as_written_escape(after: str) -> bool:
    """Whether *after* (the text after a backslash) is an escape this module writes."""
    match = _ESCAPE_TEXT.match(after)
    if match is None:
        return False
    try:
        character = chr(int(match.group()[1:], 16))
    except (ValueError, OverflowError):
        # Beyond U+10FFFF; eight hex digits whose value does not fit a C int
        # make chr() raise OverflowError, not ValueError, on some Python versions.
        return False
    # Compared with the letter lowercased on both sides: escape_for writes the
    # letter of an eight-digit escape as "U", and the hex digits in lower case.
    return (
        is_shown_as_escape(character)
        and escape_for(character).lower() == "\\" + match.group().lower()
    )


def _reads_as_ascii_escape(after: str) -> bool:
    """Whether *after* is an escape this module or :func:`shown_in_ascii` writes.

    The text of a character outside ASCII, or of one :func:`is_shown_as_escape`
    names, in the form :func:`escape_for` gives it: ``\\xe9`` for "é", never
    JSON's ``\\u00e9``, whose value is below U+0100.
    """
    match = _ESCAPE_TEXT.match(after)
    if match is None:
        return False
    try:
        character = chr(int(match.group()[1:], 16))
    except (ValueError, OverflowError):
        return False
    if character.isascii() and not is_shown_as_escape(character):
        return False
    return escape_for(character).lower() == "\\" + match.group().lower()


def controls_shown(
    text: str,
    *,
    keep_layout: bool = True,
    lookalikes: Literal["any", "written", "ascii"] = "any",
) -> str:
    """*text* with each character :func:`is_shown_as_escape` names written as its
    escape, one to one.

    For a sink that only a terminal reads. For a console or a log a CI runner can
    read, use :func:`shown_not_obeyed`.

    *keep_layout* False writes tab, newline and carriage return as escapes too, for
    a value that must not lay out the text around it (a shard's scanner name).
    *lookalikes* "written" doubles a backslash run only before the text of an
    escape this function writes, rather than before any ``xNN``, ``uNNNN`` or
    ``UNNNNNNNN``; ``ash report`` uses it, as a Windows path's ``\\x64`` is no
    escape it writes. *lookalikes* "ascii" doubles a run before that text and
    before the text of a character outside ASCII in the form :func:`escape_for`
    writes it, for text :func:`shown_in_ascii` then puts in ASCII: a JSON
    document's ``\\u00e9`` is left as it is, where "any" doubled its run and the
    command that quoted it then read the text "u00e9".
    """

    def shown(match: re.Match[str]) -> str:
        run = match.group(1)
        if run:
            after = match.end()
            if lookalikes == "any":
                reads_as_escape = _ESCAPE_TEXT.match(text, after) is not None
            elif lookalikes == "written":
                reads_as_escape = _reads_as_written_escape(text[after : after + 9])
            else:
                reads_as_escape = _reads_as_ascii_escape(text[after : after + 9])
            if reads_as_escape or (
                after < len(text) and _escaped(text, after, keep_layout)
            ):
                return run * 2
            return run
        if _escaped(text, match.start(), keep_layout):
            return escape_for(match.group())
        return match.group()

    return _CANDIDATES.sub(shown, text)


def only_controls_shown(text: str) -> str:
    """*text* with each such character written as its escape, and nothing else changed.

    No backslash is doubled and no command broken: for text whose values already
    went through :func:`shown_not_obeyed` (:func:`raw_controls_shown`), and for a
    code snippet highlighted as code, where the escapes it holds are its own.
    """

    def shown(match: re.Match[str]) -> str:
        if _escaped(text, match.start(), True):
            return escape_for(match.group())
        return match.group()

    return _OUTSIDE_PRINTABLE_ASCII.sub(shown, text)


def json_controls_shown(text: str) -> str:
    """JSON text with each such character written as a JSON escape, ``\\uNNNN``.

    A JSON serializer escapes C0 controls in strings itself, but writes DEL, C1 and
    the format and separator characters as they are, and ``\\xNN`` is no JSON
    escape. A character beyond U+FFFF is written as the surrogate pair JSON reads.
    Tab and newline, outside a string only, lay the document out and are kept.
    JSON's own escaping keeps text and escapes apart, so no backslash is doubled.
    """

    def shown(match: re.Match[str]) -> str:
        character = match.group()
        if not _escaped(text, match.start(), True):
            return character
        code = ord(character)
        if code <= 0xFFFF:
            return "\\u%04x" % code
        code -= 0x10000
        return "\\u%04x\\u%04x" % (0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF))

    return _OUTSIDE_PRINTABLE_ASCII.sub(shown, text)


#: The characters that end a line for ``str.splitlines``: a newline, a carriage
#: return, vertical tab, form feed, the three information separators, NEL and the
#: Unicode line and paragraph separators. A consumer that reads lines does not all
#: agree on which of them end one (the stream in utils/command_safe_stream.py ends
#: a line at a lone carriage return, not at the others), so a "::" after any of
#: them is a line start here.
_LINE_ENDS = r"\n\r\x0b\x0c\x1c-\x1e\x85\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}"

#: The first colon of a line that starts, after whitespace that ends no line,
#: with "::". The runner trims leading whitespace, Unicode's included, before it
#: reads a line, so indentation does not protect it. A line starts at the text's
#: start and after each character in :data:`_LINE_ENDS`; the whitespace skipped
#: leaves those out, so each position is tried once and a long run of them costs
#: time linear in its length. A "\r\n" is one break: the position between the two
#: is followed by a newline, which is no colon.
_LINE_START_COMMAND = re.compile(
    rf"(?:^|(?<=[{_LINE_ENDS}]))([^\S{_LINE_ENDS}]*):(?=:)"
)

#: The first "#" of "##" followed by a name and "[" anywhere in a line ("##[cmd]",
#: "##vso[", "##teamcity["), with any backslashes just before it, which are
#: doubled so the "\x23" put in its place reads as one escape. The run is
#: matched from its first backslash only, as every other run pattern here is:
#: matched from anywhere in it, a run not followed by "#" was retried from each
#: of its positions, in time that grew with the square of its length.
NAMED_HASH_COMMAND = re.compile(r"(?<!\\)(\\*)#(?=#[A-Za-z]*\[)")


class ShownText(str):
    """Text :func:`shown_not_obeyed` or :func:`shown_on_one_line` wrote: shown once.

    :func:`shown_in_ascii` makes one from one, for a stream that takes only ASCII.
    A sink that shows the text it is given leaves a ShownText as it is: a log
    record whose message is one and has no arguments left to put in
    (utils/log.py's console_text), escape_markup, and the console's echo. Text
    shown twice has the backslash of each escape doubled, so it no longer reads
    as what it stood for.

    Nothing else makes one: calling the class raises, it cannot be subclassed,
    an instance holds no attribute, and a str cannot be given it as its class.
    What a str operation makes from one (a concatenation, a format that fills
    something in, a slice, ``str()``, a copy, a pickle) is a plain str, which a
    sink shows as any other text; an operation that leaves the text as it is (a
    format with nothing to fill in, a partition that does not find its
    separator) returns the same object. Text that merely looks shown is shown
    again: twice is safe, once too few would not be. Python does let an instance
    of another str subclass with the same layout be given this class, so
    tests/unit/utils/test_shown_text_is_shown_once.py refuses that, and any
    other way of making one, in the package.
    """

    __slots__ = ()

    # It returns nothing, so no Self: it raises.
    def __new__(cls, *args: object, **kwargs: object) -> "ShownText":  # noqa: PYI034
        raise TypeError(
            "a ShownText is made only by shown_not_obeyed, shown_on_one_line "
            "and shown_in_ascii"
        )

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("ShownText cannot be subclassed")

    def __reduce_ex__(self, protocol: object) -> tuple[type[str], tuple[str]]:
        # A copy or a pickle is plain text, which a sink shows.
        return (str, (str(self),))

    def __reduce__(self) -> tuple[type[str], tuple[str]]:
        # The same: object's own would rebuild this class around the text.
        return (str, (str(self),))


def _as_shown(text: str) -> ShownText:
    """*text*, which one of the two escapers below just wrote, as a ShownText."""
    return str.__new__(ShownText, text)


def commands_broken(text: str) -> str:
    """*text* with each CI command form broken, as :func:`shown_not_obeyed` does.

    The forms a runner reads: "::" at a line start (after whitespace), and "##"
    with an optional name and "[" anywhere, in any case. A bare "##", a Markdown
    heading's, is no command and is left. Expects text that :func:`controls_shown`
    already went over, or that holds no escape-like text of its own: the escapes
    it puts in are single backslashes.
    """
    text = _LINE_START_COMMAND.sub(r"\1\\x3a", text)
    return NAMED_HASH_COMMAND.sub(hash_command_broken, text)


def hash_command_broken(match: re.Match[str]) -> str:
    """The replacement for a :data:`NAMED_HASH_COMMAND` match."""
    return match.group(1) * 2 + "\\x23"


def shown_not_obeyed(
    text: str, *, lookalikes: Literal["any", "written", "ascii"] = "any"
) -> ShownText:
    """*text* as a console or a CI log shows it: what it says, not what it commands.

    Tab and newline lay the text out and are kept. A :class:`ShownText` is
    returned as it is, since it was shown already. *lookalikes* is
    :func:`controls_shown`'s: "ascii" for text :func:`shown_in_ascii` then puts
    in ASCII.
    """
    if isinstance(text, ShownText):
        return text
    return _as_shown(commands_broken(controls_shown(text, lookalikes=lookalikes)))


#: A tab, newline or carriage return, with the run of backslashes just before it,
#: matched from the run's first backslash only.
_LAYOUT = re.compile(r"(?<!\\)(\\*)([\t\n\r])")


def _layout_shown(match: re.Match[str]) -> str:
    return match.group(1) * 2 + escape_for(match.group(2))


def shown_on_one_line(text: str) -> ShownText:
    """*text* as :func:`shown_not_obeyed` shows it, with tab, newline and carriage
    return written as escapes too (``\\x09``, ``\\x0a``, ``\\x0d``), so it is one
    line wherever it is printed.

    For a call site that quotes a repository's text in a one-line message: a
    newline there would start a line the text chose. The call site shows the
    whole message, values included, and logs or prints the result, which the sink
    leaves as it is; shown in parts and joined, the escapes at the joins would not
    be one to one. A :class:`ShownText` that kept its layout has only those three
    left to write, each with the run of backslashes before it doubled.
    """
    if isinstance(text, ShownText):
        return _as_shown(_LAYOUT.sub(_layout_shown, text))
    return _as_shown(commands_broken(controls_shown(text, keep_layout=False)))


#: A character outside ASCII, with the run of backslashes just before it, matched
#: from the run's first backslash only.
_OUTSIDE_ASCII = re.compile(r"(?<!\\)(\\*)([^\x00-\x7f])")

#: How many hex digits follow each escape's letter.
_ESCAPE_DIGITS = {"x": 2, "u": 4, "U": 8}

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _outside_ascii_shown(match: re.Match[str]) -> str:
    return match.group(1) * 2 + escape_for(match.group(2))


def _joins_its_neighbors(replacement: str) -> bool:
    """Whether *replacement*, put in shown text, could read as something else.

    Empty, it joins the text on each side; with a backslash, a character outside
    printable ASCII, the start of an escape's text (``x4`` before ``1``) or a
    hex digit first (``b`` after ``\\x1``, which shown text can end in), it could
    make an escape the text does not hold. A "::" or "##[" it makes with its
    neighbors is broken afterwards, as shown_not_obeyed breaks one.
    """
    if not replacement or "\\" in replacement:
        return True
    if any(not " " <= character <= "~" for character in replacement):
        return True
    if replacement[0] in _HEX_DIGITS:
        return True
    digits = _ESCAPE_DIGITS.get(replacement[0])
    if digits is None:
        return False
    return all(digit in _HEX_DIGITS for digit in replacement[1 : 1 + digits])


def shown_in_ascii(text: ShownText, replacements: Mapping[str, str]) -> ShownText:
    """*text*, shown already, with nothing outside ASCII left in it.

    For a sink whose stream cannot encode more: utils/log.py's WindowsSafeFilter,
    on a Windows console or CI runner. Each key of *replacements* is put as its
    value (an emoji as a bracketed word); each other character outside ASCII is
    written as its escape, with the run of backslashes before it doubled, as
    :func:`shown_on_one_line` writes a newline in shown text; then a "::" or
    "##[" a replacement joined with its neighbors is broken. Nothing is dropped:
    a character dropped from shown text could join what was on each side of it
    into a command or an escape the text never held. A value that could do the
    same is refused, as is a key with a character in ASCII, which could be part
    of an escape.
    """
    if not isinstance(text, ShownText):
        raise TypeError("shown_in_ascii takes text an escaper here wrote")
    replaced = str(text)
    for key, value in replacements.items():
        if not key or any(character.isascii() for character in key):
            raise ValueError(f"replacement key {key!r} has a character in ASCII")
        if _joins_its_neighbors(value):
            raise ValueError(f"replacement {value!r} could join the text around it")
        replaced = replaced.replace(key, value)
    return _as_shown(
        commands_broken(_OUTSIDE_ASCII.sub(_outside_ascii_shown, replaced))
    )


#: A whole run of backslashes, matched from its first, and the escape text after it.
_RUN_BEFORE_ESCAPE = re.compile(
    r"(?<!\\)(\\+)(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})"
)


def as_written(text: str) -> str:
    """The text a :class:`ShownText` was made from; any other str as it is.

    For text that is stored, and shown once later by whatever reads it: a part a
    call site showed already would be shown a second time there. A ShownText holds
    no attribute, so it is read back. The escapers write a character as its escape
    (``\\xNN``, ``\\uNNNN``, ``\\UNNNNNNNN``, ":" and "#" of a command among them)
    and double a run of backslashes before text that reads as an escape, so an odd
    run ends in an escape and an even run stands for half as many backslashes.
    That is exact for :func:`shown_not_obeyed` and :func:`shown_on_one_line`; a
    character :func:`shown_in_ascii` put as a replacement stays as the
    replacement.
    """
    if not isinstance(text, ShownText):
        return text

    def written(match: re.Match[str]) -> str:
        run, escape = match.group(1), match.group(2)
        backslashes = "\\" * (len(run) // 2)
        if len(run) % 2 == 0:
            return backslashes + escape
        try:
            return backslashes + chr(int(escape[1:], 16))
        except (ValueError, OverflowError):
            # Beyond U+10FFFF, which no escaper writes; for a value that does
            # not fit a C int some Python versions raise OverflowError instead.
            return match.group()

    return _RUN_BEFORE_ESCAPE.sub(written, str(text))


def raw_controls_shown(text: str) -> str:
    """Only the raw controls in *text* as escapes, and its CI commands broken.

    For text whose values already went through :func:`shown_not_obeyed`, such as
    a message logged with MARKUP after escape_markup: running the whole of
    shown_not_obeyed again would double the backslashes of the escapes it wrote.
    """
    return commands_broken(only_controls_shown(text))


def raw_controls_on_one_line(text: str) -> str:
    """*text* on one line, each character :func:`is_shown_as_escape` names written
    as its escape (tab, newline and carriage return included), its CI command
    forms broken, and its backslashes kept.

    For a one-line field a program hands on to be displayed, such as an MCP
    tool's error: its message can quote a value raw, or hold escapes already
    where a value was escaped as the error was raised. Nothing in
    the result acts on a terminal or a CI runner, and applied again it changes
    nothing. Unlike :func:`shown_on_one_line` it is not one to one: a value's
    own backslash followed by ``x1b`` reads the same as an escaped ESC.
    """
    shown = "".join(
        escape_for(character) if is_shown_as_escape(character) else character
        for character in str(text)
    )
    return commands_broken(shown)
