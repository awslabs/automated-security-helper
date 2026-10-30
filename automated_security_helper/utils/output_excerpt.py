# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cut a tool's output down for an error message without losing its last words.

A tool that fails usually says why at the end. trivy, for one, prints its database
download progress first and the error that stopped it last, so an excerpt of the first
2000 characters of its stderr was all progress bar and no reason (seen in a podman CI
leg, where the message ended inside the download's progress output). An excerpt here
keeps the start, for context such as which config file was loaded, and the end, where
the error is, and says how much it left out between them.

A tool's stderr can also echo a configured value (a token passed on its command line,
a path read from the environment), and the excerpt lands in an error message that
results, reports and logs keep. :func:`tool_output_excerpt` takes the caller's
redaction values and hides them (``error_text.text_without_values``) before the cut,
so a value is matched whole, never split by the cut's marker.
"""

from __future__ import annotations

import re
import string
from typing import Iterable

from automated_security_helper.utils.terminal_text import (
    commands_broken,
    controls_shown,
)

#: Share of the limit given to the start of the text; the rest goes to the end.
_HEAD_SHARE = 4

#: The text after a backslash that makes an escape as the sinks and
#: :func:`controls_shown` write one, by its letter: the hex digits it takes.
_ESCAPE_DIGITS = {"x": 2, "u": 4, "U": 8}

#: The most characters a cut is moved back to the start of the backslash run it
#: fell in (or the run before the escape text it fell in). A longer run is cut
#: near the cut instead, so a run the length of the text cannot make an excerpt
#: the length of the text.
_MOVE_LIMIT = 16


def _is_hex(text: str) -> bool:
    return all(character in string.hexdigits for character in text)


def _escape_letter_at(text: str, index: int) -> int:
    """The position of the letter of an escape's text that *index* falls inside
    (after the escape's last backslash, before its end), or -1.

    The escape's text is a backslash, ``x``, ``u`` or ``U``, and the two, four or
    eight hex digits that letter takes.
    """
    for letter in range(max(1, index - 8), index + 1):
        digits = _ESCAPE_DIGITS.get(text[letter])
        if (
            digits is not None
            and text[letter - 1] == "\\"
            and index < letter + 1 + digits
            and len(text) >= letter + 1 + digits
            and _is_hex(text[letter + 1 : letter + 1 + digits])
        ):
            return letter
    return -1


def _run_start(text: str, end: int) -> int:
    """The start of the run of backslashes that ends just before *end*."""
    start = end
    while start > 0 and text[start - 1] == "\\":
        start -= 1
    return start


def _cut_outside_escapes(text: str, index: int) -> int:
    """*index* moved back to the start of the escape text, or the backslash run,
    it would otherwise fall inside of; unchanged when it falls between two
    characters that belong to no escape.

    The move is bounded (:data:`_MOVE_LIMIT`). Past it the cut stays near where it
    fell and keeps its parity in the run: a tail that begins with a run reads the
    same, escape or pairs of backslashes, only if its length has the parity of the
    run it was cut from, so the cut lands an even number of characters from the
    run's start, one character earlier at most when it fell on an odd one. A cut
    inside the text of an escape after a long run goes to the escape's last
    backslash when the run is odd (the escape stays whole in the tail) and to the
    escape's letter when it is even (the text after the pairs is plain)."""
    if not 0 < index < len(text):
        return index
    letter = _escape_letter_at(text, index)
    if letter != -1:
        run_start = _run_start(text, letter)
        if index - run_start <= _MOVE_LIMIT:
            return run_start
        return letter - 1 if (letter - run_start) % 2 else letter
    if text[index] == "\\" and text[index - 1] == "\\":
        run_start = _run_start(text, index)
        inside = index - run_start
        return run_start if inside <= _MOVE_LIMIT else index - inside % 2
    return index


def head_and_tail(text: str, limit: int) -> str:
    """``text`` cut to about ``limit`` characters, keeping its start and its end.

    Text within the limit is returned unchanged. Otherwise the first quarter of the
    limit and the last three quarters are kept, joined by a marker naming how many
    characters were left out. The marker itself is not counted against ``limit``.
    Neither cut lands inside an escape's text (``\\xNN``, ``\\uNNNN``, a backslash
    run): such a cut is moved back to the escape's start, so the head ends before it
    and the tail begins with it whole. The move is bounded: for a run longer than
    that the cut stays near where it fell and keeps the parity of the run, so the
    excerpt stays near ``limit`` however long the run is (:func:`_cut_outside_escapes`).
    """
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    head = _cut_outside_escapes(text, limit // _HEAD_SHARE)
    tail_start = _cut_outside_escapes(text, len(text) - (limit - head))
    if tail_start <= head:
        return text
    omitted = tail_start - head
    return f"{text[:head]} ...[{omitted} characters omitted]... {text[tail_start:]}"


#: ANSI escape sequences: CSI (colors, cursor moves) and OSC (titles, links). An
#: OSC ends at BEL, at ST (ESC followed by a backslash, or the C1 form 0x9c), and
#: never runs past the end of its line: an OSC a tool left unterminated used to
#: swallow every line up to the next BEL, the error reason included.
_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b\x9c\r\n]*(?:\x07|\x1b\\|\x9c)"
)


def tool_output_excerpt(text: str, limit: int, values: Iterable[str] = ()) -> str:
    """A tool's output for an error message: values hidden, escapes removed, then
    ``head_and_tail``.

    ``values`` are the configured values the caller redacts its own text with (the
    run's environment-read values, ``error_text.plugin_environment_values``); each
    is hidden as ``error_text.text_without_values`` hides it, on the whole text
    before the cut, so a value the cut would split is still matched. With no
    values the text is only cleaned and cut.

    A tool's stderr can carry terminal escape sequences and other control
    characters, from its own coloring or from a file it echoes back, and an error
    message is shown in terminals, logs and reports. Escape sequences are removed,
    and every character a terminal or a log viewer acts on rather than shows
    (``terminal_text.is_shown_as_escape``: the C0 and C1 controls but newline and
    tab, the format characters such as a bidirectional override or a zero-width
    space, the line and paragraph separators) is written as its escape, so nothing
    in the message can move a cursor, clear a screen, rewrite a line or reorder the
    text around it. The CI command forms are broken too (``commands_broken``):
    removing a color sequence at a line's start had left ``::error`` standing at
    the start of the line, and joining the text on both sides of one could form
    ``##[`` the output never held contiguously.
    """
    values = list(values)
    if values:
        # Imported here: error_text imports config modules at call time and this
        # module is imported by the scanners early.
        from automated_security_helper.utils.error_text import text_without_values

        text = text_without_values(text, values)
    cleaned = _ANSI.sub("", text)
    cleaned = commands_broken(controls_shown(cleaned))
    return head_and_tail(cleaned, limit)
