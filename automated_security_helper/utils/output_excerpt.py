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
from typing import Iterable

from automated_security_helper.utils.terminal_text import (
    commands_broken,
    controls_shown,
)

#: Share of the limit given to the start of the text; the rest goes to the end.
_HEAD_SHARE = 4

#: The text of an escape as the sinks and :func:`controls_shown` write one, with
#: the run of backslashes before it. A cut inside one would leave half an escape
#: on each side of the marker, or a tail that starts inside a backslash run and
#: so reads as an escape the text did not hold.
_ESCAPE_TEXT = re.compile(r"\\+(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})?")


def _cut_outside_escapes(text: str, index: int) -> int:
    """*index* moved back to the start of the escape text, or the backslash run,
    it would otherwise fall inside of; unchanged when it falls between two
    characters that belong to no escape."""
    start = max(0, index - 11)
    # The window can open inside a long backslash run, and a match found from
    # there starts mid-run: the cut moved back to it left the run's other half on
    # the other side. The window opens at the start of the run it fell in.
    while start > 0 and text[start - 1] == "\\":
        start -= 1
    for match in _ESCAPE_TEXT.finditer(text, start, min(len(text), index + 11)):
        if match.start() < index < match.end():
            return match.start()
    return index


def head_and_tail(text: str, limit: int) -> str:
    """``text`` cut to about ``limit`` characters, keeping its start and its end.

    Text within the limit is returned unchanged. Otherwise the first quarter of the
    limit and the last three quarters are kept, joined by a marker naming how many
    characters were left out. The marker itself is not counted against ``limit``.
    Neither cut lands inside an escape's text (``\\xNN``, ``\\uNNNN``, a backslash
    run): such a cut is moved back to the escape's start, so the head ends before it
    and the tail begins with it whole.
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
