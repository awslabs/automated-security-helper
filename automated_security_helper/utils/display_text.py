# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Text a scanned repository chose, shown so it reads as written and changes nothing around it.

A path from the scanned tree (a lockfile's repository-relative path, for one) can hold any
character a file name can: a newline that starts a line of its own in a summary, a
terminal escape sequence, a bidirectional-override character that reorders what is
displayed, or a backtick that ends a markdown code span early. These helpers show such a
value with its control and format characters escaped, and, for markdown, inside a code
span that its own backticks cannot close.

A backslash is left as it is, so a name that already holds a backslash followed by ``n``
reads the same as an escaped newline. The point is that nothing in the value acts on the
output, not that every value has one spelling.

Which characters are escaped is utils/terminal_text.py's one definition
(``is_shown_as_escape``): control and format characters, the line and paragraph
separators, a lone surrogate, and the private-use and unassigned code points, so a
name that is not UTF-8 (read with surrogateescape) is shown as text a strict UTF-8
writer can take. Each is written as terminal_text writes it (``escape_for``:
``\\xNN``, ``\\uNNNN``, ``\\UNNNNNNNN``), except that a newline, a carriage return
and a tab are written by name.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, List, Union

from automated_security_helper.utils.terminal_text import (
    escape_for,
    is_shown_as_escape,
)

_NAMED = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}

_BACKTICK_RUN = re.compile(r"`+")


def escape_controls(text: object) -> str:
    """``text`` with each control, format, separator, surrogate, private-use and
    unassigned character written as an escape."""
    parts = []
    for character in str(text):
        if not is_shown_as_escape(character):
            parts.append(character)
        elif character in _NAMED:
            parts.append(_NAMED[character])
        else:
            parts.append(escape_for(character))
    return "".join(parts)


def escape_controls_in(text: object, values: Iterable[object]) -> str:
    """``text`` with each occurrence of each of ``values`` written as ``escape_controls`` writes it.

    For a message that quotes something a user chose, such as a file's path, inside
    text of ASH's or a parser's: the value cannot act on the output, and the rest of
    the message keeps its own line breaks. Longer values are replaced first, so one
    inside another is replaced once. A value that is itself a line break (a file
    named by one control character) cannot be told from the message's own, so
    every occurrence is escaped: the message then reads on one line, which is
    the lesser cost next to a value that starts a line of its own.
    """
    shown = str(text)
    for value in sorted({str(value) for value in values}, key=len, reverse=True):
        escaped = escape_controls(value)
        if value and escaped != value:
            shown = shown.replace(value, escaped)
    return shown


def path_spellings(path: Union[str, "os.PathLike[str]"]) -> List[str]:
    """The ways a message may quote ``path``: as given, POSIX-style, absolute, resolved.

    The absolute and resolved spellings need the working directory, which can be
    gone while an error about the path is being printed; a spelling that cannot
    be made is left out rather than raised from the printer.
    """
    given = Path(path)
    spellings = [os.fspath(path), str(given), given.as_posix()]
    for spelled in (given.absolute, given.resolve):
        try:
            spellings.append(str(spelled()))
        except (OSError, RuntimeError):
            pass
    return spellings


def markdown_code_span(text: object) -> str:
    """``text`` as a markdown code span, with its control characters escaped.

    Fenced with one more backtick than the longest run of backticks it holds, so none
    of them can close the span, and padded with a space on each side when it starts or
    ends with a backtick, which CommonMark strips again. CommonMark strips one space
    from each side of any span that both starts and ends with a space and is not all
    spaces, so such a text is padded the same way and reads back with its own.
    """
    shown = escape_controls(text)
    longest = max((len(run) for run in _BACKTICK_RUN.findall(shown)), default=0)
    fence = "`" * (longest + 1)
    edged_by_spaces = (
        shown.startswith(" ") and shown.endswith(" ") and not shown.isspace()
    )
    if shown.startswith("`") or shown.endswith("`") or edged_by_spaces:
        return f"{fence} {shown} {fence}"
    return f"{fence}{shown}{fence}"
