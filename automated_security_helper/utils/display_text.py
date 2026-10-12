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
"""

from __future__ import annotations

import re
import unicodedata

#: Unicode categories escaped: control characters (newlines, tabs, ESC), format
#: characters (bidirectional overrides, zero-width characters) and the line and
#: paragraph separators.
_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})

_NAMED = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}

_BACKTICK_RUN = re.compile(r"`+")


def escape_controls(text: object) -> str:
    """``text`` with each control, format and separator character written as an escape."""
    parts = []
    for character in str(text):
        if unicodedata.category(character) not in _ESCAPED_CATEGORIES:
            parts.append(character)
        elif character in _NAMED:
            parts.append(_NAMED[character])
        elif ord(character) < 0x100:
            parts.append(f"\\x{ord(character):02x}")
        else:
            parts.append(f"\\u{ord(character):04x}")
    return "".join(parts)


def markdown_code_span(text: object) -> str:
    """``text`` as a markdown code span, with its control characters escaped.

    Fenced with one more backtick than the longest run of backticks it holds, so none
    of them can close the span, and padded with a space on each side when it starts or
    ends with a backtick, which CommonMark strips again.
    """
    shown = escape_controls(text)
    longest = max((len(run) for run in _BACKTICK_RUN.findall(shown)), default=0)
    fence = "`" * (longest + 1)
    if shown.startswith("`") or shown.endswith("`"):
        return f"{fence} {shown} {fence}"
    return f"{fence}{shown}{fence}"
