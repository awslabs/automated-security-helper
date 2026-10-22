# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Windows log filter keeps a markup record's escaped values as text.

Why this exists
---------------
On a Windows console that cannot write Unicode, and on a Windows CI runner,
``WindowsSafeFilter`` rewrites each record's message to ASCII: it replaces some
characters (an arrow "↓" becomes "v") and drops the rest. A record that asks for
Rich markup (``extra=MARKUP``) has had each value escaped with ``escape_markup``
before that, and the rewrite can undo the escape: a dropped character between a
value's own backslash and the escape's would leave two backslashes before "[/x]",
which Rich reads as a tag and refuses with MarkupError, so the line would be lost;
"[↓x]", which is no tag, would become "[vx]", which is one, and its text be
dropped. A record
whose rewrite would change the text it shows is written as that text's ASCII
form, without markup; one whose rewrite changes nothing but characters keeps its
styles.

The filter is active on Windows only, so these cells turn it on.
"""

from __future__ import annotations

import logging

import pytest
from rich.text import Text

from automated_security_helper.utils.log import (
    MARKUP,
    WindowsSafeFilter,
    escape_markup,
)


def _filtered(message: str) -> logging.LogRecord:
    windows_filter = WindowsSafeFilter()
    windows_filter._active = True
    record = logging.LogRecord("ash", logging.INFO, __file__, 1, message, (), None)
    record.__dict__.update(MARKUP)
    assert windows_filter.filter(record)
    return record


def _shown(record: logging.LogRecord) -> Text:
    message = record.getMessage()
    if getattr(record, "markup", False):
        return Text.from_markup(message)
    return Text(message)


@pytest.mark.parametrize(
    "value, shown",
    [
        pytest.param("C:\\\u00e9[/x]", "C:\\[/x]", id="dropped-after-a-backslash"),
        pytest.param(
            "C:\\\u00e9[bold]x[/bold]",
            "C:\\[bold]x[/bold]",
            id="style-after-a-backslash",
        ),
        pytest.param("[\u2193x]", "[vx]", id="replaced-into-a-tag"),
    ],
)
def test_an_escaped_value_is_shown_as_its_ascii_text(value, shown):
    record = _filtered(f"[yellow]p[/yellow] {escape_markup(value)}")

    assert _shown(record).plain == f"p {shown}"


def test_a_record_the_rewrite_leaves_whole_keeps_its_styles():
    record = _filtered(f"[yellow]p[/yellow] \u2705 {escape_markup('x[/x]')}")

    text = _shown(record)
    assert text.plain == "p [OK] x[/x]"
    assert getattr(record, "markup", False) is True
    assert [span.style for span in text.spans] == ["yellow"]
