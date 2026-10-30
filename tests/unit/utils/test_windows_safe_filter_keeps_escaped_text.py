# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Windows log filter keeps a markup record's escaped values as text.

Why this exists
---------------
On a Windows console that cannot write Unicode, and on a Windows CI runner,
``WindowsSafeFilter`` rewrites each record's message to ASCII: it replaces some
characters (an arrow "↓" becomes "v") and writes the rest as escapes (an "é"
becomes the four characters of ``\\xe9``; nothing is dropped). A record that asks
for Rich markup (``extra=MARKUP``) has had each value escaped with
``escape_markup`` before that, and the rewrite can undo the escape: the escape
text put between a value's own backslash and the tag changes what stands before
"[/x]", and "[↓x]", which is no tag, would become "[vx]", which is one, and its
text be dropped. A record whose rewrite would change the text it shows is
written as that text's ASCII form, without markup; one whose rewrite changes
nothing but characters keeps its styles.

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

pytestmark = pytest.mark.unit


def _filtered(message: str) -> logging.LogRecord:
    windows_filter = WindowsSafeFilter()
    windows_filter._active = True
    record = logging.LogRecord("ash", logging.INFO, __file__, 1, message, (), None)
    record.__dict__.update(MARKUP)
    assert windows_filter.filter(record)
    return record


def _filtered_plain(message: str, args=()) -> logging.LogRecord:
    """A plain (no markup) record through the active filter."""
    windows_filter = WindowsSafeFilter()
    windows_filter._active = True
    record = logging.LogRecord("ash", logging.INFO, __file__, 1, message, args, None)
    assert windows_filter.filter(record)
    return record


def test_an_ascii_message_keeps_its_own_escape_text():
    """A suggested command quotes a JSON document whose non-ASCII character is
    JSON's own escape, four ASCII characters after one backslash. Shown, that
    run was doubled and the pasted command read the escape as text; a message
    the console can already write is left as it was logged."""
    import json
    import shlex

    message = "ash --config-overrides " + shlex.quote(
        json.dumps({"ignore_paths": ["café dir/.ash/ash_output"]})
    )
    assert message.isascii() and "\\u00e9" in message

    record = _filtered_plain(message)

    assert record.getMessage() == message
    (quoted,) = shlex.split(record.getMessage())[2:]
    assert json.loads(quoted) == {"ignore_paths": ["café dir/.ash/ash_output"]}


def test_an_ascii_message_with_ascii_arguments_is_left_as_logged():
    record = _filtered_plain("scan %s in %d ms", ("a::b ##vso[x]", 3))

    assert record.msg == "scan %s in %d ms"
    assert record.args == ("a::b ##vso[x]", 3)


def test_a_message_the_console_cannot_write_is_folded_and_shown():
    record = _filtered_plain("path %s", ("café ::x",))

    assert record.args == ()
    assert record.getMessage().isascii()
    assert "caf\\xe9" in record.getMessage()
    assert "::x" not in record.getMessage()


def _shown(record: logging.LogRecord) -> Text:
    message = record.getMessage()
    if getattr(record, "markup", False):
        return Text.from_markup(message)
    return Text(message)


@pytest.mark.parametrize(
    "value, shown",
    [
        pytest.param("C:\\\u00e9[/x]", "C:\\\\xe9[/x]", id="escaped-after-a-backslash"),
        pytest.param(
            "C:\\\u00e9[bold]x[/bold]",
            "C:\\\\xe9[bold]x[/bold]",
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
