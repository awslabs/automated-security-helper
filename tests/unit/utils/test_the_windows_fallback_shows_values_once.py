# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Windows filter's plain-text fallback shows each value once.

Why this exists
---------------
On a console whose encoding cannot carry the message, WindowsSafeFilter rewrites
a MARKUP record in ASCII. When the rewrite changes what the message showed (an
arrow replaced by "v" can turn escaped text into a tag), the filter falls back
to the message's plain text. Falling back to a markup-off record sent that text
through the console's and ash.log's whole-message show a second time, so every
value escape_markup had shown was shown twice: "a\\x1bb" became "a\\\\x1bb" on
the console and in ash.log, while the JSONL file kept one backslash. The
fallback keeps the record markup, with the plain text escaped so it renders as
exactly itself, and the sinks agree.
"""

from __future__ import annotations

import logging

import pytest
from rich.text import Text

from automated_security_helper.utils.log import (
    TextFileFormatter,
    WindowsSafeFilter,
    console_text,
    escape_markup,
)

pytestmark = pytest.mark.unit

#: A value a repository chose: a control, and escaped text the ASCII rewrite
#: turns into a tag ("[↓x]" shown is no tag; "[vx]" is one).
VALUE = "a\x1bb [↓x]"

#: What the console and the last resort show for the message: the value's
#: control as its escape, once, in the rewrite's ASCII. The UTF-8 files write
#: the text as logged, so they keep the arrow (log.py, _UNFILTERED_ATTR).
EXPECTED = "p a\\x1bb [vx]"
EXPECTED_IN_THE_FILE = "p a\\x1bb [↓x]"


def _filtered_record() -> logging.LogRecord:
    record = logging.LogRecord(
        "ash-windows-fallback",
        logging.WARNING,
        "app.py",
        1,
        f"[yellow]p[/yellow] {escape_markup(VALUE)}",
        None,
        None,
    )
    record.markup = True
    # A console that is known to write only ASCII, whatever host the test is on.
    windows = WindowsSafeFilter(writes=None)
    windows._active = True
    assert windows.filter(record) is True
    return record


def _console_view(record: logging.LogRecord) -> str:
    """The record as the console handler lays its message out."""
    message = console_text(record, record.getMessage())
    if getattr(record, "markup", False):
        return Text.from_markup(message).plain
    return Text(message).plain


def test_the_console_shows_the_fallback_text_once():
    record = _filtered_record()

    assert _console_view(record) == EXPECTED, _console_view(record)


def test_ash_log_shows_the_fallback_text_once():
    """The last resort's formatter (unfiltered=False) writes the console form;
    ash.log's (the default) writes the record as logged. Each shows the value's
    control once."""
    record = _filtered_record()

    console_form = TextFileFormatter("%(message)s", unfiltered=False).format(record)
    written = TextFileFormatter("%(message)s").format(record)

    assert console_form == EXPECTED, console_form
    assert written == EXPECTED_IN_THE_FILE, written


def test_control_a_kept_rewrite_still_shows_once():
    """The control: a message the rewrite does not change keeps its markup and
    shows its value once."""
    record = logging.LogRecord(
        "ash-windows-kept",
        logging.WARNING,
        "app.py",
        1,
        f"[yellow]p[/yellow] {escape_markup('plain [x]')}",
        None,
        None,
    )
    record.markup = True
    windows = WindowsSafeFilter(writes=None)
    windows._active = True
    assert windows.filter(record) is True

    assert record.markup is True
    assert _console_view(record) == "p plain [x]", _console_view(record)
    assert TextFileFormatter("%(message)s").format(record) == "p plain [x]"
