# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A handler an application puts on the ``ash`` logger can write as ASH's log file does.

Why this exists
---------------
ASH keeps a handler an application put on its ``ash`` logger
(test_get_logger_keeps_a_host_handler.py), and that handler gets ASH's records as
written: a file name or a tool's output from the scanned repository in them, a
line starting "::" or a "##vso[" included. ASH's own console and log file write
each record with its control characters as escapes and its CI command lines
broken. ``utils.log.CommandSafeFormatter`` is that formatter, for an application
to give its own handler.
"""

from __future__ import annotations

import io
import logging
import re

import pytest

from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

#: A record quoting text from a scanned repository, holding two runners' commands.
LINE = "x\n::add-mask::A ##vso[task.setvariable variable=x]B"


def _written_by_a_host_handler(
    formatter: logging.Formatter, message: str = LINE
) -> str:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        ASH_LOGGER.warning(message)
    finally:
        logger.removeHandler(handler)
    return stream.getvalue()


def _windows_safe_filter_set(monkeypatch, active: bool) -> None:
    """Set whether the ``ash`` logger's WindowsSafeFilter rewrites records.

    The filter decides once, when it is made (Windows, and a CI runner or a
    console that cannot encode). Active, it leaves a record the console can
    write (ASCII) as logged and rewrites one it cannot: shown (controls as
    escapes, CI commands broken) and in ASCII, so a host handler on such a
    console gets that record shown. Both are pinned below, whatever this
    process runs on.
    """
    from automated_security_helper.utils.log import WindowsSafeFilter

    found = [f for f in ASH_LOGGER.filters if isinstance(f, WindowsSafeFilter)]
    assert found, "the ash logger carries no WindowsSafeFilter"
    for windows_filter in found:
        monkeypatch.setattr(windows_filter, "_active", active)


def test_a_host_handler_gets_ashs_records_as_written(monkeypatch):
    _windows_safe_filter_set(monkeypatch, active=False)

    written = _written_by_a_host_handler(logging.Formatter("%(message)s"))

    assert written == f"{LINE}\n", written


def test_a_host_handler_gets_an_ascii_record_as_written_under_the_active_filter(
    monkeypatch,
):
    """The active filter rewrites only what the console cannot write: an ASCII
    record, CI commands included, reaches a host handler as written there too."""
    _windows_safe_filter_set(monkeypatch, active=True)

    written = _written_by_a_host_handler(logging.Formatter("%(message)s"))

    assert written == f"{LINE}\n", written


def test_a_host_handler_on_a_console_that_cannot_encode_gets_the_record_shown(
    monkeypatch,
):
    """Where the Windows-safe filter is active, a record the console cannot
    write is shown before any handler sees it, the plain formatter included:
    its text is ASCII, its control characters are escapes and its CI command
    forms are broken. The filter here knows nothing of a console's code page
    (it is made on this host and switched on), so every character outside ASCII
    is its escape; with a code page that writes the "é" it would be kept
    (test_windows_safe_filter_writes_what_the_code_page_writes.py)."""
    _windows_safe_filter_set(monkeypatch, active=True)

    written = _written_by_a_host_handler(
        logging.Formatter("%(message)s"), LINE + " caf" + chr(0xE9)
    )

    assert written.isascii(), written
    assert "add-mask" in written and "setvariable" in written, written
    assert "caf\\xe9" in written, written
    lines = re.split(r"\r\n|\r|\n", written)
    assert [line for line in lines if re.match(r"\s*::", line)] == [], written
    assert not re.search(r"##[A-Za-z]*\[", written), written


def test_a_host_handler_given_the_command_safe_formatter_writes_no_command():
    from automated_security_helper.utils.log import CommandSafeFormatter

    written = _written_by_a_host_handler(CommandSafeFormatter("%(message)s"))

    # The control: the record was written.
    assert "add-mask" in written and "setvariable" in written, written
    lines = re.split(r"\r\n|\r|\n", written)
    assert [line for line in lines if re.match(r"\s*::", line)] == [], written
    assert not re.search(r"##[A-Za-z]*\[", written), written


def test_a_format_string_joined_with_the_message_forms_no_command():
    """The format string's own text stands right against the message, so the
    two together can form a command neither holds alone: ":%(message)s" against
    ":add-mask::X" gives a line-start "::", and "#%(message)s" against
    "#vso[...]" gives "##vso[". The whole formatted line is checked."""
    from automated_security_helper.utils.log import CommandSafeFormatter

    starting_colon = _written_by_a_host_handler(
        CommandSafeFormatter(":%(message)s"), ":add-mask::X"
    )
    starting_hash = _written_by_a_host_handler(
        CommandSafeFormatter("#%(message)s"), "#vso[task.setvariable variable=x]Y"
    )

    assert "add-mask" in starting_colon, starting_colon
    assert "vso" in starting_hash, starting_hash
    for written in (starting_colon, starting_hash):
        lines = re.split(r"\r\n|\r|\n", written)
        assert [line for line in lines if re.match(r"\s*::", line)] == [], written
        assert not re.search(r"##[A-Za-z]*\[", written), written
