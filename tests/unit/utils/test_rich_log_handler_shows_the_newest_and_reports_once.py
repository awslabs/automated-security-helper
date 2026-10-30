# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The live log panel shows its newest records, labels every level, and its
handler reports a failed record once, through logging's guard.

The panel's rows were added oldest-first and padded to ``max_lines`` whatever
height Rich gave it, so a region shorter than that cropped the newest records off
the bottom. A level the table did not name was labelled INFO, a custom level above
WARNING among them. The deque was copied for the render while the logging threads
appended to it, with no lock. The handler's emit printed its own line to stderr
before handleError, unguarded, ignoring logging.raiseExceptions, reporting each
failure twice and showing a MarkupError's tag a second time; and a MARKUP record's
traceback, appended by the formatter, was read as markup, so a bracket in it
dropped the record. The values here are placeholders.
"""

from __future__ import annotations

import io
import logging
import sys

import pytest
from rich.console import Console

from automated_security_helper.utils.log import MARKUP
from automated_security_helper.utils.rich_log_handler import (
    LiveDisplayLogHandler,
    RichLogPanel,
)

pytestmark = pytest.mark.unit


def _messages(table) -> list[str]:
    return [
        cell.plain if hasattr(cell, "plain") else str(cell)
        for cell in table.columns[1]._cells
    ]


def test_a_short_region_shows_the_newest_records():
    panel = RichLogPanel(max_lines=10)
    for index in range(6):
        panel.add_log(f"record {index}")
    console = Console(file=io.StringIO(), width=60)
    rendered = list(panel.__rich_console__(console, console.options.update(height=3)))
    assert len(rendered) == 1
    assert _messages(rendered[0]) == ["record 3", "record 4", "record 5"]
    # With no height known the panel keeps its full, padded shape.
    assert len(_messages(panel.__rich__())) == 10


def test_every_level_gets_its_own_label():
    panel = RichLogPanel(max_lines=3)
    assert panel._level_name(logging.WARNING) == "WARN"
    assert panel._level_name(35) == "L35 "
    logging.addLevelName(36, "AUDIT")
    try:
        assert panel._level_name(36) == "AUDI"
    finally:
        logging.addLevelName(36, "Level 36")


def test_the_render_and_the_appends_share_one_lock():
    panel = RichLogPanel(max_lines=3)
    taken: list[str] = []

    class _Lock:
        def __enter__(self):
            taken.append("in")

        def __exit__(self, *exc):
            taken.append("out")

    panel._lock = _Lock()  # type: ignore[assignment]
    panel.add_log("a")
    panel.__rich__()
    assert taken == ["in", "out", "in", "out"]


def _record(message: str, **extra) -> logging.LogRecord:
    record = logging.LogRecord("ash", logging.INFO, "x.py", 1, message, (), None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_a_failed_record_is_reported_once_through_loggings_guard(monkeypatch):
    panel = RichLogPanel(max_lines=3)
    handler = LiveDisplayLogHandler(panel)

    def failing(*args, **kwargs):
        raise RuntimeError("the panel is gone")

    monkeypatch.setattr(panel, "add_log", failing)
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)

    monkeypatch.setattr(logging, "raiseExceptions", False)
    handler.emit(_record("quiet"))
    assert stderr.getvalue() == ""

    monkeypatch.setattr(logging, "raiseExceptions", True)
    handler.emit(_record("loud"))
    report = stderr.getvalue()
    assert report.count("--- Logging error ---") == 1, report
    assert "ERROR in LiveDisplayLogHandler" not in report, report


def test_a_markup_records_traceback_is_text(monkeypatch):
    panel = RichLogPanel(max_lines=3)
    handler = LiveDisplayLogHandler(panel)
    handler.setFormatter(logging.Formatter("%(message)s"))
    record = _record("[bold]scan[/bold] failed", **MARKUP)
    record.exc_text = "Traceback (most recent call last):\n  [/x] is not a tag\n"
    monkeypatch.setattr(logging, "raiseExceptions", True)
    monkeypatch.setattr(sys, "stderr", io.StringIO())

    handler.emit(record)

    assert len(panel.logs) == 1, sys.stderr.getvalue()
    _, text = panel.logs[0]
    assert (
        text.plain
        == "scan failed\nTraceback (most recent call last):\n  [/x] is not a tag\n"
    )
