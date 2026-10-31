# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fourteen readings of utils/log.py, each wrong at the base by a line or two.

The level registration, the console's layout and environment, the Windows
filter's reach into the UTF-8 files, the CI test by presence, escape_markup's
emoji split at a value's edge and inside an escaped tag, a Rich traceback's
frame paths, the tabular formatter's traceback-then-stack order, delivers() for
a logger outside "ash", the file handler closed under a late record, a level
number with no name, and a MARKUP record's traceback read as markup. The values
here are placeholders.
"""

from __future__ import annotations

import io
import logging
import uuid

import pytest
from rich.console import Console
from rich.text import Text
from rich.traceback import Frame, Stack, Trace

from automated_security_helper.utils import log
from automated_security_helper.utils.log import (
    MARKUP,
    ConsoleHandler,
    TextFileFormatter,
    WindowsSafeFilter,
    escape_markup,
    get_logger,
)
from automated_security_helper.utils.terminal_text import ShownText

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e"


def _record(
    message: str, *args, level: int = logging.INFO, **extra
) -> logging.LogRecord:
    record = logging.LogRecord("ash", level, "x.py", 1, message, args, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


# --------------------------------------------------------------------------- #
# addLoggingLevel and the level names get_logger reads
# --------------------------------------------------------------------------- #


def test_a_bare_level_attribute_still_gets_its_name_registered(monkeypatch):
    monkeypatch.delitem(logging._levelToName, 5)
    monkeypatch.delitem(logging._nameToLevel, "TRACE")
    assert logging.getLevelName(5) == "Level 5", "the control: the name is gone"
    log.addLoggingLevel("TRACE", 5)
    assert logging.getLevelName(5) == "TRACE"


@pytest.mark.parametrize(
    ("value", "level"),
    [("10", 10), (" 20 ", 20), ("WARNING", logging.WARNING), ("²", None), ("x", None)],
)
def test_coerce_log_level_takes_ascii_digits_only(value, level):
    assert log._coerce_log_level(value) == level


def _fresh_logger_name() -> str:
    return f"ash.low-rows-{uuid.uuid4().hex[:8]}"


def _console_handler(logger: logging.Logger) -> ConsoleHandler:
    handlers = [h for h in logger.handlers if isinstance(h, ConsoleHandler)]
    assert len(handlers) == 1, logger.handlers
    return handlers[0]


@pytest.fixture
def quiet_windows(monkeypatch):
    monkeypatch.setattr(log, "configure_windows_safe_logging", lambda: None)
    monkeypatch.setattr(log, "_detect_encoding_issues", lambda: False)


def test_get_logger_takes_an_int_level_with_no_name(quiet_windows):
    name = _fresh_logger_name()
    logger = get_logger(name=name, level=37, show_progress=False)
    try:
        assert _console_handler(logger).level == 37
    finally:
        log.remove_ash_handlers(logger)


def test_the_info_console_takes_the_plain_layout(quiet_windows):
    name = _fresh_logger_name()
    logger = get_logger(name=name, level=logging.INFO, show_progress=False)
    try:
        handler = _console_handler(logger)
        assert handler._log_render.show_time is False
        assert handler._log_render.show_level is True
    finally:
        log.remove_ash_handlers(logger)
    verbose = get_logger(name=_fresh_logger_name(), level=15, show_progress=False)
    try:
        assert _console_handler(verbose)._log_render.show_time is True
    finally:
        log.remove_ash_handlers(verbose)


def test_the_console_reads_the_environment(quiet_windows, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    logger = get_logger(name=_fresh_logger_name(), show_progress=False)
    try:
        assert _console_handler(logger).console.no_color is True
    finally:
        log.remove_ash_handlers(logger)


def test_the_file_announcements_reach_the_files_they_name(quiet_windows, tmp_path):
    name = _fresh_logger_name()
    logger = get_logger(
        name=name,
        show_progress=False,
        output_dir=tmp_path,
        log_format="BOTH",
        file_log_level=log.VERBOSE_LEVEL,
    )
    try:
        tabular = (tmp_path / f"{name}.log").read_text(encoding="utf-8")
        jsonl = (tmp_path / f"{name}.log.jsonl").read_text(encoding="utf-8")
    finally:
        handlers = list(logger.handlers)
        log.remove_ash_handlers(logger)
        for handler in handlers:
            handler.close()
    assert "Logging to tabular file" in tabular, tabular
    assert "Logging to JSONL file" in jsonl, jsonl


# --------------------------------------------------------------------------- #
# The Windows filter and the CI test
# --------------------------------------------------------------------------- #


def test_ci_set_to_false_is_no_runner_on_windows(monkeypatch):
    for marker in ("CI", *log._CI_RUNNER_MARKERS):
        monkeypatch.delenv(marker, raising=False)
    monkeypatch.setattr(log.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        log.sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    )
    monkeypatch.setenv("CI", "false")
    assert log._detect_encoding_issues() is False
    monkeypatch.setenv("CI", "true")
    assert log._detect_encoding_issues() is True


def test_an_unlisted_narrow_code_page_counts_as_one_that_cannot_encode():
    assert log._console_cannot_encode("cp1251") is True
    assert log._console_cannot_encode("utf-8") is False


def _active_filter() -> WindowsSafeFilter:
    # A console that is known to write only ASCII, whatever host the test is on.
    windows_filter = WindowsSafeFilter(writes=None)
    windows_filter._active = True
    return windows_filter


def test_the_filter_drops_nothing_and_the_files_keep_the_text():
    record = _record("caf\u00e9 \u2705 %s", "r\u00e9sum\u00e9")
    assert _active_filter().filter(record)
    # The console's text: ASCII, every character kept as text or as its escape.
    assert isinstance(record.msg, ShownText)
    console = record.getMessage()
    assert console.isascii(), console
    assert "caf\\xe9 [OK] r\\xe9sum\\xe9" == console, console
    # The files' text: as logged.
    assert log._file_text(record) == "caf\u00e9 \u2705 r\u00e9sum\u00e9"
    formatter = TextFileFormatter("%(message)s")
    assert formatter.format(record) == "caf\u00e9 \u2705 r\u00e9sum\u00e9"
    assert log.JsonFormatter().format(record).count("caf\\u00e9") == 1


def test_the_last_resort_keeps_the_console_text():
    record = _record("caf\u00e9")
    assert _active_filter().filter(record)
    assert (
        TextFileFormatter("%(message)s", unfiltered=False).format(record) == "caf\\xe9"
    )


# --------------------------------------------------------------------------- #
# escape_markup's emoji split
# --------------------------------------------------------------------------- #


def test_a_code_formed_with_the_message_beside_the_value_is_not_an_emoji():
    rendered = Text.from_markup(f"{escape_markup('x :lock')}: done").plain
    assert rendered == "x :lock: done", rendered
    rendered = Text.from_markup(f"see: {escape_markup('lock: x')}").plain
    assert rendered == "see: lock: x", rendered


def test_no_split_lands_inside_an_escaped_tag():
    rendered = Text.from_markup(escape_markup("[a:b:]")).plain
    assert rendered == "[a:b:]", rendered
    # A code outside the escaped tag is still shown as written.
    assert Text.from_markup(escape_markup("[a:b:] :lock:")).plain == "[a:b:] :lock:"


# --------------------------------------------------------------------------- #
# _show_trace, the tabular formatter, delivers, the file handler, render_message
# --------------------------------------------------------------------------- #


def test_a_frame_path_that_needs_no_showing_is_left_for_rich_to_read():
    windows = "C:\\Python\\x64\\Lib\\a.py"
    stack = Stack(
        exc_type="E",
        exc_value="v",
        frames=[
            Frame(filename=windows, lineno=1, name="f"),
            Frame(filename="a\x1bb.py", lineno=2, name="g"),
        ],
    )
    log._show_trace(Trace(stacks=[stack]))
    assert stack.frames[0].filename == windows
    assert stack.frames[1].filename == "a\\x1bb.py"


def test_a_cached_traceback_comes_before_the_stack_block():
    record = _record("boom")
    record.exc_text = "Traceback (most recent call last):\n  cached\n"
    record.stack_info = "Stack (most recent call last):\n  frame"
    formatted = TextFileFormatter("%(message)s").format(record)
    assert formatted.index("cached") < formatted.index("Stack (most recent"), formatted


def test_delivers_reads_the_fallbacks_level_for_a_logger_outside_ash(monkeypatch):
    other = logging.getLogger(f"other.low-rows-{uuid.uuid4().hex[:8]}")
    monkeypatch.setattr(logging.root, "handlers", [])
    assert isinstance(logging.lastResort, log._RoutedLastResort), "the control"
    assert log.delivers(other, logging.DEBUG) is False
    assert log.delivers(other, logging.WARNING) is True


def test_a_closed_file_handler_takes_no_late_record(tmp_path):
    path = tmp_path / "late.log"
    handler = log.LogFileHandler(path.as_posix())
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.emit(_record("first"))
    handler.close()
    handler.emit(_record("late"))
    assert handler.stream is None
    assert path.read_text(encoding="utf-8") == "first\n"


def test_a_markup_records_traceback_is_rendered_as_text():
    console = Console(file=io.StringIO(), width=120)
    handler = ConsoleHandler(console=console, rich_tracebacks=False, markup=False)
    handler.setFormatter(logging.Formatter("%(message)s"))
    record = _record("[bold]scan[/bold] failed", **MARKUP)
    record.exc_text = "Traceback (most recent call last):\n  [/x] is not a tag\n"
    rendered = handler.render_message(record, handler.format(record))
    assert rendered.plain == (
        "scan failed\nTraceback (most recent call last):\n  [/x] is not a tag\n"
    ), rendered.plain
