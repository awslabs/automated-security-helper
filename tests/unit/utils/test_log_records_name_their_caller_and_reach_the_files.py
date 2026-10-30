# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Five readings of utils/log.py.

A verbose() or trace() record names the file and line that logged it, not the
wrapper's. ASHLogger.callHandlers hands a record to every handler that was on the
logger when it started, so a handler removed under the walk does not skip the
next one. WindowsSafeFilter puts a record's arguments in ASCII as it does its
message, so a non-ASCII argument does not fail the file's write. ash.log.jsonl's
timestamps are UTC under their "Z". And ash.log is written as UTF-8 whatever the
locale.
"""

from __future__ import annotations

import inspect
import logging
import os
import time
from pathlib import Path

import pytest

from automated_security_helper.utils.log import (
    ASHLogger,
    JsonFormatter,
    LogFileHandler,
    WindowsSafeFilter,
)

pytestmark = pytest.mark.unit


class _Keep(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def ash_logger():
    logger = ASHLogger("ash.test_records_name_their_caller")
    logger.setLevel(1)
    logger.propagate = False
    keep = _Keep()
    logger.addHandler(keep)
    yield logger, keep
    logger.removeHandler(keep)


@pytest.mark.parametrize("method", ["verbose", "trace"])
def test_a_verbose_or_trace_record_names_the_caller(ash_logger, method):
    logger, keep = ash_logger

    getattr(logger, method)("from the test")
    line = inspect.currentframe().f_lineno - 1  # type: ignore[union-attr]

    (record,) = keep.records
    assert record.filename == Path(__file__).name
    assert record.lineno == line


def test_a_handler_removed_under_the_walk_does_not_skip_the_next(ash_logger):
    logger, keep = ash_logger
    logger.removeHandler(keep)

    class _RemovesTheNext(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            logger.removeHandler(self)

    logger.addHandler(_RemovesTheNext())
    logger.addHandler(keep)

    logger.info("still delivered")

    assert [record.getMessage() for record in keep.records] == ["still delivered"]


def test_the_windows_safe_filter_puts_the_arguments_in_ascii(monkeypatch):
    monkeypatch.setattr(
        "automated_security_helper.utils.log._detect_encoding_issues", lambda: True
    )
    safe = WindowsSafeFilter()
    arrow = chr(0x2192)
    record = logging.LogRecord(
        "ash", logging.INFO, "f", 1, "%s then %(k)s", (arrow + "x",), None
    )
    record.args = (arrow + "x",)

    assert safe.filter(record)
    assert record.args == ("->x",)
    record.args = {"k": "caf" + chr(0xE9)}
    assert safe.filter(record)
    # Written as its escape, not dropped: the file sinks write the record as it
    # was logged, and the console gets every character as text or as an escape.
    assert record.args == {"k": "caf\\xe9"}
    record.msg = "%(k)s"
    record.getMessage().encode("ascii")


@pytest.mark.skipif(not hasattr(time, "tzset"), reason="needs tzset")
def test_jsonl_timestamps_are_utc_under_their_z(monkeypatch):
    monkeypatch.setenv("TZ", "Etc/GMT-5")
    time.tzset()
    try:
        formatter = JsonFormatter({"timestamp": "asctime", "message": "message"})
        record = logging.LogRecord("ash", logging.INFO, "f", 1, "m", (), None)
        record.created = 1_700_000_000.0  # 2023-11-14T22:13:20Z
        record.msecs = 0.0

        written = formatter.format(record)
    finally:
        monkeypatch.delenv("TZ", raising=False)
        time.tzset()

    assert '"timestamp": "2023-11-14T22:13:20.000Z"' in written, written


def test_ash_log_is_written_as_utf8_whatever_the_locale(tmp_path, monkeypatch):
    from automated_security_helper.utils.sandbox import fs_guard

    opened = {}
    real_open = fs_guard.open_for_write

    def record_encoding(path, *args, **kwargs):
        opened["encoding"] = kwargs.get("encoding")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(fs_guard, "open_for_write", record_encoding)
    handler = LogFileHandler(os.fspath(tmp_path / "ash.log"))
    try:
        handler.emit(
            logging.LogRecord("ash", logging.INFO, "f", 1, "caf" + chr(0xE9), (), None)
        )
        handler.flush()
    finally:
        handler.close()

    # The handler's own encoding, not only the open's: since Python 3.10
    # FileHandler records its default as the name "locale", and a fallback at
    # the open that read "self.encoding or 'utf-8'" kept that name.
    assert handler.encoding == "utf-8"
    assert opened["encoding"] == "utf-8"
    # Read back strict: the bytes on disk are UTF-8 whatever the locale was.
    written = (tmp_path / "ash.log").read_bytes().decode("utf-8")
    assert written.rstrip() == "caf" + chr(0xE9)


def test_a_callers_encoding_is_kept(tmp_path):
    handler = LogFileHandler(os.fspath(tmp_path / "ash.log"), encoding="latin-1")
    try:
        assert handler.encoding == "latin-1"
    finally:
        handler.close()
