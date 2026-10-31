# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The display's fallback console sink reports a failed record shown.

``LiveProgressDisplay._console_sink`` built a plain ``logging.StreamHandler``.
When such a handler cannot write a record, ``logging.Handler.handleError``
prints the record's traceback and arguments to stderr as given, and an
argument's text can carry a terminal control. Every other handler ASH puts on
its logger reports that through ``ShownHandlerErrors``; the sink now does too.
"""

from __future__ import annotations

import io
import logging

import pytest

from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.utils.log import ShownHandlerErrors

pytestmark = pytest.mark.unit

ESC = "\x1b"


class _Unprintable:
    """A logged argument whose text cannot be made: its error carries ESC."""

    def __str__(self) -> str:
        raise RuntimeError(f"hostile {ESC}[2J text")


def test_the_console_sink_reports_a_failed_record_shown(monkeypatch, capsys):
    monkeypatch.setattr(logging, "raiseExceptions", True)
    sink = LiveProgressDisplay._console_sink(logging.INFO)
    # Red at the base: a plain StreamHandler, whose handleError prints as given.
    assert isinstance(sink, ShownHandlerErrors)
    assert isinstance(sink, logging.StreamHandler)
    assert sink.level == logging.INFO
    sink.setStream(io.StringIO())

    record = logging.LogRecord(
        "ash", logging.WARNING, "app.py", 7, "value %s", (_Unprintable(),), None
    )
    try:
        sink.handle(record)
    finally:
        sink.close()

    err = capsys.readouterr().err
    assert "Logging error" in err, err
    assert "Logged from file app.py, line 7" in err, err
    assert ESC not in err, err
    assert "\\x1b" in err, err
