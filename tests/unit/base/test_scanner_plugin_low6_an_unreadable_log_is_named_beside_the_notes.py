# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stderr log that cannot be read is named even when ASH's notes are shown.

``_describe_scan_failure`` says "Stderr could not be read; see <log>" when the
tool's stderr log is there and the bounded read of it fails (a link or a FIFO at
the name, a permission). When ``errors`` held only ASH's own notes, the notes
were shown as "Stderr" and that sentence was skipped, so the message did not say
that a log existed and could not be read. The notes are still shown, and the
unreadable log is named after them.
"""

from __future__ import annotations

import logging

import pytest

from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit

LOG_NAME = "StubScanner.stderr.log"


def _results_file(tmp_path, *, log):
    """The results path of a scan; ``log`` is how the scanner's stderr log is
    left beside it: ``"directory"`` (there, and not readable), ``"file"`` or
    ``None`` (not written)."""
    results = tmp_path / "scanners" / "stub" / "results.json"
    results.parent.mkdir(parents=True)
    if log == "directory":
        (results.parent / LOG_NAME).mkdir()
    elif log == "file":
        (results.parent / LOG_NAME).write_text(
            "the tool wrote this\n", encoding="utf-8"
        )
    return results


def test_a_note_and_an_unreadable_log_both_reach_the_message(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))
    results = _results_file(tmp_path, log="directory")
    scanner._plugin_log("the run timed out after '5' s", level=logging.ERROR)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert "the run timed out after '5' s" in detail, detail
    assert "could not be read; see" in detail, detail
    assert LOG_NAME in detail, detail
    assert "No stderr captured" not in detail, detail
    # The note leads and the log is named after it.
    assert detail.index("the run timed out") < detail.index("could not be read")


def test_an_unreadable_log_with_no_note_is_named_as_before(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))
    results = _results_file(tmp_path, log="directory")

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert ". Stderr could not be read; see" in detail, detail
    assert LOG_NAME in detail, detail


def test_a_note_beside_a_readable_log_does_not_say_it_could_not_be_read(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))
    results = _results_file(tmp_path, log="file")
    scanner._plugin_log("the run timed out after '5' s", level=logging.ERROR)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert "the tool wrote this" in detail, detail
    assert "could not be read" not in detail, detail


def test_a_note_with_no_log_written_does_not_say_it_could_not_be_read(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))
    results = _results_file(tmp_path, log=None)
    scanner._plugin_log("the run timed out after '5' s", level=logging.ERROR)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert "the run timed out after '5' s" in detail, detail
    assert "could not be read" not in detail, detail


def test_lines_the_tool_wrote_leave_an_unreadable_log_unread(tmp_path):
    # The log is only read when the tool's own lines are missing, so a log that
    # cannot be read is not a fact about this message.
    scanner = _scanner(_context(tmp_path, ()))
    results = _results_file(tmp_path, log="directory")
    scanner._process_command_response({"returncode": 1, "stderr": "tool said no"})

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert "tool said no" in detail, detail
    assert "could not be read" not in detail, detail
