# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH's own notes in ``errors`` no longer keep the tool's stderr log unread.

``_describe_scan_failure`` reads the stderr log when ``errors`` is empty: under
the default ``stderr_preference="write"`` that log is where the tool's stderr
is. A note ASH wrote itself through ``_plugin_log`` (a timeout notice) sits in
``errors`` too, so the log was never read and the
message showed ASH's note as "Stderr" and left out what the tool wrote. Now a
message whose ``errors`` hold only such notes shows them and then the log's
text. ``errors`` itself is unchanged, and the invocation record still carries
the notes.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from automated_security_helper.config.config_validator import REDACTED
from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    CANARY,
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit


def _results_file(tmp_path, log_text=None):
    """The results path of a scan, and the stderr log the scanner class names
    beside it when ``log_text`` is given."""
    results = tmp_path / "scanners" / "stub" / "results.json"
    results.parent.mkdir(parents=True)
    if log_text is not None:
        (results.parent / "StubScanner.stderr.log").write_text(
            log_text, encoding="utf-8"
        )
    return results


def test_an_ash_note_and_the_stderr_log_are_both_in_the_message(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))
    results = _results_file(tmp_path, "the tool wrote this\n")
    scanner._plugin_log("the run timed out after '5' s", level=logging.ERROR)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert "the tool wrote this" in detail, detail
    assert "the run timed out after '5' s" in detail, detail
    # ASH's note comes first, then the tool's text.
    assert detail.index("the run timed out") < detail.index("the tool wrote this")


def test_lines_the_tool_wrote_still_stand_in_for_the_log(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))
    results = _results_file(tmp_path, "the log text\n")
    scanner._process_command_response({"returncode": 1, "stderr": "tool said no"})
    scanner._plugin_log("a note beside it", level=logging.ERROR)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert "tool said no" in detail, detail
    assert "a note beside it" in detail, detail
    assert "the log text" not in detail, detail


def test_a_note_alone_is_shown_when_there_is_no_log(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))
    results = _results_file(tmp_path)
    scanner._plugin_log("offline explainer", level=logging.ERROR)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert ". Stderr: (stub) offline explainer" in detail, detail
    assert "No stderr captured" not in detail, detail


def test_a_configured_value_in_the_log_is_hidden_beside_a_note(tmp_path):
    scanner = _scanner(_context(tmp_path, [CANARY]))
    results = _results_file(tmp_path, f"cannot read {CANARY} here\n")
    scanner._plugin_log("a note of ASH's", level=logging.ERROR)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert "cannot read" in detail, detail
    assert CANARY not in detail, detail
    assert REDACTED in detail, detail


def test_the_values_hook_is_read_once_for_a_note_and_a_log(tmp_path):
    scanner = _scanner(_context(tmp_path, [CANARY]))
    scanner.exit_code = 7
    results = _results_file(tmp_path, "the tool wrote this\n")
    scanner._plugin_log("a note of ASH's", level=logging.ERROR)
    hook = scanner._values_to_redact

    with patch.object(scanner, "_values_to_redact", side_effect=hook) as read:
        detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert "the tool wrote this" in detail, detail
    assert read.call_count == 1, read.call_args_list


def test_a_values_hook_that_raises_withholds_the_note_and_names_the_log(tmp_path):
    # ``_plugin_log`` stores a note as written, so one that names a configured
    # value holds it in clear; with no values to hide it with, the note is left
    # out as the log's text is, and the log is named.
    scanner = _scanner(_context(tmp_path, [CANARY]))
    results = _results_file(tmp_path, f"cannot read {CANARY} here\n")
    scanner._plugin_log(f"a note of ASH's about {CANARY}", level=logging.ERROR)

    def _raising_hook(*_args, **_kwargs):
        raise RuntimeError("hook broke")

    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert "a note of ASH's" not in detail, detail
    assert "Stderr could not be shown; see" in detail, detail
    assert "StubScanner.stderr.log" in detail, detail
    assert "cannot read" not in detail, detail
    assert CANARY not in detail, detail
