# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Starting a run's error lines over clears the record of ASH's notes with them.

``_plugin_log_lines`` records which lines of ``errors`` ASH wrote itself, so that
``_tool_error_lines`` can tell them from the tool's. It has to be cleared
wherever ``errors`` is: only ``ScannerPluginBase.scan`` did it, and the nine
scanners that override ``scan()`` assigned ``errors`` alone. Their record kept
the notes of every earlier target, grew across targets, and a tool line of the
next target that read the same as an old note was dropped from the tool's lines.
``_reset_errors`` clears both, and those scanners call it.
"""

from __future__ import annotations

import logging

import pytest

from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit


def _plugin(tmp_path):
    return _scanner(_context(tmp_path, ()))


def test_the_reset_clears_the_error_lines_and_the_record_of_notes(tmp_path):
    scanner = _plugin(tmp_path)
    scanner._process_command_response({"returncode": 1, "stderr": "tool said no"})
    scanner._plugin_log("a note of the last target", level=logging.ERROR)
    assert scanner.errors and scanner._plugin_log_lines

    scanner._reset_errors()

    assert scanner.errors == [], scanner.errors
    assert scanner._plugin_log_lines == [], scanner._plugin_log_lines


def test_the_reset_leaves_the_output_lines_alone(tmp_path):
    scanner = _plugin(tmp_path)
    scanner.output = ["stdout of the last target"]

    scanner._reset_errors()

    assert scanner.output == ["stdout of the last target"], scanner.output


def test_an_old_note_does_not_hide_a_tool_line_that_reads_the_same(tmp_path):
    scanner = _plugin(tmp_path)
    scanner._plugin_log("same words", level=logging.ERROR)
    scanner._reset_errors()
    # The next target's tool line reads like the old note.
    scanner.errors.append("(stub) same words")

    assert scanner._tool_error_lines() == ["(stub) same words"], (
        scanner._tool_error_lines()
    )


def test_a_new_run_after_the_reset_records_its_own_notes(tmp_path):
    scanner = _plugin(tmp_path)
    scanner._plugin_log("a note of the last target", level=logging.ERROR)
    scanner._reset_errors()

    scanner._plugin_log("a note of this target", level=logging.ERROR)

    assert scanner._plugin_log_lines == ["(stub) a note of this target"], (
        scanner._plugin_log_lines
    )
    assert scanner._tool_error_lines() == [], scanner._tool_error_lines()
