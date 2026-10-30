# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The lines ``_plugin_log`` adds to ``errors`` are told apart from the tool's.

``errors`` is one list. ``_process_command_response`` adds the lines of a tool's
stderr to it, and ``_plugin_log`` adds ASH's own notes (a timeout notice, a
message about a skipped target). A reader that has to decide whether the tool
said anything could not tell the two apart. ``_tool_error_lines`` answers: the
lines of ``errors`` that no ``_plugin_log`` call wrote. ``errors`` itself is
unchanged for every other reader.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from automated_security_helper.base.plugin_base import PluginBase
from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit


def _plugin(tmp_path):
    return _scanner(_context(tmp_path, ()))


def test_an_error_note_is_in_errors_and_is_not_a_tool_line(tmp_path):
    scanner = _plugin(tmp_path)

    scanner._plugin_log("the run timed out", level=logging.ERROR)

    assert scanner.errors == ["(stub) the run timed out"], scanner.errors
    assert scanner._tool_error_lines() == [], scanner._tool_error_lines()


def test_a_note_written_to_the_stderr_stream_is_not_a_tool_line(tmp_path):
    scanner = _plugin(tmp_path)

    scanner._plugin_log(
        "nothing to scan here", level=logging.INFO, append_to_stream="stderr"
    )

    assert scanner.errors == ["(stub) nothing to scan here"], scanner.errors
    assert scanner._tool_error_lines() == [], scanner._tool_error_lines()


def test_a_note_below_error_that_is_not_streamed_is_in_neither(tmp_path):
    scanner = _plugin(tmp_path)

    scanner._plugin_log("all is well", level=logging.INFO)

    assert scanner.errors == [], scanner.errors
    assert scanner._tool_error_lines() == [], scanner._tool_error_lines()


def test_the_tools_lines_stay_in_order_around_a_note(tmp_path):
    scanner = _plugin(tmp_path)
    scanner._process_command_response({"returncode": 1, "stderr": "first\nsecond"})
    scanner._plugin_log("a note between", level=logging.ERROR)
    scanner._process_command_response({"returncode": 1, "stderr": "third"})

    assert scanner.errors == [
        "first",
        "second",
        "(stub) a note between",
        "third",
    ], scanner.errors
    assert scanner._tool_error_lines() == ["first", "second", "third"], (
        scanner._tool_error_lines()
    )


def test_a_tool_line_equal_to_a_note_is_dropped_only_as_often_as_the_note_was_written(
    tmp_path,
):
    scanner = _plugin(tmp_path)
    scanner.errors.append("(stub) same words")
    scanner._plugin_log("same words", level=logging.ERROR)

    assert scanner.errors == ["(stub) same words", "(stub) same words"]
    assert scanner._tool_error_lines() == ["(stub) same words"], (
        scanner._tool_error_lines()
    )


def test_lines_set_directly_on_errors_are_the_tools(tmp_path):
    scanner = _plugin(tmp_path)
    scanner.errors = ["set by a test double"]

    assert scanner._tool_error_lines() == ["set by a test double"]


def test_a_new_scan_forgets_the_notes_of_the_last_one(tmp_path):
    scanner = _plugin(tmp_path)
    scanner._plugin_log("a note of the last target", level=logging.ERROR)
    empty = tmp_path / "converted"
    empty.mkdir()

    scanner.scan(empty, "converted")

    assert "(stub) a note of the last target" not in scanner._plugin_log_lines
    assert "(stub) a note of the last target" not in scanner.errors
    assert scanner._tool_error_lines() == [], scanner._tool_error_lines()


def test_the_unbound_call_on_a_stand_in_still_appends_to_errors():
    plugin = SimpleNamespace(
        config=SimpleNamespace(name="stand-in"), errors=[], output=[]
    )

    PluginBase._plugin_log(plugin, "boom", level=logging.ERROR)

    assert plugin.errors == ["(stand-in) boom"], plugin.errors
