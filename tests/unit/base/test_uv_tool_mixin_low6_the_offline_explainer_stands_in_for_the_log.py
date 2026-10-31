# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The offline resolve explainer stands in for the stderr log it quotes.

The explainer reads the scanner's stderr log, finds uv's resolver error, and
writes a cause-first message that ends "uv said: <the log's text>". It is
written through ``_plugin_log``, which records a line as one of ASH's own notes,
and the failure message reads the stderr log beside such notes. For the
explainer that read the same log a second time: uv's text was printed twice, and
the cut of the pair could drop the log's last lines. The explainer's line now
counts as the tool's text, so the failure message shows it once and leaves the
log unread. A note that quotes nothing, such as a timeout notice, is still one of
ASH's notes and still leaves the log to be read.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit

#: A word only uv's resolver text holds, so its count is the count of copies of
#: that text in the message.
RESOLVER_WORD = "zq-resolver-marker-77"

LOG_NAME = "StubScanner.stderr.log"


def _offline_scanner(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))
    scanner.command = "faketool"
    return scanner


def _results_with_a_resolve_failure(tmp_path):
    """The results path of a scan whose stderr log holds uv's resolver error."""
    results = tmp_path / "scanners" / "stub" / "results.json"
    results.parent.mkdir(parents=True)
    (results.parent / LOG_NAME).write_text(
        "error: No solution found when resolving dependencies:\n"
        f"  Because faketool depends on {RESOLVER_WORD} which cannot be found\n",
        encoding="utf-8",
    )
    return results


def _explained(scanner, results):
    """Run the explainer as ``_uv_response`` does: offline, the run's stderr
    empty (it went to the log), the results directory beside the log."""
    with (
        patch.object(type(scanner), "_is_offline_mode", return_value=True),
        patch.object(type(scanner), "_uv_from_spec", return_value="faketool==1.0"),
    ):
        scanner._explain_offline_resolve_failure(
            {"returncode": 1, "stderr": ""}, results.parent
        )


def test_the_explainer_ran_and_quotes_the_log(tmp_path):
    scanner = _offline_scanner(tmp_path)
    results = _results_with_a_resolve_failure(tmp_path)

    _explained(scanner, results)

    assert scanner.errors, "the explainer did not run"
    assert "uv said:" in scanner.errors[0], scanner.errors
    assert RESOLVER_WORD in scanner.errors[0], scanner.errors


def test_the_explainer_line_counts_as_the_tools_text(tmp_path):
    scanner = _offline_scanner(tmp_path)
    results = _results_with_a_resolve_failure(tmp_path)

    _explained(scanner, results)

    assert scanner._tool_error_lines() == scanner.errors, scanner._tool_error_lines()


def test_the_failure_message_shows_the_resolver_text_once(tmp_path):
    scanner = _offline_scanner(tmp_path)
    results = _results_with_a_resolve_failure(tmp_path)
    _explained(scanner, results)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert detail.count(RESOLVER_WORD) == 1, detail
    assert "Offline mode: uv could not resolve" in detail, detail


def test_a_timeout_note_beside_the_explainer_is_still_one_of_ashs_notes(tmp_path):
    scanner = _offline_scanner(tmp_path)
    results = _results_with_a_resolve_failure(tmp_path)
    _explained(scanner, results)
    scanner._plugin_log("the run timed out after '5' s", level=logging.ERROR)

    tool_lines = scanner._tool_error_lines()

    assert len(tool_lines) == 1, tool_lines
    assert "uv said:" in tool_lines[0], tool_lines
    assert "the run timed out" in scanner.errors[-1], scanner.errors


def test_a_note_that_quotes_nothing_still_leaves_the_log_to_be_read(tmp_path):
    """The control: only the explainer stands in for the log."""
    scanner = _offline_scanner(tmp_path)
    results = _results_with_a_resolve_failure(tmp_path)
    scanner._plugin_log("the run timed out after '5' s", level=logging.ERROR)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert "the run timed out after '5' s" in detail, detail
    assert detail.count(RESOLVER_WORD) == 1, detail
