# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failing values hook leaves the scanner's stderr lines out of the failure text.

``_describe_scan_failure`` quotes the lines in ``errors`` after hiding the
plugin's values from them. When the values hook raised or gave no usable answer
there was nothing to hide them with, and the lines were quoted as they were:
the log branch below already withholds the stderr log in that case and names
it, so the same failure showed the log's text withheld and ``errors`` in the
clear. The lines are now withheld too, and the text names the stderr log the
way the log branch does.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from automated_security_helper.base.scanner_plugin import _RejectedResultError
from automated_security_helper.config.config_validator import REDACTED
from automated_security_helper.core.exceptions import ScannerError
from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    CANARY,
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit


def _raising_hook(*_args, **_kwargs):
    raise RuntimeError("hook broke")


def _scanner_with_tool_stderr(tmp_path):
    scanner = _scanner(_context(tmp_path, [CANARY]))
    scanner.exit_code = 2
    scanner.errors = [f"cannot read {CANARY}"]
    return scanner


def test_a_working_hook_still_redacts_the_stderr_lines(tmp_path):
    scanner = _scanner_with_tool_stderr(tmp_path)
    results = tmp_path / "results.sarif"

    detail = scanner._describe_scan_failure(ScannerError("planted"), results)

    assert CANARY not in detail, detail
    assert REDACTED in detail, detail
    assert "cannot read" in detail, detail


def test_a_raising_hook_withholds_the_stderr_lines_and_names_the_log(tmp_path):
    scanner = _scanner_with_tool_stderr(tmp_path)
    results = tmp_path / "results.sarif"

    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        detail = scanner._describe_scan_failure(ScannerError("planted"), results)

    assert CANARY not in detail, detail
    assert "cannot read" not in detail, detail
    assert "Stderr could not be shown" in detail, detail
    assert f"{scanner.__class__.__name__}.stderr.log" in detail, detail


def test_a_raising_hook_withholds_the_lines_with_no_results_file_to_name(tmp_path):
    scanner = _scanner_with_tool_stderr(tmp_path)

    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        detail = scanner._describe_scan_failure(ScannerError("planted"), None)

    assert CANARY not in detail, detail
    assert "Stderr could not be shown" in detail, detail
    assert "No stderr captured" not in detail, detail


def test_a_raising_hook_withholds_the_lines_of_a_rejected_result(tmp_path):
    scanner = _scanner_with_tool_stderr(tmp_path)
    results = tmp_path / "results.sarif"

    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        detail = scanner._describe_scan_failure(
            _RejectedResultError("planted"), results
        )

    assert CANARY not in detail, detail
    assert "Stderr could not be shown" in detail, detail


def test_a_raising_hook_withholds_a_note_ash_wrote_itself(tmp_path):
    # ``_plugin_log`` stores its message as written, so a note that names a
    # configured value is in ``errors`` in the clear; with no tool stderr beside
    # it, it is quoted ahead of the stderr log's text.
    scanner = _scanner(_context(tmp_path, [CANARY]))
    scanner.exit_code = 2
    scanner.errors = []
    scanner._plugin_log(
        f"offline rules at {CANARY} were not found", level=logging.ERROR
    )
    results = tmp_path / "results.sarif"

    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        detail = scanner._describe_scan_failure(ScannerError("planted"), results)

    assert CANARY not in detail, detail
    assert "offline rules" not in detail, detail
    assert "Stderr could not be shown" in detail, detail
