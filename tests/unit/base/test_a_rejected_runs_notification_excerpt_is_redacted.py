# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A rejected run's SARIF notification excerpt is redacted before it is cut.

``_describe_scan_failure`` quotes the error-level toolExecutionNotifications
of a rejected run's results file, the tool's own words about why it failed.
The stderr excerpt beside it is redacted with the scanner's values before its
cut; the notification excerpt was cut with no redaction at all, so a tool that
echoed a configured value (a path it could not read, say) printed it into the
failure message in the clear. The reader now takes the same values and
redacts BEFORE the cut. On a rejected result (whose stderr log is named, not
read) a values hook that gives no usable answer leaves the notifications
unquoted with the file named; the hook is read at most once per failure.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    _STDERR_EXCERPT_LIMIT,
    _RejectedResultError,
    _error_notifications,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_validator import REDACTED
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.exceptions import ScannerError
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit

#: Long enough that redaction replaces it anywhere, so these checks measure
#: the sink, not the band a short value falls in.
CANARY = "/nonexistent/ENVCANARY-77aa/rules.yaml"


def _context(tmp_path, environment_values):
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )
    context.config._environment_values = list(environment_values)
    return context


def _results_file(tmp_path, *texts):
    results = tmp_path / "results.sarif"
    results.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "invocations": [
                            {
                                "toolExecutionNotifications": [
                                    {"level": "error", "message": {"text": text}}
                                    for text in texts
                                ]
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return results


def test_a_configured_value_in_a_notification_is_redacted(tmp_path):
    scanner = _scanner(_context(tmp_path, [CANARY]))
    scanner.exit_code = 2
    scanner.errors = []
    results = _results_file(tmp_path, f"rules file {CANARY} could not be read")

    detail = scanner._describe_scan_failure(ScannerError("planted"), results)

    assert "reports:" in detail, detail
    assert CANARY not in detail, detail
    assert REDACTED in detail, detail
    assert "could not be read" in detail, detail


def test_the_reader_redacts_before_the_cut(tmp_path):
    # A value that straddles the cut: redaction after the cut would leave its
    # first half in the clear. The head is computed from the marker's length, so
    # the test does not depend on what the marker is: the raw value starts a few
    # characters before the limit and runs past it, the redacted marker ends
    # just inside it, and the " tail" after it pushes the text past the limit.
    assert len(CANARY) > len(REDACTED) + 2, "the raw value must straddle the cut"
    head = "x" * (_STDERR_EXCERPT_LIMIT - len(REDACTED) - 3)
    results = _results_file(tmp_path, f"{head} {CANARY} tail")

    shown = _error_notifications(results, [CANARY])

    assert CANARY not in shown, shown[-200:]
    assert "ENVCANARY" not in shown, shown[-200:]
    assert REDACTED in shown, shown[-200:]
    # The redacted text is longer than the limit, so the cut always happens;
    # a "tail" ending would mean the value was not redacted first.
    assert shown.endswith(" ...[truncated]"), shown[-60:]
    assert "/nonexist" not in shown, shown[-200:]


def _raising_hook(*_args, **_kwargs):
    raise RuntimeError("hook broke")


def _none_hook(*_args, **_kwargs):
    return None


@pytest.mark.parametrize("hook", [_raising_hook, _none_hook], ids=["raises", "none"])
def test_a_values_hook_with_no_usable_answer_leaves_the_notifications_unquoted(
    tmp_path, hook
):
    # A REJECTED result: its stderr log is named, never read, so the only
    # text the hook guards here is the notification excerpt. (On a
    # non-rejected failure the stderr block reads the hook first and returns
    # with the log named before the notifications are reached.) A hook that
    # raises and one that answers None are the same broken answer.
    scanner = _scanner(_context(tmp_path, [CANARY]))
    scanner.exit_code = 2
    scanner.errors = []
    results = _results_file(tmp_path, f"rules file {CANARY} could not be read")

    with patch.object(scanner, "_values_to_redact", side_effect=hook):
        detail = scanner._describe_scan_failure(
            _RejectedResultError("planted"), results
        )

    assert CANARY not in detail, detail
    assert "reports:" not in detail, detail
    # The file is still named, so the reader can open it.
    assert results.as_posix() in detail, detail


def test_the_hook_is_read_once_for_a_failure_that_quotes_both(tmp_path):
    scanner = _scanner(_context(tmp_path, [CANARY]))
    scanner.exit_code = 2
    scanner.errors = []
    results = _results_file(tmp_path, f"rules file {CANARY} could not be read")
    # The tool's stderr log sits beside the results, named for the scanner class;
    # without it only the notifications are quoted, not both.
    log = tmp_path / f"{type(scanner).__name__}.stderr.log"
    log.write_text(f"error: cannot open {CANARY} LOGLINE-9d4\n", encoding="utf-8")
    hook = scanner._values_to_redact

    with patch.object(scanner, "_values_to_redact", side_effect=hook) as read:
        detail = scanner._describe_scan_failure(ScannerError("planted"), results)

    assert read.call_count == 1, read.call_args_list
    assert "reports:" in detail and CANARY not in detail, detail
    # Both blocks quoted: the notification above, and the log's own line.
    assert "LOGLINE-9d4" in detail, detail
    assert "could not be read" in detail, detail
