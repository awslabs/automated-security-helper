# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The template scan's argument, timing, failure-text and record details.

One small behavior per test, each about ``ScannerPluginBase`` in
``base/scanner_plugin.py``: an extra-arg key that ends in a newline is refused,
a number extra-arg value reaches the command line as text, a SARIF
notification reader neither hangs on a FIFO nor fails on deeply nested JSON,
the per-target start and end times are not the previous target's, a values hook
that raises cannot replace the error being reported, and so on.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from unittest.mock import create_autospec, patch

import pytest

from automated_security_helper.base.scanner_plugin import (
    _VALID_FLAG_KEY_PATTERN,
    _RejectedResultError,
    _error_notifications,
)
from automated_security_helper.config.config_validator import REDACTED
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import ToolArgs, ToolExtraArg
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.log import ASH_LOGGER
from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    CANARY,
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import (
    MINIMAL_SARIF,
    _execute_writing,
    _populated_target,
    _scanner,
)

pytestmark = pytest.mark.unit

LONG_AGO = datetime(2000, 1, 1, tzinfo=timezone.utc)


def _resolved(tmp_path, *extra_args):
    scanner = _scanner(
        _context(tmp_path, ()), args=ToolArgs(extra_args=list(extra_args))
    )
    return scanner._resolve_arguments(tmp_path / "t", tmp_path / "r.json")


# -- extra args ---------------------------------------------------------------


def test_a_flag_key_ending_in_a_newline_is_not_a_valid_key():
    assert _VALID_FLAG_KEY_PATTERN.match("--flag") is not None
    assert _VALID_FLAG_KEY_PATTERN.match("--flag=value") is not None
    assert _VALID_FLAG_KEY_PATTERN.match("--flag\n") is None


def test_an_extra_arg_key_ending_in_a_newline_is_skipped(tmp_path):
    args = _resolved(tmp_path, ToolExtraArg(key="--flag\n", value="after"))

    assert "--flag\n" not in args
    assert "after" not in args


def test_number_extra_arg_values_reach_the_command_as_text(tmp_path):
    args = _resolved(
        tmp_path,
        ToolExtraArg(key="--depth", value=5),
        ToolExtraArg(key="--ratio", value=1.5),
    )

    assert all(isinstance(argument, str) for argument in args), args
    assert args[args.index("--depth") + 1] == "5"
    assert args[args.index("--ratio") + 1] == "1.5"


# -- the notification reader ----------------------------------------------------


def test_json_nested_past_the_recursion_limit_gives_no_notifications(tmp_path):
    results = tmp_path / "deep.sarif"
    results.write_text("[" * 200_000, encoding="utf-8")

    assert _error_notifications(results) == ""


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_fifo_at_the_results_path_gives_no_notifications_without_blocking(tmp_path):
    fifo = tmp_path / "results.sarif"
    os.mkfifo(fifo)
    answers = []
    reader = threading.Thread(
        target=lambda: answers.append(_error_notifications(fifo)), daemon=True
    )
    reader.start()
    try:
        reader.join(timeout=10)
        finished = not reader.is_alive()
    finally:
        # Opening a FIFO read-write never blocks and releases a reader stuck in
        # its own open, so a hung reader does not outlive the test.
        os.close(os.open(fifo, os.O_RDWR))
        reader.join(timeout=10)

    assert finished, "the reader blocked on the FIFO"
    assert answers == [""]


# -- missing-dependency reason and validate_plugin -------------------------------


def test_a_uv_run_scanner_without_uv_names_uv_not_the_path(tmp_path):
    scanner = _scanner(_context(tmp_path, ()), use_uv_tool=True)

    with (
        patch(
            "automated_security_helper.base.scanner_plugin.find_executable",
            lambda name: None,
        ),
        patch(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            return_value=None,
        ),
    ):
        reason = scanner.missing_dependency_reason()

    assert "uv" in reason, reason
    assert "was not found on PATH" not in reason, reason


def test_a_uv_run_scanner_with_uv_keeps_the_path_reason(tmp_path):
    scanner = _scanner(_context(tmp_path, ()), use_uv_tool=True)

    with (
        patch(
            "automated_security_helper.base.scanner_plugin.find_executable",
            lambda name: None,
        ),
        patch(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            return_value="/usr/bin/uv",
        ),
    ):
        reason = scanner.missing_dependency_reason()

    assert "was not found on PATH" in reason, reason


def test_validate_plugin_honors_a_reason_recorded_at_construction(tmp_path):
    scanner = _scanner(
        _context(tmp_path, ()), dependency_unavailable_reason="its cache is absent"
    )
    available = {
        "available": True,
        "validation_method": "path",
        "warnings": [],
        "errors": [],
    }

    with patch.object(
        type(scanner),
        "_validate_tool_availability_with_pre_installed",
        return_value=available,
    ):
        assert scanner.validate_plugin() is False

    assert scanner.dependencies_satisfied is False


# -- timing of one target ---------------------------------------------------------


def test_an_empty_target_is_timed_from_its_own_scan(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))
    scanner.start_time = LONG_AGO
    scanner.end_time = LONG_AGO
    empty = tmp_path / "empty"
    empty.mkdir()

    assert scanner.scan(target=empty, target_type="source") is True

    assert scanner.start_time > LONG_AGO
    assert scanner.end_time >= scanner.start_time


def test_a_failure_before_the_tool_ends_after_it_began(tmp_path):
    def refuse(scanner, target, target_type, global_ignore_paths):
        raise RuntimeError("no arguments")

    scanner = _scanner(_context(tmp_path, ()), execute_scan=refuse)
    scanner.start_time = LONG_AGO
    scanner.end_time = LONG_AGO

    with pytest.raises(ScannerError):
        scanner.scan(target=_populated_target(tmp_path), target_type="source")

    assert scanner.end_time > LONG_AGO
    assert scanner.end_time >= scanner.start_time


# -- what scan() reads and reports --------------------------------------------------


def test_a_file_target_is_scanned_not_listed(tmp_path):
    scanner = _scanner(
        _context(tmp_path, ()), execute_scan=_execute_writing(json.dumps(MINIMAL_SARIF))
    )
    target = tmp_path / "one.py"
    target.write_text("x = 1\n", encoding="utf-8")

    with patch.object(type(scanner), "_run_subprocess", return_value={"returncode": 0}):
        result = scanner.scan(target=target, target_type="source")

    assert isinstance(result, SarifReport)


def test_a_raise_before_the_tool_starts_says_the_tool_was_not_started(tmp_path):
    scanner = _scanner(
        _context(tmp_path, ()), execute_scan=_execute_writing(json.dumps(MINIMAL_SARIF))
    )

    with (
        patch.object(
            type(scanner), "_subprocess_cwd", side_effect=RuntimeError("cwd hook")
        ),
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=_populated_target(tmp_path), target_type="source")

    assert "was not started" in str(excinfo.value), str(excinfo.value)


def test_a_report_for_an_empty_results_file_gets_the_invocation_record(tmp_path):
    scanner = _scanner(_context(tmp_path, ()), execute_scan=_execute_writing(""))
    clean = SarifReport.model_validate(MINIMAL_SARIF)

    with (
        patch.object(type(scanner), "_run_subprocess", return_value={"returncode": 0}),
        patch.object(type(scanner), "_handle_empty_results", lambda self: clean),
    ):
        result = scanner.scan(target=_populated_target(tmp_path), target_type="source")

    invocations = result.runs[0].invocations
    assert invocations, "the report carries no invocation record"
    assert invocations[0].exitCode == 0


def test_a_run_less_report_for_an_empty_results_file_is_refused(tmp_path):
    scanner = _scanner(_context(tmp_path, ()), execute_scan=_execute_writing(""))

    with (
        patch.object(type(scanner), "_run_subprocess", return_value={"returncode": 0}),
        patch.object(
            type(scanner),
            "_handle_empty_results",
            lambda self: SarifReport.model_validate({}),
        ),
        pytest.raises(ScannerError, match="no SARIF run"),
    ):
        scanner.scan(target=_populated_target(tmp_path), target_type="source")


def test_a_run_less_hook_report_is_not_blamed_on_the_results_file(tmp_path):
    """The file was empty. It is the scanner's hook that answered with no run,
    and the message says so instead of pointing at the file."""
    scanner = _scanner(_context(tmp_path, ()), execute_scan=_execute_writing(""))

    with (
        patch.object(type(scanner), "_run_subprocess", return_value={"returncode": 0}),
        patch.object(
            type(scanner),
            "_handle_empty_results",
            lambda self: SarifReport.model_validate({}),
        ),
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=_populated_target(tmp_path), target_type="source")

    message = str(excinfo.value)
    assert "empty-results hook" in message, message
    assert "its results file holds no SARIF run" not in message, message


@pytest.mark.parametrize(
    "flag, said",
    [("cancelled", "cancelled"), ("result_rejected", "rejected")],
)
def test_a_code_ash_chose_is_not_reported_as_the_tools_exit(tmp_path, flag, said):
    scanner = _scanner(_context(tmp_path, ()))
    scanner.exit_code = 125
    scanner._scan_kept_flag = (flag, "recorded")

    with pytest.raises(_RejectedResultError) as excinfo:
        scanner._refuse_rejected_exit_code()

    message = str(excinfo.value)
    assert "its tool exited" not in message, message
    assert "125" in message and said in message, message


# -- the values hook cannot replace the error ------------------------------------------


def _raising_hook(*_args, **_kwargs):
    raise RuntimeError("hook broke")


def test_a_raising_values_hook_does_not_replace_a_timeout(tmp_path):
    scanner = _scanner(
        _context(tmp_path, [CANARY]), execute_scan=_execute_writing(None)
    )

    with (
        patch.object(
            type(scanner), "_run_subprocess", return_value={"timed_out": True}
        ),
        patch.object(scanner, "_values_to_redact", side_effect=_raising_hook),
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=_populated_target(tmp_path), target_type="source")

    message = str(excinfo.value)
    assert "timed out" in message, message
    assert "hook broke" not in message, message


def test_a_raising_values_hook_does_not_print_a_post_run_error_text(tmp_path):
    scanner = _scanner(
        _context(tmp_path, [CANARY]), execute_scan=_execute_writing(None)
    )
    response = {"post_run_error": True, "error": f"could not write {CANARY}"}

    with (
        patch.object(type(scanner), "_run_subprocess", return_value=response),
        patch.object(scanner, "_values_to_redact", side_effect=_raising_hook),
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=_populated_target(tmp_path), target_type="source")

    message = str(excinfo.value)
    assert "could not record" in message, message
    assert CANARY not in message and "hook broke" not in message, message


# -- failure text ---------------------------------------------------------------------


def test_error_lines_stored_as_written_are_redacted_in_the_failure_message(tmp_path):
    scanner = _scanner(_context(tmp_path, [CANARY]))
    scanner.exit_code = 2
    # As _plugin_log stores a line: as written, with no redaction.
    scanner.errors = [f"rules file {CANARY} could not be read"]

    detail = scanner._describe_scan_failure(RuntimeError("planted"), None)

    assert CANARY not in detail, detail
    assert REDACTED in detail, detail


def test_an_unreadable_stderr_log_is_not_reported_as_no_stderr(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))
    scanner.exit_code = 2
    results = tmp_path / "scanners" / "stub" / "results.json"
    results.parent.mkdir(parents=True)
    # Something that is not a regular file at the log's name: it exists, and a
    # read that refuses it is not the same as a log the tool never wrote. A
    # directory does this on every platform, where a link needs privileges.
    (results.parent / "StubScanner.stderr.log").mkdir()

    detail = scanner._describe_scan_failure(RuntimeError("planted"), results)

    assert "No stderr captured" not in detail, detail
    assert "could not be read" in detail, detail


# -- safe_scan --------------------------------------------------------------------------


def _safe_scan_failure(tmp_path):
    scanner = _scanner(_context(tmp_path, [CANARY]))
    logger = create_autospec(ASH_LOGGER)
    with (
        patch.object(
            type(scanner), "scan", side_effect=RuntimeError(f"failed at {CANARY}")
        ),
        patch("automated_security_helper.base.scanner_plugin.ASH_LOGGER", logger),
    ):
        result = scanner.safe_scan(
            target=_populated_target(tmp_path), target_type="source"
        )
    return scanner, logger, result


def test_safe_scan_hides_the_plugins_values_from_its_log_and_response(tmp_path):
    _, logger, result = _safe_scan_failure(tmp_path)

    logged = [str(call) for call in logger.error.call_args_list]
    logged += [str(call) for call in logger.debug.call_args_list]
    assert CANARY not in " ".join(logged), logged
    assert CANARY not in result["error"], result["error"]
    assert CANARY not in result["stack_trace"], result["stack_trace"]
    assert CANARY not in " ".join(result["errors"]), result["errors"]


def test_safe_scan_lists_the_failure_once(tmp_path):
    scanner, _, result = _safe_scan_failure(tmp_path)

    failure = [line for line in result["errors"] if "scanner failed" in line]
    assert len(failure) == 1, result["errors"]
    assert any("scanner failed" in line for line in scanner.errors)
