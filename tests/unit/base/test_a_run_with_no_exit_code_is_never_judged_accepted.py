# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run that reported no exit code is never judged or printed as exit 0.

``exit_code`` starts at 0 and only an integer returncode moves it, so a run
whose response carried none -- an unstopped timeout keeps ``returncode: None``
because the tool never finished -- was judged through ``_exit_code_accepted``
as an accepted 0, and the failure description printed ``(exit code 0: an
accepted exit code...)`` for a tool that is in fact still running. The
attribute now records the timeout's own code (coreutils' 124) for judging,
the response keeps ``None`` so no printer invents a code the tool never
returned, the failure description says there is no exit code instead of
printing one, and the scan template resets the attribute to ``None`` at the
top, as its declaration always promised, so a scan that never reached its
tool does not carry the previous target's code.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import COULD_NOT_STOP_MARKER

PluginContext.model_rebuild()

#: The runner's response for a timeout whose stop did not end the child.
_STOP_FAILED = {
    "stdout": "",
    "stderr": "",
    "returncode": None,
    "timed_out": True,
    "could_not_stop": True,
    "could_not_stop_pid": 4242,
    "error": (
        "Command timed out after 5s: tool; "
        f"{COULD_NOT_STOP_MARKER} 4242), which may still be running"
    ),
}

#: The control: the same timeout, stopped at the limit, the tool gone.
_STOPPED_AT_THE_LIMIT = {
    "stdout": "",
    "stderr": "",
    "returncode": 124,
    "timed_out": True,
    "error": "Command timed out after 5s: tool",
}


@pytest.fixture
def checkov(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    scanner = CheckovScanner(
        context=context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(scan_timeout=5)
        ),
    )
    scanner.dependencies_satisfied = True
    scanner.use_uv_tool = False
    return scanner, source


def _template_scan(scanner, source, response):
    with (
        patch.object(CheckovScanner, "validate_plugin_dependencies", return_value=True),
        patch.object(
            subprocess_utils,
            "run_command_with_output_handling",
            return_value=dict(response),
        ),
        pytest.raises(ScannerError),
    ):
        scanner.scan(target=source, target_type="source")


def test_an_unstopped_timeout_is_not_judged_accepted(checkov):
    """The judging surface: a could-not-stop run must never read as an
    accepted exit 0. The tool never finished, so there is nothing to accept."""
    scanner, source = checkov
    _template_scan(scanner, source, _STOP_FAILED)

    assert scanner.exit_code != 0, (
        "the 0 default survived a run whose response carried no code"
    )
    assert scanner._exit_code_accepted() is False, scanner.exit_code


def test_an_unstopped_timeout_never_prints_a_code(checkov):
    """The printing surface: the failure description must not claim an exit
    code for a tool that never returned one."""
    scanner, source = checkov
    _template_scan(scanner, source, _STOP_FAILED)

    detail = scanner._describe_scan_failure(RuntimeError("boom"), None)
    assert "(exit code" not in detail, detail
    assert "no exit code" in detail, detail


def test_a_scan_that_never_reaches_its_tool_reports_no_exit_code(checkov):
    """The promised reset: a scan that never started its tool does not carry
    the previous target's code.

    The declaration's comment says scan() resets the attribute to None at the
    top, so a target the scanner rejects before any run reports no exit code
    rather than the last target's."""
    scanner, source = checkov
    scanner.exit_code = 7
    with (
        patch.object(CheckovScanner, "validate_plugin_dependencies", return_value=True),
        patch.object(
            CheckovScanner,
            "_execute_scan",
            side_effect=RuntimeError("this target was rejected before any run"),
        ),
        pytest.raises(ScannerError),
    ):
        scanner.scan(target=source, target_type="source")

    assert scanner.exit_code is None, scanner.exit_code


def test_a_stopped_timeout_keeps_its_real_code(checkov):
    """The control: a stop that worked recorded the runner's 124, which is
    judged and printed as the code it is."""
    scanner, source = checkov
    _template_scan(scanner, source, _STOPPED_AT_THE_LIMIT)

    assert scanner.exit_code == 124, scanner.exit_code
    assert scanner._exit_code_accepted() is False

    detail = scanner._describe_scan_failure(RuntimeError("boom"), None)
    assert "(exit code 124" in detail, detail


def test_a_real_accepted_code_still_judges_accepted(checkov):
    """The other control: judging real codes is unchanged."""
    scanner, _ = checkov
    scanner.exit_code = 1
    assert scanner._exit_code_accepted() is True


@pytest.mark.parametrize(
    ("flag", "code"),
    [
        ("timed_out", 124),
        ("cancelled", 130),
        ("result_rejected", 125),
        ("post_run_error", 125),
        ("signaled", 125),
        ("spawn_failed", 127),
    ],
)
def test_a_codeless_flagged_response_records_the_flags_own_code(checkov, flag, code):
    """Every codeless flagged outcome judges by its flag's own code, the one
    shell convention gives the same outcome, not only the timeout's 124."""
    scanner, _ = checkov
    scanner.exit_code = None
    scanner._record_target_exit_code({"returncode": None, flag: True})
    assert scanner.exit_code == code, (flag, scanner.exit_code)


def test_a_codeless_response_with_several_flags_records_the_first(checkov):
    """Precedence follows the runner's own flag order: a timed-out run whose
    post-run step also failed judges as the timeout."""
    scanner, _ = checkov
    scanner.exit_code = None
    scanner._record_target_exit_code(
        {"returncode": None, "timed_out": True, "post_run_error": True}
    )
    assert scanner.exit_code == 124, scanner.exit_code


def test_a_codeless_unflagged_response_still_records_nothing(checkov):
    """The control: a response with no code and no flag (a test double)
    leaves the attribute as it is."""
    scanner, _ = checkov
    scanner.exit_code = None
    scanner._record_target_exit_code({"returncode": None})
    assert scanner.exit_code is None, scanner.exit_code


@pytest.mark.parametrize(
    ("flag", "code"),
    [
        ("timed_out", 124),
        ("cancelled", 130),
        ("result_rejected", 125),
        ("post_run_error", 125),
        ("signaled", 125),
        ("spawn_failed", 127),
    ],
)
def test_the_accumulator_grades_a_codeless_flagged_response(checkov, flag, code):
    """The worst-code accumulator reads the same flag table: a scanner that
    overrides scan() reaches only this reader, and its 0 default must not
    survive a codeless flagged run as an accepted exit 0."""
    scanner, _ = checkov
    scanner.exit_code = 0
    scanner._process_command_response(
        {"stdout": "", "stderr": "", "returncode": None, flag: True}
    )
    assert scanner.exit_code == code, (flag, scanner.exit_code)


def test_the_accumulator_leaves_a_codeless_unflagged_response_alone(checkov):
    """The control: a codeless response with no flag (a test double) still
    contributes nothing to the accumulated code."""
    scanner, _ = checkov
    scanner.exit_code = 0
    scanner._process_command_response({"stdout": "", "stderr": "", "returncode": None})
    assert scanner.exit_code == 0, scanner.exit_code


def test_a_response_missing_its_returncode_is_not_judged_successful(checkov):
    """The accumulator defaulted a MISSING returncode key to 1, and scanners
    whose accepted codes include 1 judged such a response as "ran and found
    issues". A response with no returncode key at all is not a run's verdict:
    it is judged from its lead flag, and with no flag it is graded as the
    wrapper's own failure (125), never as an accepted code."""
    scanner, _ = checkov
    scanner.exit_code = 0
    scanner._process_command_response({"stdout": "", "stderr": ""})
    assert scanner.exit_code == 125, scanner.exit_code

    scanner.exit_code = 0
    scanner._process_command_response({"stdout": "", "stderr": "", "timed_out": True})
    assert scanner.exit_code == 124, scanner.exit_code


@pytest.mark.parametrize("stand_in", [False, True], ids=["false", "true"])
def test_a_bool_returncode_is_not_a_code(checkov, stand_in):
    """bool is an int subclass, so a response whose returncode is False read
    as an accepted 0 through the integer comparison -- and True as a 1 some
    accepted sets admit. A bool is a flag's stand-in, never a code a process
    returned: with no flag it grades as the wrapper's own failure, like a
    missing key."""
    scanner, _ = checkov
    scanner.exit_code = 0
    scanner._process_command_response(
        {"stdout": "", "stderr": "", "returncode": stand_in}
    )
    assert scanner.exit_code == 125, (stand_in, scanner.exit_code)


def test_a_bool_returncode_with_a_flag_grades_by_the_flag(checkov):
    scanner, _ = checkov
    scanner.exit_code = 0
    scanner._process_command_response(
        {"stdout": "", "stderr": "", "returncode": False, "timed_out": True}
    )
    assert scanner.exit_code == 124, scanner.exit_code


def test_the_recorder_treats_a_bool_code_as_codeless(checkov):
    """The per-target recorder already refuses to record a bool; it must also
    fall to the flag the response carries, as it does for a None, so a
    flagged run whose double left a bool is still graded by its flag."""
    scanner, _ = checkov
    scanner.exit_code = None
    scanner._record_target_exit_code({"returncode": False, "timed_out": True})
    assert scanner.exit_code == 124, scanner.exit_code


def test_a_raise_after_a_bool_coded_run_still_grades_it(checkov):
    """The error handler's recorder checked ``isinstance(returncode, int)``,
    which a bool passes: a cancelled run whose double left ``False`` was
    recorded as an accepted-looking 0 instead of the flag's own code."""
    scanner, source = checkov
    cancelled = {
        "stdout": "",
        "stderr": "",
        "returncode": False,
        "cancelled": True,
        "error": "Command was cancelled: tool",
    }
    with (
        patch.object(CheckovScanner, "validate_plugin_dependencies", return_value=True),
        patch.object(
            subprocess_utils,
            "run_command_with_output_handling",
            return_value=dict(cancelled),
        ),
        patch.object(
            CheckovScanner,
            "_process_command_response",
            side_effect=RuntimeError("the record step raised"),
        ),
        pytest.raises(ScannerError),
    ):
        scanner.scan(target=source, target_type="source")

    assert scanner.exit_code == 130, scanner.exit_code


def test_the_public_flag_order_is_the_code_tables_flag_column():
    """Result helpers downstream take the judging precedence from the public
    name, so it must be the code table's own flag column -- a row added to or
    moved in the table without the public name following would hand consumers
    a different precedence than judging uses. The members must also be exactly
    the response flags; only the order is the table's own."""
    assert subprocess_utils.FLAG_ORDER == tuple(
        flag for flag, _ in subprocess_utils._CODELESS_FLAG_CODES
    )
    assert "signaled" in subprocess_utils.FLAG_ORDER
    assert set(subprocess_utils.FLAG_ORDER) == set(subprocess_utils.RESPONSE_FLAGS)


def test_a_raise_after_a_flagged_codeless_run_still_grades_it(checkov):
    """The error handler's recorder: a raise between the run and its records
    re-runs them in the handler, which read only an integer returncode, so a
    flagged codeless run that then raised left exit_code at its default."""
    scanner, source = checkov
    cancelled = {
        "stdout": "",
        "stderr": "",
        "returncode": None,
        "cancelled": True,
        "error": "Command was cancelled: tool",
    }
    with (
        patch.object(CheckovScanner, "validate_plugin_dependencies", return_value=True),
        patch.object(
            subprocess_utils,
            "run_command_with_output_handling",
            return_value=dict(cancelled),
        ),
        patch.object(
            CheckovScanner,
            "_process_command_response",
            side_effect=RuntimeError("the record step raised"),
        ),
        pytest.raises(ScannerError),
    ):
        scanner.scan(target=source, target_type="source")

    assert scanner.exit_code == 130, scanner.exit_code
