# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner killed at its timeout must be reported as timed out, on every path.

Why this file exists
--------------------
``ScannerPluginBase.scan`` says "timed out after Ns" only when the response it
gets back carries ``timed_out``. ``run_command_with_output_handling`` sets that
key, but checkov, bandit and semgrep set ``use_uv_tool=True``, so their response
is built twice more before ``scan`` sees it: ``UVToolRunner.run_tool`` turns the
dict into a ``CompletedProcess``, and ``UVToolMixin._try_uv_tool_execution``
turns that back into a dict of stdout, stderr and returncode. Both rebuilt the
result from a fixed set of fields, so the flag was dropped and a killed checkov
surfaced as ``[Errno 2] No such file or directory`` for the SARIF file it never
wrote (issue #628).

The existing test of the timeout message mocks ``_run_subprocess`` to return
``{"timed_out": True}``, which skips both rebuilds. These tests put the timeout
at ``subprocess.run`` instead, underneath every layer that has to carry it.
"""

import subprocess
import sys
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
from automated_security_helper.utils.subprocess_utils import run_command
from automated_security_helper.utils.uv_tool_runner import UVToolRunner

PluginContext.model_rebuild()

_SUBPROCESS_RUN = "automated_security_helper.utils.subprocess_utils.subprocess.run"


def _timeout(cmd, timeout, **_kwargs):
    raise subprocess.TimeoutExpired(
        cmd=cmd, timeout=timeout, output=b"", stderr=b"checkov: still parsing\n"
    )


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
    return scanner, source


@pytest.fixture
def uv_available():
    with (
        patch.object(UVToolRunner, "is_uv_available", return_value=True),
        patch.object(CheckovScanner, "validate_plugin_dependencies", return_value=True),
    ):
        yield


def test_checkov_through_uv_reports_the_timeout(checkov, uv_available):
    """The #628 case: a uv-run scanner killed at scan_timeout says so."""
    scanner, source = checkov
    assert scanner.use_uv_tool, "the test must exercise the uv path"

    with (
        patch(_SUBPROCESS_RUN, side_effect=_timeout) as run,
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=source, target_type="source")

    # The uv command, not a direct-execution fallback.
    assert run.call_count == 1
    assert run.call_args.args[0][1:3] == ["tool", "run"]
    message = str(excinfo.value)
    assert "timed out after 5.0s" in message, message
    assert "No such file or directory" not in message, message


def test_checkov_without_uv_reports_the_timeout(checkov):
    """The direct path, held to the same message so the two cannot drift."""
    scanner, source = checkov
    scanner.use_uv_tool = False

    with (
        patch.object(CheckovScanner, "validate_plugin_dependencies", return_value=True),
        patch(_SUBPROCESS_RUN, side_effect=_timeout),
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=source, target_type="source")

    assert "timed out after 5.0s" in str(excinfo.value)


def test_the_timeout_is_recorded_on_the_scanner(checkov, uv_available):
    """Scanners that override scan() never reach the template's timeout check.

    The executor reads this instead, so it has to be set by _run_subprocess,
    the one call every scanner's subprocess goes through.
    """
    scanner, source = checkov

    with patch(_SUBPROCESS_RUN, side_effect=_timeout), pytest.raises(ScannerError):
        scanner.scan(target=source, target_type="source")

    assert scanner.scan_timed_out_after == 5.0
    assert any("timed out after 5.0s" in line for line in scanner.errors)


def test_partial_stderr_of_a_killed_tool_is_kept(checkov, uv_available):
    """What the tool printed before it was killed is the best clue to why."""
    scanner, source = checkov

    with patch(_SUBPROCESS_RUN, side_effect=_timeout), pytest.raises(ScannerError):
        scanner.scan(target=source, target_type="source")

    log = scanner.results_dir / "source" / "CheckovScanner.stderr.log"
    assert log.exists(), "partial stderr of a timed-out tool was not written"
    assert "still parsing" in log.read_text()


class TestRunToolCarriesTheFlag:
    def test_with_a_results_dir(self, tmp_path):
        runner = UVToolRunner()
        with (
            patch.object(UVToolRunner, "is_uv_available", return_value=True),
            patch(_SUBPROCESS_RUN, side_effect=_timeout),
        ):
            result = runner.run_tool(
                "checkov", args=["-d", "."], results_dir=tmp_path, timeout=3
            )

        assert result.returncode == 124
        assert getattr(result, "timed_out", False) is True

    def test_without_a_results_dir(self):
        """This branch let TimeoutExpired escape, which the mixin turned into a
        silent fallback to direct execution: the tool ran a second time."""
        runner = UVToolRunner()
        with (
            patch.object(UVToolRunner, "is_uv_available", return_value=True),
            patch(
                "automated_security_helper.utils.uv_tool_runner.subprocess.run",
                side_effect=_timeout,
            ),
        ):
            result = runner.run_tool("checkov", args=["-d", "."], timeout=3)

        assert result.returncode == 124
        assert getattr(result, "timed_out", False) is True


def test_run_command_marks_a_timeout():
    """run_command keeps its -1 return code, which callers and tests pin, and
    gains the same marker so nothing has to infer a timeout from the code."""
    result = run_command(
        [sys.executable, "-c", "import time; time.sleep(30)"], timeout=1
    )

    assert result.returncode == -1
    assert getattr(result, "timed_out", False) is True
    assert isinstance(result, subprocess.CompletedProcess)


def test_a_completed_command_carries_no_marker():
    result = run_command([sys.executable, "-c", "pass"], timeout=30)

    assert result.returncode == 0
    assert getattr(result, "timed_out", False) is False
    assert not isinstance(result, subprocess_utils.TimedOutProcess)
