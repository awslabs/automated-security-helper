# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A timeout whose stop failed is never reported as "was killed" by the plugin.

The scan template's timeout raise and the plugin's own timeout log line both
said "was killed" for every timed-out run. When ASH's stop did not end the
tool, that is the one claim the operator must not read: the process may still
be running, holding files and burning time. Both texts now say so from the
response's recorded could-not-stop state -- the flag, or a timeout with no
exit code -- never from a text match; a timeout whose stop worked keeps
"was killed". The executor's two sites carry the same contract in
tests/unit/core/phases/test_a_timeout_ash_could_not_stop_is_never_said_killed.py.
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

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

#: The runner's response for a timeout whose stop did not end the child: the
#: flag kept, no exit code, the reason naming the pid.
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
    """A template-scan scanner on the direct path, like the timeout-signal cells."""
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
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=source, target_type="source")
    return str(excinfo.value)


def test_the_template_raise_says_it_may_still_be_running(checkov):
    """A could-not-stop timeout through the scan template: the raise and the
    recorded error lines say the tool may still be running, and nothing says
    it was killed."""
    scanner, source = checkov
    message = _template_scan(scanner, source, _STOP_FAILED)

    assert "may still be running" in message, message
    assert "was killed" not in message, message
    killed = [line for line in scanner.errors if "was killed" in line]
    assert killed == [], killed


def test_a_stopped_timeout_keeps_was_killed_in_the_template_raise(checkov):
    """The control: a timeout whose stop worked IS a killed tool."""
    scanner, source = checkov
    message = _template_scan(scanner, source, _STOPPED_AT_THE_LIMIT)

    assert "was killed" in message, message
    assert "may still be running" not in message, message
    assert not any("may still be running" in line for line in scanner.errors)


def test_the_recorded_timeout_line_says_it_may_still_be_running(checkov):
    """_record_timeout alone, as a scanner that swallows the failure leaves it:
    the one trace must carry the same contract."""
    scanner, _ = checkov
    scanner._record_timeout(dict(_STOP_FAILED), 5)

    lines = [line for line in scanner.errors if "timed out after" in line]
    assert any("may still be running" in line for line in lines), lines
    assert not any("was killed" in line for line in lines), lines


def test_the_recorded_timeout_line_keeps_was_killed_for_a_stopped_tool(checkov):
    scanner, _ = checkov
    scanner._record_timeout(dict(_STOPPED_AT_THE_LIMIT), 5)

    lines = [line for line in scanner.errors if "timed out after" in line]
    assert any("was killed" in line for line in lines), lines
    assert not any("may still be running" in line for line in lines), lines
