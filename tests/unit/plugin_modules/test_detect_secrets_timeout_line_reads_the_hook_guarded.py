# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The detect-secrets timeout line reads the values hook through the guarded read.

The line is a record path. It took the limit's token from a bare read of the
overridable hook, so a hook that raised aborted the worker's timeout handling
with the hook's own error. A hook that raised, or gave no usable answer, now
gets the line without the limit, with a note saying why.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)
from automated_security_helper.utils import subprocess_utils


def _raising(_self):
    raise RuntimeError("the hook broke")


@pytest.fixture
def timed_out_scan(test_plugin_context, tmp_path):
    def run(hook):
        scanner = DetectSecretsScanner(
            context=test_plugin_context, config=DetectSecretsScannerConfig()
        )
        scanner.config.options.scan_timeout = 5
        target_dir = tmp_path / "source"
        target_dir.mkdir(exist_ok=True)
        (target_dir / "app.py").write_text("x = 1")  # pragma: allowlist secret
        scanner.context.source_dir = target_dir
        scanner.context.output_dir = tmp_path / "output"
        scanner.context.output_dir.mkdir(exist_ok=True)
        scanner.dependencies_satisfied = True
        with (
            patch.object(DetectSecretsScanner, "_values_to_redact", hook),
            patch.object(scanner, "_pre_scan", return_value=True),
            patch.object(scanner, "_post_scan"),
            patch.object(scanner, "_resolve_arguments"),
            patch(
                "automated_security_helper.plugin_modules.ash_builtin.scanners"
                ".detect_secrets_scanner.scan_set",
                return_value=[str(target_dir / "app.py")],
            ),
            patch.object(
                subprocess_utils,
                "run_command_with_output_handling",
                return_value={"timed_out": True, "returncode": 124, "stderr": ""},
            ),
        ):
            scanner.scan(target=target_dir, target_type="source")
        return [e for e in scanner.errors if "timed out" in e]

    return run


def test_a_raising_hook_still_writes_the_timeout_line(timed_out_scan):
    lines = timed_out_scan(_raising)

    assert lines, "no timeout line was written"
    assert "values hook raised RuntimeError" in lines[0], lines


def test_a_working_hook_writes_the_limit(timed_out_scan):
    """The control: with a usable hook the line carries the limit as before."""
    lines = timed_out_scan(lambda _self: ())

    assert lines and "timed out after '5' s" in lines[0], lines
