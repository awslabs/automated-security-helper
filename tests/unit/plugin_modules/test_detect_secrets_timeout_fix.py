# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test for #215: detect-secrets must not hang on pathological files.

Before the fix, scan_files was called directly without any timeout guard.
A pathological file (e.g. a minified JS bundle with high-entropy strings)
could cause detect-secrets to spin indefinitely, blocking the entire scan.

The fix bounds the scan with a configurable scan_timeout. The scan now runs in a
worker subprocess, which is killed when the timeout expires; the scanner continues
with the collection it already held (the baseline's entries, or none).
"""

import time
from unittest.mock import patch

import pytest

from tests.utils.detect_secrets_worker import hanging_worker_command

from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)


@pytest.fixture
def detect_secrets_scanner(test_plugin_context):
    scanner = DetectSecretsScanner(
        context=test_plugin_context, config=DetectSecretsScannerConfig()
    )
    return scanner


def test_scan_timeout_does_not_hang(detect_secrets_scanner, tmp_path, monkeypatch):
    """Scanner should return within timeout when the scan hangs.

    We replace the scan worker with one that sleeps for 60 seconds, set scan_timeout to 1 second,
    and verify the scan method returns in a reasonable time (< 10 seconds).
    This would hang indefinitely on the pre-fix code.
    """
    scanner = detect_secrets_scanner

    # Override scan_timeout to 1 second
    scanner.config.options.scan_timeout = 1

    # Create a real file in the target so the scanner doesn't skip
    target_dir = tmp_path / "source"
    target_dir.mkdir()
    (target_dir / "app.py").write_text("x = 1")  # pragma: allowlist secret

    # Point context dirs at temp paths
    scanner.context.source_dir = target_dir
    scanner.context.output_dir = tmp_path / "output"
    scanner.context.output_dir.mkdir()

    # Ensure dependencies_satisfied is True so scan() doesn't bail early
    scanner.dependencies_satisfied = True

    # The scan runs in a worker subprocess (utils/detect_secrets_worker.py), so
    # the hang is a worker that sleeps for 60 seconds. scan_timeout bounds the
    # subprocess the way it used to bound scan_files in a thread.
    monkeypatch.setattr(
        DetectSecretsScanner,
        "_worker_command",
        staticmethod(hanging_worker_command(60)),
    )

    # Patch:
    #  - _pre_scan to skip real validation
    #  - _post_scan to skip real cleanup
    #  - scan_set to return one fake file
    #  - _resolve_arguments to skip real argument resolution
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_resolve_arguments"),
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners"
            ".detect_secrets_scanner.scan_set",
            return_value=[str(target_dir / "app.py")],
        ),
    ):
        start = time.monotonic()
        result = scanner.scan(target=target_dir, target_type="source")
        elapsed = time.monotonic() - start

    # The scan should complete in well under 10 seconds
    assert elapsed < 10, f"scan() took {elapsed:.1f}s -- likely hung without timeout"
    # It should return a SARIF report, not False or an exception
    assert result is not False, "scan() should return a report, not False"
    # And the timeout is what ended it, not the worker finishing early.
    assert any("timed out after 1s" in e for e in scanner.errors), scanner.errors
