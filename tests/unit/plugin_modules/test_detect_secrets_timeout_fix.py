# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test for #215: detect-secrets must not hang on pathological files.

Before the fix, scan_files was called directly without any timeout guard.
A pathological file (e.g. a minified JS bundle with high-entropy strings)
could cause detect-secrets to spin indefinitely, blocking the entire scan.

The fix wraps scan_files in a ThreadPoolExecutor with a configurable
scan_timeout. When the timeout expires the future is cancelled and the
scanner continues with whatever partial results it collected.
"""
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

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


def test_scan_timeout_does_not_hang(detect_secrets_scanner, tmp_path):
    """Scanner should return within timeout when scan_files hangs.

    We mock scan_files to sleep for 60 seconds, set scan_timeout to 1 second,
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

    def hanging_scan(*args, **kwargs):
        time.sleep(60)

    # Build a mock collection whose scan_files hangs but data is empty
    mock_collection = MagicMock()
    mock_collection.scan_files = hanging_scan
    mock_collection.data = {}

    # Patch:
    #  - _pre_scan to skip real validation
    #  - _post_scan to skip real cleanup
    #  - scan_set to return one fake file
    #  - SecretsCollection constructor (scan() creates a fresh one at line 374)
    #  - _resolve_arguments to skip real argument resolution
    with patch.object(scanner, "_pre_scan", return_value=True), \
         patch.object(scanner, "_post_scan"), \
         patch.object(scanner, "_resolve_arguments"), \
         patch(
             "automated_security_helper.plugin_modules.ash_builtin.scanners"
             ".detect_secrets_scanner.scan_set",
             return_value=[str(target_dir / "app.py")],
         ), \
         patch(
             "automated_security_helper.plugin_modules.ash_builtin.scanners"
             ".detect_secrets_scanner.SecretsCollection",
             return_value=mock_collection,
         ):
        start = time.monotonic()
        result = scanner.scan(target=target_dir, target_type="source")
        elapsed = time.monotonic() - start

    # The scan should complete in well under 10 seconds
    assert elapsed < 10, f"scan() took {elapsed:.1f}s -- likely hung without timeout"
    # It should return a SARIF report, not False or an exception
    assert result is not False, "scan() should return a report, not False"
