# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for #215: detect-secrets must not hang, and a timeout is a failure.

Before the fix, scan_files was called directly without any timeout guard.
A pathological file (e.g. a minified JS bundle with high-entropy strings)
could cause detect-secrets to spin indefinitely, blocking the entire scan.

The fix bounds the scan with a configurable scan_timeout. The scan runs in a
worker subprocess, which is killed when the timeout expires. A killed worker
writes no results, so the scan fails: scan() raises ScannerError naming the
scanner and the limit, the timeout is recorded on the scanner, and the scan is
graded ERROR. It is never returned as a clean scan with no findings.
"""

import time
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from tests.utils.detect_secrets_worker import hanging_worker_command

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)

pytestmark = pytest.mark.integration

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


@pytest.fixture
def detect_secrets_scanner(test_plugin_context):
    scanner = DetectSecretsScanner(
        context=test_plugin_context, config=DetectSecretsScannerConfig()
    )
    return scanner


@pytest.fixture
def hung_scanner(detect_secrets_scanner, tmp_path, monkeypatch):
    """The scanner and its target, with a worker that sleeps for 60 seconds under
    a scan_timeout of 1 second."""
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
    return scanner, target_dir


@contextmanager
def _scan_internals_stubbed(scanner, target_dir):
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
        yield


def test_scan_timeout_does_not_hang(hung_scanner):
    """Scanner should fail within timeout when the scan hangs.

    We replace the scan worker with one that sleeps for 60 seconds, set scan_timeout to 1 second,
    and verify the scan method raises in a reasonable time (< 10 seconds).
    This would hang indefinitely on the pre-fix code.
    """
    scanner, target_dir = hung_scanner

    with _scan_internals_stubbed(scanner, target_dir):
        start = time.monotonic()
        with pytest.raises(ScannerError, match="timed out after '1' s"):
            scanner.scan(target=target_dir, target_type="source")
        elapsed = time.monotonic() - start

    # The scan should end in well under 10 seconds
    assert elapsed < 10, f"scan() took {elapsed:.1f}s -- likely hung without timeout"
    # And the timeout is what ended it, not the worker finishing early. It is
    # recorded on the scanner, which is how the executor names it.
    assert scanner.scan_timed_out_after == 1
    assert any("timed out after '1' s" in e for e in scanner.errors), scanner.errors


def test_a_killed_worker_is_never_graded_passed(hung_scanner):
    """A worker killed at scan_timeout found nothing anyone can rely on.

    Returning a report with no findings would be graded PASSED, which reads as a
    clean scan of a tree that was never scanned. The executor has to grade it
    ERROR and say why.
    """
    scanner, target_dir = hung_scanner
    executor = ScannerExecutor(
        plugin_context=scanner.context,
        progress_display=MagicMock(),
        scanner_tasks=[],
    )

    with _scan_internals_stubbed(scanner, target_dir):
        start = time.monotonic()
        (container,) = executor._execute_scanner(
            "detect-secrets", scanner, [{"path": target_dir, "type": "source"}]
        )
        elapsed = time.monotonic() - start

    assert elapsed < 10, f"the worker was not killed at its timeout ({elapsed:.1f}s)"
    assert container.status == ScannerStatus.ERROR, container.status
    first = container.raw_results["errors"][0]
    assert "timed out after '1' s" in first, first


def test_scan_timeout_line_carries_no_environment_value(hung_scanner):
    """The limit can be ``${VAR}``-sourced, and the line is kept in the record.

    A short number redacts only where the message quotes it whole, so the
    quoted-token form above is what makes this possible at all. The error the
    failed scan raises carries the same text, so it hides the value too.
    """
    scanner, target_dir = hung_scanner
    scanner.context.config._environment_values = ["1"]

    with _scan_internals_stubbed(scanner, target_dir):
        with pytest.raises(ScannerError) as raised:
            scanner.scan(target=target_dir, target_type="source")

    line = next(e for e in scanner.errors if "detect-secrets scan timed out after" in e)
    assert "1" not in line, line
    assert "1" not in str(raised.value), str(raised.value)
