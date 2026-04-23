"""Tests for exit code accumulation across multiple subprocess calls.

Scanners that run multiple subprocesses in a loop (cfn_nag, npm_audit) must
retain the worst exit code, not just the last one. If the first template scan
fails (exit 2) but the last succeeds (exit 0), the recorded exit code must
be 2, not 0.
"""

from unittest.mock import patch

import pytest

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)


class _StubConfig(ScannerPluginConfigBase):
    name: str = "stub"


class _StubScanner(ScannerPluginBase[_StubConfig]):
    """Minimal concrete scanner for testing subprocess exit codes."""

    def scan(self, target, target_type="source"):
        pass

    def _resolve_arguments(self, target):
        return ["echo", "ok"]


@pytest.fixture()
def scanner(test_plugin_context):
    return _StubScanner(context=test_plugin_context, config=_StubConfig())


def _fake_run(returncode):
    """Return a dict that looks like run_command_with_output_handling output."""
    return {"stdout": "", "stderr": "", "returncode": returncode}


class TestExitCodeAccumulation:
    """Exit code must reflect the worst result across all subprocess calls."""

    def test_first_fails_last_succeeds(self, scanner):
        """exit codes [2, 0] must record 2, not 0."""
        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
        ) as mock_run:
            mock_run.return_value = _fake_run(2)
            scanner._run_subprocess(["tool", "bad.yaml"])
            assert scanner.exit_code == 2

            mock_run.return_value = _fake_run(0)
            scanner._run_subprocess(["tool", "good.yaml"])
            assert scanner.exit_code == 2  # must keep the worst

    def test_first_succeeds_last_fails(self, scanner):
        """exit codes [0, 1] must record 1."""
        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
        ) as mock_run:
            mock_run.return_value = _fake_run(0)
            scanner._run_subprocess(["tool", "good.yaml"])
            assert scanner.exit_code == 0

            mock_run.return_value = _fake_run(1)
            scanner._run_subprocess(["tool", "bad.yaml"])
            assert scanner.exit_code == 1

    def test_single_success(self, scanner):
        """Single call with exit 0 stays 0."""
        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
        ) as mock_run:
            mock_run.return_value = _fake_run(0)
            scanner._run_subprocess(["tool", "ok.yaml"])
            assert scanner.exit_code == 0

    def test_single_failure(self, scanner):
        """Single call with exit 1 records 1."""
        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
        ) as mock_run:
            mock_run.return_value = _fake_run(1)
            scanner._run_subprocess(["tool", "bad.yaml"])
            assert scanner.exit_code == 1

    def test_multiple_failures_keeps_highest(self, scanner):
        """exit codes [1, 3, 2] must record 3."""
        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
        ) as mock_run:
            for code in [1, 3, 2]:
                mock_run.return_value = _fake_run(code)
                scanner._run_subprocess(["tool", "file.yaml"])

            assert scanner.exit_code == 3
