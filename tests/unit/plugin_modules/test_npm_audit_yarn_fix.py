# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for #180: yarn/pnpm audit must not crash when binary is missing.

Before the fix, the scanner unconditionally invoked ``yarn`` or ``pnpm``
based on the lock file name.  If the binary was absent the subprocess
raised ``FileNotFoundError`` (or equivalent), crashing the scan.

The fix checks ``find_executable`` before invoking non-npm binaries and
logs a warning + skips the lock file when the tool is not installed.
"""

import logging
from pathlib import Path
from unittest.mock import patch, MagicMock, call

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER


@pytest.fixture
def npm_scanner(test_plugin_context):
    scanner = NpmAuditScanner(
        context=test_plugin_context, config=NpmAuditScannerConfig()
    )
    scanner.exit_code = 0
    scanner.dependencies_satisfied = True
    scanner.tool_version = "1.0.0"
    return scanner


def _make_project(base: Path, lock_name: str) -> Path:
    """Create a minimal project dir with package.json and a lock file."""
    project = base / "project"
    project.mkdir(parents=True, exist_ok=True)
    (project / "package.json").write_text('{"name":"test"}')
    (project / lock_name).write_text("")
    return project


def test_yarn_lock_skipped_when_yarn_not_installed(npm_scanner, tmp_path):
    """When yarn.lock exists but ``yarn`` is not installed, the scanner
    should log a warning and skip that lock file instead of crashing."""
    project = _make_project(tmp_path, "yarn.lock")

    # Point the scanner context at our temp project
    npm_scanner.context.source_dir = project

    mock_warning = MagicMock()
    with (
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.find_executable",
            side_effect=lambda cmd: None if cmd == "yarn" else f"/usr/bin/{cmd}",
        ),
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.scan_set",
            return_value=[str(project / "package.json")],
        ),
        patch.object(npm_scanner, "_pre_scan", return_value=True),
        patch.object(npm_scanner, "_post_scan"),
        patch.object(ASH_LOGGER, "warning", mock_warning),
    ):
        result = npm_scanner.scan(target=project, target_type="source")

    # Must not raise; should return a SARIF report (possibly empty)
    assert result is not False
    # A warning about missing yarn should have been logged
    warning_messages = [str(c) for c in mock_warning.call_args_list]
    assert any(
        "yarn" in msg.lower() and "not installed" in msg.lower()
        for msg in warning_messages
    ), f"Expected a 'yarn not installed' warning, got: {warning_messages}"


def test_pnpm_lock_skipped_when_pnpm_not_installed(npm_scanner, tmp_path):
    """Same as yarn test but for pnpm-lock.yaml when pnpm is missing."""
    project = _make_project(tmp_path, "pnpm-lock.yaml")
    npm_scanner.context.source_dir = project

    mock_warning = MagicMock()
    with (
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.find_executable",
            side_effect=lambda cmd: None if cmd == "pnpm" else f"/usr/bin/{cmd}",
        ),
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.scan_set",
            return_value=[str(project / "package.json")],
        ),
        patch.object(npm_scanner, "_pre_scan", return_value=True),
        patch.object(npm_scanner, "_post_scan"),
        patch.object(ASH_LOGGER, "warning", mock_warning),
    ):
        result = npm_scanner.scan(target=project, target_type="source")

    assert result is not False
    warning_messages = [str(c) for c in mock_warning.call_args_list]
    assert any(
        "pnpm" in msg.lower() and "not installed" in msg.lower()
        for msg in warning_messages
    ), f"Expected a 'pnpm not installed' warning, got: {warning_messages}"


def test_yarn_lock_scanned_when_yarn_available(npm_scanner, tmp_path):
    """When yarn IS available, yarn.lock should be scanned normally."""
    project = _make_project(tmp_path, "yarn.lock")
    npm_scanner.context.source_dir = project

    captured_commands = []

    def fake_run(command, **kwargs):
        captured_commands.append(command)
        return {"stdout": '{"vulnerabilities":{}}', "returncode": 0}

    with (
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.find_executable",
            return_value="/usr/local/bin/yarn",
        ),
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.scan_set",
            return_value=[str(project / "package.json")],
        ),
        patch.object(npm_scanner, "_pre_scan", return_value=True),
        patch.object(npm_scanner, "_post_scan"),
        patch.object(npm_scanner, "_run_subprocess", side_effect=fake_run),
    ):
        result = npm_scanner.scan(target=project, target_type="source")

    assert result is not False
    # Verify yarn was actually invoked
    assert any(
        cmd[0] == "yarn" for cmd in captured_commands
    ), f"Expected yarn to be invoked, got: {captured_commands}"
