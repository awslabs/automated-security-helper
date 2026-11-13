# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for #180: yarn/pnpm audit must not crash when binary is missing.

Before the fix, the scanner unconditionally invoked ``yarn`` or ``pnpm``
based on the lock file name.  If the binary was absent the subprocess
raised ``FileNotFoundError`` (or equivalent), crashing the scan.

The fix checks ``find_executable`` before invoking non-npm binaries, so the
missing tool is never started. The lockfile it would have audited is then a failed
target named in the scanner's errors: with no other lockfile the executor records
ERROR, and beside audited lockfiles their findings are kept and the completeness
gate reports the shortfall, so no empty report reads as a clean audit.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)


pytestmark = pytest.mark.unit


def _yarn_1_clean(command):
    """yarn 1 answering `--version`, then a clean `yarn audit --json`."""
    if "--version" in command:
        return {"stdout": "1.22.22\n", "returncode": 0}
    return {
        "stdout": '{"type":"auditSummary","data":{"vulnerabilities":{"info":0,'
        '"low":0,"moderate":0,"high":0,"critical":0}}}\n',
        "returncode": 0,
    }


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


def test_yarn_lock_is_a_failed_target_when_yarn_not_installed(npm_scanner, tmp_path):
    """When yarn.lock exists but ``yarn`` is not installed, that lockfile is a failed
    target named in the errors, not a crash or a clean read."""
    project = _make_project(tmp_path, "yarn.lock")

    # Point the scanner context at our temp project
    npm_scanner.context.source_dir = project

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
    ):
        report = npm_scanner.scan(target=project, target_type="source")

    assert report is not False
    assert (npm_scanner.targets_attempted, npm_scanner.targets_failed) == (1, 1)
    message = " ".join(npm_scanner.errors)
    assert "yarn is not installed" in message, message
    assert "yarn.lock" in message, message


def test_pnpm_lock_is_a_failed_target_when_pnpm_not_installed(npm_scanner, tmp_path):
    """When pnpm-lock.yaml exists but ``pnpm`` is not installed, that lockfile is a
    failed target named in the errors, not a crash or a clean read."""
    project = _make_project(tmp_path, "pnpm-lock.yaml")
    npm_scanner.context.source_dir = project

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
    ):
        report = npm_scanner.scan(target=project, target_type="source")

    assert report is not False
    assert (npm_scanner.targets_attempted, npm_scanner.targets_failed) == (1, 1)
    message = " ".join(npm_scanner.errors)
    assert "pnpm is not installed" in message, message
    assert "pnpm-lock.yaml" in message, message


def test_yarn_lock_scanned_when_yarn_available(npm_scanner, tmp_path):
    """When yarn IS available, yarn.lock should be scanned normally."""
    project = _make_project(tmp_path, "yarn.lock")
    npm_scanner.context.source_dir = project

    captured_commands = []

    def fake_run(command, **kwargs):
        captured_commands.append(command)
        return _yarn_1_clean(command)

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
    assert any(cmd[0] == "yarn" for cmd in captured_commands), (
        f"Expected yarn to be invoked, got: {captured_commands}"
    )
