# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test for #180: an absent yarn or pnpm does not crash the scan.

The guard in npm_audit_scanner checks find_executable() before invoking yarn or
pnpm, so a missing binary is never started and no FileNotFoundError escapes.

The guard makes the lockfile a failed target, so dependencies nobody checked do
not read as a clean audit.
It is counted, and named in the scanner's errors, so the executor records ERROR
when it was the only lockfile and the completeness gate reports the shortfall
otherwise.

This test monkeypatches find_executable to simulate missing binaries and asserts
that the scan neither raises nor reads clean: one target attempted, one failed,
and the error names the missing tool and the lockfile.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)

pytestmark = pytest.mark.unit


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
    project = base / "project"
    project.mkdir(parents=True, exist_ok=True)
    (project / "package.json").write_text('{"name":"test"}')
    (project / lock_name).write_text("")
    return project


def test_yarn_lock_without_yarn_is_a_failed_target(npm_scanner, tmp_path):
    """Issue #180: no crash on a missing yarn, and no clean read either."""
    project = _make_project(tmp_path, "yarn.lock")
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


def test_pnpm_lock_without_pnpm_is_a_failed_target(npm_scanner, tmp_path):
    """Issue #180: no crash on a missing pnpm, and no clean read either."""
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
