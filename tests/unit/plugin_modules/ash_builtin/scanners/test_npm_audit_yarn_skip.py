# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test for #180: yarn/pnpm graceful-skip when binary is absent.

The guard at npm_audit_scanner.py:506-512 checks find_executable() before
invoking yarn or pnpm.  When the binary is missing it logs a warning and
skips the lock file instead of crashing with FileNotFoundError.

This test monkeypatches find_executable to simulate missing binaries and
asserts that:
- the scanner does not raise
- it returns a non-False result (empty SARIF rather than hard failure)
- the log contains "<binary> is not installed"
"""

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    project = base / "project"
    project.mkdir(parents=True, exist_ok=True)
    (project / "package.json").write_text('{"name":"test"}')
    (project / lock_name).write_text("")
    return project


def test_yarn_graceful_skip_when_yarn_missing(npm_scanner, tmp_path, caplog):
    """Issue #180: scanner must warn-and-skip yarn.lock when yarn is not installed.

    Monkeypatches find_executable to return None for 'yarn', mimicking a
    system without yarn.  Asserts no exception is raised, the scan returns
    a result (not False), and the warning log mentions 'yarn' and 'not installed'.
    """
    project = _make_project(tmp_path, "yarn.lock")
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

    assert result is not False, "Scanner must not return False on missing yarn"

    warning_messages = [str(c) for c in mock_warning.call_args_list]
    assert any(
        "yarn" in msg.lower() and "not installed" in msg.lower()
        for msg in warning_messages
    ), f"Expected 'yarn is not installed' warning; got: {warning_messages}"


def test_pnpm_graceful_skip_when_pnpm_missing(npm_scanner, tmp_path):
    """Issue #180: scanner must warn-and-skip pnpm-lock.yaml when pnpm is not installed."""
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

    assert result is not False, "Scanner must not return False on missing pnpm"

    warning_messages = [str(c) for c in mock_warning.call_args_list]
    assert any(
        "pnpm" in msg.lower() and "not installed" in msg.lower()
        for msg in warning_messages
    ), f"Expected 'pnpm is not installed' warning; got: {warning_messages}"
