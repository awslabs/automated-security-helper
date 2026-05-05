# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for #99: pnpm audit must run from the lock file's directory.

Before the fix, ``_run_subprocess`` was called without an explicit ``cwd``,
so it defaulted to ``context.source_dir``.  When a ``pnpm-lock.yaml``
lived in a nested subdirectory, pnpm failed with ``ERR_PNPM_NO_LOCKFILE``
because it could not find the lock file in the working directory.

The fix passes ``cwd=lock_file.parent`` to ``_run_subprocess`` for every
package manager invocation so the audit command runs from the correct
directory.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)


@pytest.fixture
def npm_scanner(test_plugin_context):
    scanner = NpmAuditScanner(
        context=test_plugin_context, config=NpmAuditScannerConfig()
    )
    scanner.exit_code = 0
    scanner.dependencies_satisfied = True
    scanner.tool_version = "1.0.0"
    return scanner


def test_pnpm_audit_runs_from_lockfile_directory(npm_scanner, tmp_path):
    """When a nested pnpm-lock.yaml is found, _run_subprocess must be
    called with cwd set to the lock file's parent directory."""
    root = tmp_path / "repo"
    nested = root / "packages" / "sub"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"name":"sub"}')
    (nested / "pnpm-lock.yaml").write_text("")

    npm_scanner.context.source_dir = root

    captured_kwargs = []

    def fake_run(command, **kwargs):
        captured_kwargs.append(kwargs)
        return {"stdout": '{"vulnerabilities":{}}', "returncode": 0}

    with (
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.find_executable",
            return_value="/usr/local/bin/pnpm",
        ),
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.scan_set",
            return_value=[str(nested / "package.json")],
        ),
        patch.object(npm_scanner, "_pre_scan", return_value=True),
        patch.object(npm_scanner, "_post_scan"),
        patch.object(npm_scanner, "_run_subprocess", side_effect=fake_run),
    ):
        npm_scanner.scan(target=root, target_type="source")

    # At least one call must have cwd pointing at the nested dir
    cwds = [kw.get("cwd") for kw in captured_kwargs]
    assert any(
        cwd is not None and Path(cwd) == nested for cwd in cwds
    ), f"Expected cwd={nested}, got cwds={cwds}"


def test_npm_audit_runs_from_lockfile_directory(npm_scanner, tmp_path):
    """npm (package-lock.json) should also run from the lock file directory."""
    root = tmp_path / "repo"
    nested = root / "apps" / "web"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"name":"web"}')
    (nested / "package-lock.json").write_text("{}")

    npm_scanner.context.source_dir = root

    captured_kwargs = []

    def fake_run(command, **kwargs):
        captured_kwargs.append(kwargs)
        return {"stdout": '{"vulnerabilities":{}}', "returncode": 0}

    with (
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.find_executable",
            return_value="/usr/local/bin/npm",
        ),
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.scan_set",
            return_value=[str(nested / "package.json")],
        ),
        patch.object(npm_scanner, "_pre_scan", return_value=True),
        patch.object(npm_scanner, "_post_scan"),
        patch.object(npm_scanner, "_run_subprocess", side_effect=fake_run),
    ):
        npm_scanner.scan(target=root, target_type="source")

    cwds = [kw.get("cwd") for kw in captured_kwargs]
    assert any(
        cwd is not None and Path(cwd) == nested for cwd in cwds
    ), f"Expected cwd={nested}, got cwds={cwds}"


def test_yarn_audit_runs_from_lockfile_directory(npm_scanner, tmp_path):
    """yarn should also run from the lock file directory."""
    root = tmp_path / "repo"
    nested = root / "libs" / "core"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"name":"core"}')
    (nested / "yarn.lock").write_text("")

    npm_scanner.context.source_dir = root

    captured_kwargs = []

    def fake_run(command, **kwargs):
        captured_kwargs.append(kwargs)
        return {"stdout": '{"vulnerabilities":{}}', "returncode": 0}

    with (
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.find_executable",
            return_value="/usr/local/bin/yarn",
        ),
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.scan_set",
            return_value=[str(nested / "package.json")],
        ),
        patch.object(npm_scanner, "_pre_scan", return_value=True),
        patch.object(npm_scanner, "_post_scan"),
        patch.object(npm_scanner, "_run_subprocess", side_effect=fake_run),
    ):
        npm_scanner.scan(target=root, target_type="source")

    cwds = [kw.get("cwd") for kw in captured_kwargs]
    assert any(
        cwd is not None and Path(cwd) == nested for cwd in cwds
    ), f"Expected cwd={nested}, got cwds={cwds}"
