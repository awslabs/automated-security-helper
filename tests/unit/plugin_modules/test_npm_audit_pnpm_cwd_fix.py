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

npm, pnpm and yarn now run from a private copy of that directory's manifest and
lockfile instead, so they read no settings file the repository wrote (see
test_npm_audit_project_rc_ignored.py). What #99 needs is the lockfile in the
tool's working directory, so that is what is checked: the working directory, read
when the tool is started, holds that lockfile's contents.
"""

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from tests.utils.npm_audit_reports import NPM_CLEAN, PNPM_CLEAN


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


def _cwd_contents(cwd) -> dict:
    """The files in ``cwd`` and their text, read while the tool would run."""
    if cwd is None:
        return {}
    return {p.name: p.read_text() for p in Path(cwd).iterdir() if p.is_file()}


def test_pnpm_audit_runs_from_lockfile_directory(npm_scanner, tmp_path):
    """When a nested pnpm-lock.yaml is found, pnpm must run in a directory
    holding that lockfile (a private copy of the lockfile's directory)."""
    root = tmp_path / "repo"
    nested = root / "packages" / "sub"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"name":"sub"}')
    (nested / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n# packages/sub\n")

    npm_scanner.context.source_dir = root

    seen = []

    def fake_run(command, **kwargs):
        seen.append(_cwd_contents(kwargs.get("cwd")))
        return {"stdout": PNPM_CLEAN, "returncode": 0}

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

    # The copy is its own pnpm workspace root, so it holds a workspace file the
    # repository's directory did not have.
    expected = {
        "package.json": (nested / "package.json").read_text(),
        "pnpm-lock.yaml": (nested / "pnpm-lock.yaml").read_text(),
        "pnpm-workspace.yaml": yaml.safe_dump({"packages": ["."]}),
    }
    assert expected in seen, f"no pnpm run had {nested}'s lockfile: {seen}"


def test_npm_audit_runs_from_lockfile_directory(npm_scanner, tmp_path):
    """npm (package-lock.json) should also run with the lock file's directory."""
    root = tmp_path / "repo"
    nested = root / "apps" / "web"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"name":"web"}')
    (nested / "package-lock.json").write_text('{"name": "web", "lockfileVersion": 3}')

    npm_scanner.context.source_dir = root

    seen = []

    def fake_run(command, **kwargs):
        seen.append(_cwd_contents(kwargs.get("cwd")))
        return {"stdout": NPM_CLEAN, "returncode": 0}

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

    expected = {
        "package.json": (nested / "package.json").read_text(),
        "package-lock.json": (nested / "package-lock.json").read_text(),
    }
    assert expected in seen, f"no npm run had {nested}'s lockfile: {seen}"


def test_yarn_audit_runs_from_lockfile_directory(npm_scanner, tmp_path):
    """yarn should also run with the lock file directory's contents."""
    root = tmp_path / "repo"
    nested = root / "libs" / "core"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"name":"core"}')
    (nested / "yarn.lock").write_text("# yarn lockfile v1\n# libs/core\n")

    npm_scanner.context.source_dir = root

    seen = []

    def fake_run(command, **kwargs):
        if "audit" in command:
            seen.append(_cwd_contents(kwargs.get("cwd")))
        return _yarn_1_clean(command)

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

    expected = {
        "package.json": (nested / "package.json").read_text(),
        "yarn.lock": (nested / "yarn.lock").read_text(),
    }
    assert expected in seen, f"no yarn run had {nested}'s lockfile: {seen}"
