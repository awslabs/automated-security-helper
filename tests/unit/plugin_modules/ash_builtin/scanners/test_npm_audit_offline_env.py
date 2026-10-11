# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline, npm-audit starts no package manager, so corepack cannot fetch one.

Why this file exists
--------------------
#451 taught npm-audit to set ``COREPACK_ENABLE_NETWORK=0`` when offline:
``COREPACK_ENABLE_DOWNLOAD_PROMPT=0`` (set in the Dockerfile) stops corepack
*asking* before it downloads a package manager; it does not stop the download.
Two defects then went unnoticed because nothing tested it: the module used
``os.environ`` without importing ``os``, and a merge dropped the ``env=`` argument
while still computing the environment.

Offline, npm-audit now runs no audit at all: npm, pnpm and yarn audit only against
the registry's advisory service, and offline ``npm audit --offline`` reported no
advisories for a lockfile with known ones. Every lockfile is recorded as not audited
instead (npm_audit_scanner._skip_offline), so no package manager starts and corepack
has nothing to fetch. The tests below pin that no process starts offline, that the
lockfile is recorded, and, online, that npm-audit passes no environment override.

Why assert on the call rather than run corepack
-----------------------------------------------
The contract worth pinning is what reaches ``_run_subprocess``. The double
records its kwargs, so a process started offline, or an override online, fails
loudly and immediately.
"""

from unittest.mock import patch

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
    NpmAuditScannerConfigOptions,
)


def _scanner(context, *, offline: bool):
    scanner = NpmAuditScanner(
        context=context,
        config=NpmAuditScannerConfig(
            options=NpmAuditScannerConfigOptions(offline=offline)
        ),
    )
    scanner.exit_code = 0
    scanner.dependencies_satisfied = True
    scanner.tool_version = "1.0.0"
    return scanner


def _run_scan(scanner, tmp_path, returned=None):
    """Drive scan() over one npm project and return the recorded kwargs.

    ``returned``, when given, is a list that receives scan()'s return value.

    An npm project. Online npm-audit runs npm from the lockfile's directory;
    offline it runs nothing (see npm_audit_scanner._skip_offline).

    ``fake_run`` takes ``**kwargs`` deliberately. Pinning the real signature here
    would make this test fail whenever _run_subprocess gains an argument, which
    is what happened to the syft double when ``timeout`` was added -- and a test
    that breaks for that reason gets "fixed" by loosening the assertion.
    """
    root = tmp_path / "repo"
    nested = root / "packages" / "sub"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"name":"sub"}')
    (nested / "package-lock.json").write_text("{}")
    scanner.context.source_dir = root

    captured = []

    def fake_run(command, **kwargs):
        captured.append(kwargs)
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
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=fake_run),
    ):
        result = scanner.scan(target=root, target_type="source")
    if returned is not None:
        returned.append(result)

    return captured


def test_offline_mode_starts_no_package_manager(test_plugin_context, tmp_path):
    """Offline no audit runs at all: npm, pnpm and yarn audit only against the
    registry's advisory service. So corepack is never asked for a package manager,
    with or without COREPACK_ENABLE_NETWORK, and no environment has to be built."""
    scanner = _scanner(test_plugin_context, offline=True)

    captured = _run_scan(scanner, tmp_path)

    assert captured == [], f"offline npm-audit started a process: {captured}"


def test_offline_mode_records_the_lockfile_as_not_audited(
    test_plugin_context, tmp_path
):
    scanner = _scanner(test_plugin_context, offline=True)

    _run_scan(scanner, tmp_path)

    assert [entry["path"] for entry in scanner.inputs_not_scanned] == [
        "packages/sub/package-lock.json"
    ]
    assert all(entry["reason"] for entry in scanner.inputs_not_scanned)


def test_offline_mode_with_a_lockfile_is_missing(test_plugin_context, tmp_path):
    """scan() returns False, which the executor records MISSING, as snyk-code is
    offline: what the audit depends on, the registry's advisory service, is absent."""
    scanner = _scanner(test_plugin_context, offline=True)
    returned = []

    _run_scan(scanner, tmp_path, returned)

    assert returned == [False]


@pytest.mark.parametrize("offline", [False])
def test_online_mode_passes_no_environment_override(
    test_plugin_context, tmp_path, offline
):
    """Online scans must not inherit the offline override.

    Asserting None rather than "no COREPACK_ENABLE_NETWORK key" on purpose: the
    scanner's contract is that it does not touch the environment unless offline,
    and passing a full copy of os.environ online would silently change what the
    child inherits if the caller ever set that variable themselves.
    """
    scanner = _scanner(test_plugin_context, offline=offline)

    captured = _run_scan(scanner, tmp_path)

    assert captured, "scan() never reached _run_subprocess"
    assert all(kw.get("env") is None for kw in captured), (
        f"online scan passed an env override: {[kw.get('env') for kw in captured]}"
    )
