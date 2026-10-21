# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The detect-secrets worker scans under bwrap and Landlock from its own start directory.

The worker used to start in the scanner's results directory. It now starts in an
empty directory created under its work directory for each scan
(``utils/python_child.py``), which a sandboxed process can only use if the policy
lets it see that directory. This runs the real scanner under each backend over a
tree with a planted credential and a planted ``automated_security_helper/`` package:
the credential must be found, and the package must not be imported.

Skipped when a backend cannot start a sandbox, unless ASH_REQUIRE_SANDBOX_BACKENDS
names it, which the sandbox CI job does.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
    DetectSecretsScanSettings,
    DetectSecretsScanSettingsFiltersUsed,
    DetectSecretsScanSettingsPluginsUsed,
)
from automated_security_helper.utils.sandbox.backends import (
    BwrapBackend,
    LandlockBackend,
)
from automated_security_helper.utils.sandbox.scope import SandboxScope, sandbox_scope
from tests.utils.refusing_proxy import (
    RecordingProxy,
    route_through,
    scrub_cloud_credentials,
)

pytestmark = pytest.mark.integration

#: AWS's documentation placeholder, assembled so this file holds no key-shaped text.
PLANTED_KEY = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002


def _require(backend):
    reason = backend.probe()
    if reason:
        required = os.environ.get("ASH_REQUIRE_SANDBOX_BACKENDS", "").split(",")
        if backend.name in [name.strip() for name in required]:
            pytest.fail(
                f"{backend.name} is required (ASH_REQUIRE_SANDBOX_BACKENDS) but: {reason}"
            )
        pytest.skip(f"{backend.name} unavailable: {reason}")
    return backend


@pytest.mark.parametrize(
    "backend_class", [BwrapBackend, LandlockBackend], ids=["bwrap", "landlock"]
)
def test_the_worker_scans_from_its_own_start_directory_under_the_sandbox(
    tmp_path, monkeypatch, backend_class
):
    backend = _require(backend_class())
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    results_dir = Path(scanner.results_dir)

    (source / "settings.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'\n", encoding="utf-8"
    )
    marker = tmp_path / "IMPORTED"
    for directory in (source, results_dir):
        package = directory / "automated_security_helper"
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").write_text(
            f"open({str(marker)!r}, 'a').write('imported')\n", encoding="utf-8"
        )

    scope = SandboxScope(
        backend=backend,
        scanner_name="detect-secrets",
        requirements=scanner.sandbox_requirements,
        source_dir=source,
        output_dir=output,
        results_dir=results_dir,
        scan_target=source,
        offline=True,
    )
    monkeypatch.delenv("PYTHONSAFEPATH", raising=False)
    monkeypatch.chdir(source)
    with sandbox_scope(scope):
        report = scanner.scan(target=source, target_type="source")

    # The planted package's marker path can also read as a high-entropy string.
    rules = [result.ruleId for result in report.runs[0].results]
    assert "SECRET-AWS-ACCESS-KEY" in rules, rules
    assert not marker.exists(), "the worker imported the planted package"
    leftovers = [p.name for p in (results_dir / "source").glob("ash-child-*")]
    assert leftovers == [], f"start directories left behind: {leftovers}"


#: AWS's documentation placeholder secret key, assembled so this file holds no
#: key-shaped text.
PLANTED_SECRET = "".join(["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCY", "EXAMPLEKEY"])  # noqa: FLY002
VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)


@pytest.mark.parametrize(
    "backend_class", [BwrapBackend, LandlockBackend], ids=["bwrap", "landlock"]
)
def test_operator_verification_under_the_sandbox_without_a_network_reports_unverified(
    tmp_path, monkeypatch, backend_class
):
    """The operator's settings name the verification filter, so the worker is told
    it may verify; the sandbox is not granted a network (``network_scanners`` is
    unset). The candidate pair is still reported, as unverified, and no request
    reaches the recording proxy that every proxy variable points at."""
    backend = _require(backend_class())
    scrub_cloud_credentials(monkeypatch)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    proxy = RecordingProxy()
    route_through(monkeypatch, proxy)
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (source / "settings.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'\nAWS_SECRET_ACCESS_KEY = '{PLANTED_SECRET}'\n",
        encoding="utf-8",
    )
    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(
                scan_settings=DetectSecretsScanSettings(
                    plugins_used=[
                        DetectSecretsScanSettingsPluginsUsed(name="AWSKeyDetector")
                    ],
                    filters_used=[
                        DetectSecretsScanSettingsFiltersUsed(
                            path=VERIFICATION_FILTER, min_level=2
                        )
                    ],
                )
            )
        ),
    )
    requirements = scanner.sandbox_requirements
    assert requirements.network is True and requirements.network_requires_grant, (
        "the operator's verification filter did not reach the scanner's settings"
    )
    results_dir = Path(scanner.results_dir)
    verify_seen = []
    real_scan_in_worker = DetectSecretsScanner._scan_in_worker

    def record(self, **kwargs):
        verify_seen.append(kwargs.get("verify"))
        return real_scan_in_worker(self, **kwargs)

    monkeypatch.setattr(DetectSecretsScanner, "_scan_in_worker", record)
    scope = SandboxScope(
        backend=backend,
        scanner_name="detect-secrets",
        requirements=requirements,
        source_dir=source,
        output_dir=output,
        results_dir=results_dir,
        scan_target=source,
        offline=False,
    )
    monkeypatch.delenv("PYTHONSAFEPATH", raising=False)
    monkeypatch.chdir(source)
    try:
        with sandbox_scope(scope):
            report = scanner.scan(target=source, target_type="source")
    finally:
        proxy.close()

    assert verify_seen == [True], verify_seen
    rules = [result.ruleId for result in report.runs[0].results]
    assert "SECRET-AWS-ACCESS-KEY" in rules, rules
    assert proxy.external_requests() == [], proxy.requests
