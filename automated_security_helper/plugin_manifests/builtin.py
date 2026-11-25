# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Manifests of the builtin scanners (``plugin_modules/ash_builtin``).

Pure data; see :mod:`automated_security_helper.plugin_manifests`. Every builtin
scanner loads by default (``default_enabled``) and is ``supported``, except
semgrep, whose manifest declares the retirement shape: ``deprecated``,
superseded by opengrep, which lists ``semgrep`` among its aliases. The
declaration changes no run: semgrep stays a scanner of its own until the
retirement is decided and wired separately.
"""

from automated_security_helper.base.plugin_manifest import (
    BUNDLED_VERSION,
    MANIFEST_SCHEMA_VERSION,
    EntryPoints,
    PluginTier,
    ScannerManifest,
)
from automated_security_helper.base.plugin_provisioning import provisioning_for

_PLUGIN = "automated_security_helper.plugin_modules.ash_builtin"
_SCANNERS = f"{_PLUGIN}.scanners"
_SOURCES = "automated_security_helper/plugin_modules/ash_builtin/scanners"


def _builtin(
    name: str,
    module: str,
    scanner_class: str,
    options_class: str,
    *,
    fixtures: str | None = None,
    aliases: tuple[str, ...] = (),
    tier: PluginTier = PluginTier.SUPPORTED,
    superseded_by: str | None = None,
) -> ScannerManifest:
    """One builtin scanner's manifest; only the per-scanner facts are passed."""
    owned = [f"{_SOURCES}/{module}.py"]
    if fixtures is not None:
        owned.append(f"tests/test_data/scanners/{fixtures}")
    return ScannerManifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        name=name,
        version=BUNDLED_VERSION,
        aliases=aliases,
        tier=tier,
        default_enabled=True,
        plugin_module=_PLUGIN,
        superseded_by=superseded_by,
        entry_points=EntryPoints(scanner=f"{_SCANNERS}.{module}:{scanner_class}"),
        options_model=f"{_SCANNERS}.{module}:{options_class}",
        file_ownership=tuple(owned),
        provisioning=provisioning_for(name),
    )


MANIFESTS = (
    _builtin(
        "actionlint",
        "actionlint_scanner",
        "ActionlintScanner",
        "ActionlintScannerConfigOptions",
        fixtures="actionlint",
    ),
    _builtin(
        "bandit",
        "bandit_scanner",
        "BanditScanner",
        "BanditScannerConfigOptions",
        fixtures="bandit",
    ),
    _builtin(
        "cdk-nag",
        "cdk_nag_scanner",
        "CdkNagScanner",
        "CdkNagScannerConfigOptions",
        fixtures="cdk",
    ),
    _builtin(
        "cfn-guard",
        "cfn_guard_scanner",
        "CfnGuardScanner",
        "CfnGuardScannerConfigOptions",
    ),
    _builtin(
        "cfn-lint",
        "cfn_lint_scanner",
        "CfnLintScanner",
        "CfnLintScannerConfigOptions",
    ),
    _builtin(
        "cfn-nag",
        "cfn_nag_scanner",
        "CfnNagScanner",
        "CfnNagScannerConfigOptions",
        fixtures="cfn_nag",
    ),
    _builtin(
        "checkov",
        "checkov_scanner",
        "CheckovScanner",
        "CheckovScannerConfigOptions",
        fixtures="checkov",
    ),
    _builtin(
        "detect-secrets",
        "detect_secrets_scanner",
        "DetectSecretsScanner",
        "DetectSecretsScannerConfigOptions",
    ),
    _builtin(
        "gitleaks",
        "gitleaks_scanner",
        "GitleaksScanner",
        "GitleaksScannerConfigOptions",
        fixtures="gitleaks",
    ),
    _builtin(
        "grype",
        "grype_scanner",
        "GrypeScanner",
        "GrypeScannerConfigOptions",
        fixtures="grype",
    ),
    _builtin(
        "npm-audit",
        "npm_audit_scanner",
        "NpmAuditScanner",
        "NpmAuditScannerConfigOptions",
        fixtures="npmaudit",
    ),
    _builtin(
        "opengrep",
        "opengrep_scanner",
        "OpengrepScanner",
        "OpengrepScannerConfigOptions",
        fixtures="opengrep",
        aliases=("semgrep",),
    ),
    _builtin(
        "semgrep",
        "semgrep_scanner",
        "SemgrepScanner",
        "SemgrepScannerConfigOptions",
        fixtures="semgrep",
        tier=PluginTier.DEPRECATED,
        superseded_by="opengrep",
    ),
    _builtin(
        "syft",
        "syft_scanner",
        "SyftScanner",
        "SyftScannerConfigOptions",
        fixtures="syft",
    ),
    _builtin(
        "trivy",
        "trivy_scanner",
        "TrivyScanner",
        "TrivyScannerConfigOptions",
        fixtures="trivy",
    ),
    _builtin(
        "zizmor",
        "zizmor_scanner",
        "ZizmorScanner",
        "ZizmorScannerConfigOptions",
        fixtures="zizmor",
    ),
)
