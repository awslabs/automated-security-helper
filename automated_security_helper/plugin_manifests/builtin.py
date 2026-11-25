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
    ConfigSection,
    EntryPoints,
    ExclusionOption,
    PluginTier,
    ScannerManifest,
)
from automated_security_helper.base.plugin_provisioning import provisioning_for
from automated_security_helper.plugin_manifests import ManifestRegistryError

_PLUGIN = "automated_security_helper.plugin_modules.ash_builtin"
_SCANNERS = f"{_PLUGIN}.scanners"
_SOURCES = "automated_security_helper/plugin_modules/ash_builtin/scanners"


#: The description each builtin scanner's section carries in the generated config
#: schema (``ScannerConfigSegment``).
_SECTION_DESCRIPTIONS = {
    "actionlint": "Configure the options for actionlint",
    "bandit": "Configure the options for Bandit",
    "cdk-nag": "Configure the options for CdkNag",
    "cfn-guard": "Configure the options for cfn-guard",
    "cfn-lint": "Configure the options for cfn-lint",
    "cfn-nag": "Configure the options for CfnNag",
    "checkov": "Configure the options for Checkov",
    "detect-secrets": "Configure the options for DetectSecrets",
    "gitleaks": "Configure the options for Gitleaks",
    "grype": "Configure the options for Grype",
    "mcp-config": "Configure the options for the MCP server config scanner",
    "npm-audit": "Configure the options for NpmAudit",
    "opengrep": "Configure the options for Opengrep",
    "semgrep": "Configure the options for Semgrep",
    "syft": "Configure the options for Syft",
    "trivy": "Configure the options for Trivy (trivy fs)",
    "zizmor": "Configure the options for zizmor",
}

#: The options through which a client-supplied config may keep files or findings
#: away from a builtin scanner; see ``ExclusionOption``. Keyed by scanner name.
_EXCLUSIONS = {
    "bandit": (
        ExclusionOption(
            option="excluded_paths",
            kind="bandit",
            glob_builder=f"{_SCANNERS}.bandit_scanner:bandit_excluded_path_globs",
        ),
    ),
    "checkov": (ExclusionOption(option="skip_path", kind="checkov"),),
    "opengrep": (
        ExclusionOption(
            option="exclude",
            kind="glob",
            default=("*-converted.py", "*_report_result.txt"),
        ),
    ),
    "semgrep": (
        ExclusionOption(
            option="exclude",
            kind="glob",
            default=("*-converted.py", "*_report_result.txt"),
        ),
    ),
    "syft": (ExclusionOption(option="exclude", kind="glob"),),
    "trivy": (ExclusionOption(option="ignore_file", kind="trivy-ignore-file"),),
}


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
    # The section's class is the options class without its ``Options`` suffix; a
    # name that does not end so would leave the section typed by the options
    # model itself. And a scanner with no description is named here, not as a
    # bare KeyError from the manifest walk.
    if not options_class.endswith("Options"):
        raise ManifestRegistryError(
            f"builtin scanner {name!r}: options class {options_class!r} does not "
            "end in 'Options', so its config section class cannot be derived"
        )
    if name not in _SECTION_DESCRIPTIONS:
        raise ManifestRegistryError(
            f"builtin scanner {name!r} has no entry in _SECTION_DESCRIPTIONS"
        )
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
        config_section=ConfigSection(
            model=f"{_SCANNERS}.{module}:{options_class.removesuffix('Options')}",
            description=_SECTION_DESCRIPTIONS[name],
        ),
        exclusion_options=_EXCLUSIONS.get(name, ()),
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
        "mcp-config",
        "mcp_config_scanner",
        "McpConfigScanner",
        "McpConfigScannerConfigOptions",
        fixtures="mcp_config",
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
