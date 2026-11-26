# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Manifests of the alpha scanners (``plugin_modules/ash_*_plugins``).

Pure data; see :mod:`automated_security_helper.plugin_manifests`. An alpha
scanner ships inside ASH but loads only when its plugin module is listed in
``ash_plugin_modules`` or passed with ``--ash-plugin-modules``, so each is
``alpha`` and not ``default_enabled``. The scan phase reads ``default_enabled``
(not the tier) to say which module to add for a scanner that was named but not
loaded, so promotion to ``supported`` is the one-line ``tier`` edit here and
changes neither that hint nor how the plugin loads.
"""

from typing import Any

from automated_security_helper.base.plugin_manifest import (
    BUNDLED_VERSION,
    MANIFEST_SCHEMA_VERSION,
    EntryPoints,
    ExclusionOption,
    PluginTier,
    ScannerManifest,
)
from automated_security_helper.base.plugin_provisioning import provisioning_for
from automated_security_helper.plugin_manifests import check_table_rows

_BASE = "automated_security_helper.plugin_modules"
_SOURCES = "automated_security_helper/plugin_modules"


#: The options through which a client-supplied config may keep files or findings
#: away from an alpha scanner; see ``ExclusionOption``. Keyed by scanner name.
_EXCLUSIONS = {
    "ferret-scan": (
        ExclusionOption(option="exclude_patterns", kind="glob", split_commas=True),
    ),
    "guarddog": (ExclusionOption(option="excluded_paths", kind="guarddog-path"),),
    "trivy-repo": (ExclusionOption(option="ignore_file", kind="trivy-ignore-file"),),
}


#: The default of each option a client-delivered config may not set, per scanner;
#: see ``ScannerManifest.denied_option_defaults``. snyk-code's and trivy-repo's
#: whole sections are denied, so every one of their options is listed; for the
#: others the denied options are the ones named in the default ``denied_paths`` and
#: the ones its ``/scanners/*/options/offline`` and ``tool_version`` globs reach
#: (hadolint has no ``tool_version`` option). A list default is compared with
#: ``==``, so a delivered list holding the same items in another order is not the
#: default. ``test_the_plugin_option_defaults_are_the_plugins`` derives the rows from
#: the default ``denied_paths`` and checks each value against the plugin's model.
_DENIED_OPTION_DEFAULTS: dict[str, dict[str, Any]] = {
    "betterleaks": {
        "config_file": None,
        "honor_inline_ignores": False,
        "honor_tree_ignore_files": False,
        "offline": False,
    },
    "credsweeper": {"tool_version": None},
    "ferret-scan": {
        "checks": "all",
        "confidence_levels": "all",
        "config_file": None,
        "disable_ip_types": None,
        "enable_preprocessors": True,
        "finding_limit": 0,
        "max_live_bytes": None,
        "offline": False,
        "profile": None,
        "recursive": True,
        "respect_gitignore": False,
        "tool_version": None,
        "use_default_config": True,
        "validator_budget": None,
    },
    "ggshield": {"tool_version": None},
    "guarddog": {
        "ecosystems": ["pypi", "npm", "go", "github_action", "rubygems", "crates"],
        "exclude_rules": [],
        "offline": False,
        "rules": [],
        "sandbox": "auto",
        "tool_version": None,
        "verify": False,
    },
    "hadolint": {"config_file": None, "offline": False},
    "snyk-code": {
        "honor_tree_exclusions": False,
        "offline": False,
        "scan_timeout": 1800,
        "severity_threshold": None,
    },
    "trivy-repo": {
        "config_file": None,
        "disable_telemetry": True,
        "ignore_file": None,
        "ignore_unfixed": True,
        "license_full": True,
        "module_dir": None,
        "offline": False,
        "scan_timeout": 1800,
        "scanners": ["vuln", "secret", "misconfig", "license"],
        "secret_config_file": None,
        "severity_threshold": None,
    },
}


def _alpha(
    name: str,
    package: str,
    module: str,
    scanner_class: str,
    options_class: str,
    *,
    owned: tuple[str, ...] = (),
) -> ScannerManifest:
    """One alpha scanner's manifest; the package directory is always owned."""
    return ScannerManifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        name=name,
        version=BUNDLED_VERSION,
        aliases=(),
        tier=PluginTier.ALPHA,
        default_enabled=False,
        plugin_module=f"{_BASE}.{package}",
        entry_points=EntryPoints(scanner=f"{_BASE}.{package}.{module}:{scanner_class}"),
        options_model=f"{_BASE}.{package}.{module}:{options_class}",
        file_ownership=(f"{_SOURCES}/{package}", *owned),
        provisioning=provisioning_for(name),
        exclusion_options=_EXCLUSIONS.get(name, ()),
        denied_option_defaults=_DENIED_OPTION_DEFAULTS.get(name, {}),
    )


_DOCS = "docs/content/docs/plugins/alpha"
_FIXTURES = "tests/test_data/scanners"

MANIFESTS = (
    _alpha(
        "betterleaks",
        "ash_betterleaks_plugins",
        "betterleaks_scanner",
        "BetterleaksScanner",
        "BetterleaksScannerConfigOptions",
        owned=(f"{_DOCS}/betterleaks-plugin.md", f"{_FIXTURES}/betterleaks"),
    ),
    _alpha(
        "credsweeper",
        "ash_credsweeper_plugins",
        "credsweeper_scanner",
        "CredSweeperScanner",
        "CredSweeperScannerConfigOptions",
        owned=(f"{_DOCS}/credsweeper-plugin.md", f"{_FIXTURES}/credsweeper"),
    ),
    _alpha(
        "dependency-check",
        "ash_dependency_check_plugins",
        "dependency_check_scanner",
        "DependencyCheckScanner",
        "DependencyCheckScannerConfigOptions",
        owned=(f"{_DOCS}/dependency_check-plugin.md", f"{_FIXTURES}/dependency-check"),
    ),
    _alpha(
        "ferret-scan",
        "ash_ferret_plugins",
        "ferret_scanner",
        "FerretScanScanner",
        "FerretScannerConfigOptions",
        owned=(f"{_DOCS}/ferret-scan-plugin.md", f"{_FIXTURES}/ferret-scan"),
    ),
    _alpha(
        "ggshield",
        "ash_ggshield_plugins",
        "ggshield_scanner",
        "GgshieldScanner",
        "GgshieldScannerConfigOptions",
        owned=(f"{_DOCS}/ggshield-plugin.md", f"{_FIXTURES}/ggshield"),
    ),
    _alpha(
        "gosec",
        "ash_gosec_plugins",
        "gosec_scanner",
        "GosecScanner",
        "GosecScannerConfigOptions",
        owned=(f"{_DOCS}/gosec-plugin.md", f"{_FIXTURES}/gosec"),
    ),
    _alpha(
        "guarddog",
        "ash_guarddog_plugins",
        "guarddog_scanner",
        "GuardDogScanner",
        "GuardDogScannerConfigOptions",
        owned=(f"{_DOCS}/guarddog-plugin.md", f"{_FIXTURES}/guarddog"),
    ),
    _alpha(
        "hadolint",
        "ash_hadolint_plugins",
        "hadolint_scanner",
        "HadolintScanner",
        "HadolintScannerConfigOptions",
        owned=(f"{_DOCS}/hadolint-plugin.md", f"{_FIXTURES}/hadolint"),
    ),
    _alpha(
        "kics",
        "ash_kics_plugins",
        "kics_scanner",
        "KicsScanner",
        "KicsScannerConfigOptions",
        owned=(f"{_DOCS}/kics-plugin.md", f"{_FIXTURES}/kics"),
    ),
    _alpha(
        "kingfisher",
        "ash_kingfisher_plugins",
        "kingfisher_scanner",
        "KingfisherScanner",
        "KingfisherScannerConfigOptions",
        owned=(f"{_DOCS}/kingfisher-plugin.md", f"{_FIXTURES}/kingfisher"),
    ),
    _alpha(
        "kyverno",
        "ash_kyverno_plugins",
        "kyverno_scanner",
        "KyvernoScanner",
        "KyvernoScannerConfigOptions",
        owned=(f"{_DOCS}/kyverno-plugin.md", f"{_FIXTURES}/kyverno"),
    ),
    _alpha(
        "polaris",
        "ash_polaris_plugins",
        "polaris_scanner",
        "PolarisScanner",
        "PolarisScannerConfigOptions",
        owned=(f"{_DOCS}/polaris-plugin.md", f"{_FIXTURES}/polaris"),
    ),
    _alpha(
        "secretlint",
        "ash_secretlint_plugins",
        "secretlint_scanner",
        "SecretlintScanner",
        "SecretlintScannerConfigOptions",
        owned=(f"{_DOCS}/secretlint-plugin.md", f"{_FIXTURES}/secretlint"),
    ),
    _alpha(
        "snyk-code",
        "ash_snyk_plugins",
        "snyk_code_scanner",
        "SnykCodeScanner",
        "SnykCodeScannerConfigOptions",
        owned=(f"{_DOCS}/snyk-plugin.md", f"{_DOCS}/snyk-plugin-setup.md"),
    ),
    _alpha(
        "trivy-repo",
        "ash_trivy_plugins",
        "trivy_repo_scanner",
        "TrivyRepoScanner",
        "TrivyRepoScannerConfigOptions",
        owned=(f"{_DOCS}/trivy-plugin.md",),
    ),
)

check_table_rows(
    __name__,
    {manifest.name for manifest in MANIFESTS},
    _EXCLUSIONS=_EXCLUSIONS,
    _DENIED_OPTION_DEFAULTS=_DENIED_OPTION_DEFAULTS,
)
