# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Manifests of the alpha scanners (``plugin_modules/ash_*_plugins``).

Pure data; see :mod:`automated_security_helper.plugin_manifests`. An alpha
scanner ships inside ASH but loads only when its plugin module is listed in
``ash_plugin_modules`` or passed with ``--ash-plugin-modules``, so each is
``alpha`` and not ``default_enabled``. The scan phase reads this tier to say
which module to add for a scanner that was named but not loaded.

Promotion to ``supported`` is the one-line ``tier`` edit here.
"""

from automated_security_helper.base.plugin_manifest import (
    BUNDLED_VERSION,
    MANIFEST_SCHEMA_VERSION,
    EntryPoints,
    PluginTier,
    ScannerManifest,
)

_BASE = "automated_security_helper.plugin_modules"
_SOURCES = "automated_security_helper/plugin_modules"


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
        "ferret-scan",
        "ash_ferret_plugins",
        "ferret_scanner",
        "FerretScanScanner",
        "FerretScannerConfigOptions",
        owned=(f"{_DOCS}/ferret-scan-plugin.md", f"{_FIXTURES}/ferret-scan"),
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
