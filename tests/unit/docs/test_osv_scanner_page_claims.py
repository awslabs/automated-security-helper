# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The OSV-Scanner plugin page says what the plugin does, and what it says is true.

``docs/plugins/alpha/osv-scanner-plugin.md`` names the pinned release, the option
defaults, the exit codes it accepts, how it rates a finding, its offline behavior and its
license entry. Each test pins one of those sentences with ``assert_on_page`` and then
reads the code that makes it true, in the two halves ``test_page_claims.py`` uses.

Not pinned: the list of lockfile formats (OSV-Scanner's, not ASH's), the network
paragraph's account of what OSV-Scanner sends (read from its documentation, not from
ASH's code), and the suppression example, which is the generic suppression shape.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.plugin_manifests.alpha import MANIFESTS
from automated_security_helper.plugin_modules.ash_osv_scanner_plugins.osv_scanner_install import (
    ASSET_SHA256,
    ASSETS,
    OSV_SCANNER_VERSION,
)
from automated_security_helper.plugin_modules.ash_osv_scanner_plugins.osv_scanner_scanner import (
    DEFAULT_SEVERITY,
    LEVEL_SEVERITY,
    OFFLINE_SKIP_REASON,
    OsvScannerScanner,
    OsvScannerScannerConfig,
    OsvScannerScannerConfigOptions,
    severity_from_score,
)
from automated_security_helper.schemas.sarif_schema_model import Level
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES
from tests.unit.docs.test_page_claims import assert_on_page

pytestmark = pytest.mark.unit

OSV_PAGE = "docs/plugins/alpha/osv-scanner-plugin.md"


def test_the_page_names_the_release_the_install_module_pins() -> None:
    assert_on_page(
        OSV_PAGE,
        f"ASH pins OSV-Scanner {OSV_SCANNER_VERSION} in the plugin's own install module",
    )
    # One release executable per platform and architecture, each with its digest.
    assert ASSETS and set(ASSETS.values()) == set(ASSET_SHA256)


def test_the_scanner_name_the_page_uses_is_the_manifest_and_config_name() -> None:
    assert_on_page(
        OSV_PAGE,
        "`--scanners osv-scanner` without the module listed is refused",
    )
    assert_on_page(OSV_PAGE, "`scanners.osv-scanner.enabled: false` turns it off again")
    assert "osv-scanner" in {manifest.name for manifest in MANIFESTS}
    assert OsvScannerScannerConfig().name == "osv-scanner"
    assert OsvScannerScannerConfig().enabled is True


def test_the_configuration_block_shows_the_option_defaults() -> None:
    assert_on_page(
        OSV_PAGE,
        "# Seconds for the whole OSV-Scanner run (default 1800; null for no limit). "
        "scan_timeout: 1800",
    )
    assert_on_page(OSV_PAGE, "offline: false")
    options = OsvScannerScannerConfigOptions()
    assert options.scan_timeout == 1800
    assert options.offline is False
    assert options.severity_threshold is None


@pytest.mark.parametrize(
    "row",
    [
        "| 0 | packages found, no vulnerabilities | scan succeeds |",
        "| 1 | packages found, with vulnerabilities | scan succeeds, findings reported |",
        "| 128 | no packages found | scan succeeds with no findings |",
    ],
)
def test_the_exit_code_table_lists_the_codes_the_scanner_accepts(row: str) -> None:
    assert_on_page(OSV_PAGE, row)
    assert OsvScannerScanner.success_exit_codes == {0, 1, 128}


@pytest.mark.parametrize(
    "row,score,expected",
    [
        ("| 9.0 and up | CRITICAL | `error` |", 9.0, ("CRITICAL", Level.error)),
        ("| 7.0 to 8.9 | HIGH | `error` |", 7.0, ("HIGH", Level.error)),
        ("| 7.0 to 8.9 | HIGH | `error` |", 8.9, ("HIGH", Level.error)),
        ("| 4.0 to 6.9 | MEDIUM | `warning` |", 4.0, ("MEDIUM", Level.warning)),
        ("| 4.0 to 6.9 | MEDIUM | `warning` |", 6.9, ("MEDIUM", Level.warning)),
        ("| above 0 to 3.9 | LOW | `note` |", 0.1, ("LOW", Level.note)),
        ("| above 0 to 3.9 | LOW | `note` |", 3.9, ("LOW", Level.note)),
        ("| 0 | INFO | `none` |", 0.0, ("INFO", Level.none)),
    ],
)
def test_the_score_rows_of_the_severity_table_are_the_ratings(
    row: str, score: float, expected: tuple
) -> None:
    assert_on_page(OSV_PAGE, row)
    assert severity_from_score(score) == expected


def test_the_level_rows_and_the_default_of_the_severity_table_are_the_ratings() -> None:
    for level, (severity, written) in LEVEL_SEVERITY.items():
        assert_on_page(OSV_PAGE, f"| `{level}` | {severity} | `{written.value}` |")
    assert_on_page(OSV_PAGE, "| No score and no level | | MEDIUM | `warning` |")
    assert DEFAULT_SEVERITY == ("MEDIUM", Level.warning)


def test_the_page_says_the_scanner_does_not_run_offline() -> None:
    assert_on_page(
        OSV_PAGE,
        "the scanner does not run: it is reported `MISSING`, with the reason that it "
        "needs the OSV API",
    )
    assert OsvScannerScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE
    assert "OSV API" in OFFLINE_SKIP_REASON


def test_the_license_paragraph_names_the_attribution_entry() -> None:
    assert_on_page(OSV_PAGE, "(the `osv-scanner` entry in `THIRD_PARTY_LICENSES`)")
    entry = THIRD_PARTY_LICENSES["osv-scanner"]
    assert entry.license == "Apache-2.0"
    assert entry.version == OSV_SCANNER_VERSION
