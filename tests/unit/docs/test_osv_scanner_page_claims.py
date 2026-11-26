# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The OSV-Scanner plugin page says what the plugin does, and what it says is true.

``docs/plugins/alpha/osv-scanner-plugin.md`` names the pinned release, the option
defaults, the exit codes it accepts, how it rates a finding, its suppression shape, its
offline behavior and its license entry. Each test pins one of those sentences with
``assert_on_page`` and then reads the code that makes it true, in the two halves
``test_page_claims.py`` uses.

Not pinned: the list of lockfile formats (OSV-Scanner's, not ASH's), and the network
paragraph's account of what OSV-Scanner sends (read from its documentation, not from
ASH's code).

The suppression example is pinned because it is not the generic shape. OSV-Scanner
results carry no region, so a finding has a file and no line, and an entry with a line
range never matches one: the page's first example carried ``line_start: 1`` and
``line_end: 1`` and suppressed nothing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_facets import FacetState
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.models.core import AshSuppression
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
from automated_security_helper.schemas.sarif_schema_model import Level, SarifReport
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES
from tests.unit.docs.test_page_claims import CONTENT, assert_on_page

pytestmark = pytest.mark.unit

OSV_PAGE = "docs/plugins/alpha/osv-scanner-plugin.md"
CAPTURED = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "scanners"
    / "osv-scanner"
    / "captured"
    / "positive.sarif"
)


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


_YAML_FENCE = re.compile(r"^```yaml\n(.*?)^```$", re.MULTILINE | re.DOTALL)


def _suppression_example() -> dict:
    """The one entry of the page's suppression example, read from its yaml block."""
    text = (CONTENT / OSV_PAGE).read_text(encoding="utf-8")
    blocks = [block for block in _YAML_FENCE.findall(text) if "suppressions:" in block]
    assert len(blocks) == 1, f"{OSV_PAGE}: expected one suppression example"
    (entry,) = yaml.safe_load(blocks[0])["global_settings"]["suppressions"]
    return entry


def _osv_report(rule_id: str, path: str) -> SarifReport:
    """One result in the shape OSV-Scanner writes: a lockfile location, no region."""
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "osv-scanner", "rules": [{"id": rule_id}]}
                    },
                    "results": [
                        {
                            "ruleId": rule_id,
                            "message": {
                                "text": f"A package is vulnerable to {rule_id}"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": path}
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


def _suppresses(entry: AshSuppression, source: Path, output: Path) -> bool:
    """Whether the suppression pass suppresses a finding at ``entry``'s rule and path."""
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="p", global_settings={"suppressions": [entry]}),
    )
    report = apply_suppressions_to_sarif(
        _osv_report(entry.rule_id, entry.path), context, scanner_name="osv-scanner"
    )
    (result,) = report.runs[0].results
    return bool(result.suppressions)


def test_the_suppression_example_names_no_line_and_suppresses_the_finding(
    test_source_dir: Path, test_output_dir: Path
) -> None:
    assert_on_page(
        OSV_PAGE,
        "ASH suppressions by rule and path work as for any scanner. The rule is the "
        "advisory id OSV-Scanner reports, and the path is the lockfile:",
    )
    assert_on_page(
        OSV_PAGE,
        "Leave out `line_start` and `line_end`. An OSV-Scanner finding has a file and "
        "no line, and a suppression with a line range never matches a finding that has "
        "no line, so such an entry suppresses nothing.",
    )
    example = _suppression_example()
    assert sorted(example) == ["path", "reason", "rule_id"]
    # A file and no line: the scanner's register row and the real report agree.
    assert OsvScannerScanner.facets.line_range.state is FacetState.NA
    captured = json.loads(CAPTURED.read_text(encoding="utf-8"))
    locations = [
        location["physicalLocation"]
        for result in captured["runs"][0]["results"]
        for location in result["locations"]
    ]
    assert locations and all("region" not in location for location in locations)
    # The page's entry suppresses such a finding. The same entry with the line range
    # the page used to show suppresses nothing.
    assert _suppresses(AshSuppression(**example), test_source_dir, test_output_dir)
    with_lines = AshSuppression(**example, line_start=1, line_end=1)
    assert not _suppresses(with_lines, test_source_dir, test_output_dir)


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
