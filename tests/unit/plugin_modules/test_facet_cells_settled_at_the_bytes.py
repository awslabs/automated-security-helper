# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Register cells that were recorded as droppable and were read at the bytes.

Each test pins the measurement a cell's declaration rests on, so a tool upgrade
that changes the shape fails here and the cell is re-read, and so the cell cannot
drift back to a claim nobody checked:

* semgrep and opengrep write no SARIF ``fixes`` even for a rule that has ``fix:``
  (there is nothing for fix_available to map), checkov's ``fixed_definition`` is
  declared N/A;
* guarddog's scan output names no package (its ``package`` key is a directory);
* snyk's ``priorityScore`` is not a severity and survives into the flat row;
* npm-audit's advisory CWEs reach the flat ``cwe_id`` column through rule tags.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.base.scanner_facets import (
    SCANNER_FACETS_ATTR,
    FacetState,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
    _cwe_tags,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
)
from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
    GuardDogScanner,
    _risk_severity,
)
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    Result,
    SarifReport,
)

pytestmark = pytest.mark.unit

DATA = Path(__file__).resolve().parents[2] / "test_data" / "scanners"


def _facets(cls: type):
    return vars(cls)[SCANNER_FACETS_ATTR]


# --------------------------------------------------------------------------
# semgrep, opengrep: no SARIF fixes.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "cls"),
    [
        ("semgrep/captured/semgrep-1.187.0-fix-rule.sarif", SemgrepScanner),
        ("opengrep/captured/opengrep-2.0.0-fix-rule.sarif", OpengrepScanner),
    ],
    ids=["semgrep", "opengrep"],
)
def test_a_rule_with_a_fix_key_gets_no_fixes_in_the_sarif(fixture, cls) -> None:
    """The rot guard of the N/A: the day a tool writes ``fixes``, redeclare it."""
    # one rule file produced both captures (it is kept beside the semgrep one)
    rules = DATA / "semgrep/captured/semgrep-1.187.0-fix-rule.rules.yaml"
    assert "    fix: $X is None" in rules.read_text(encoding="utf-8")
    sarif = json.loads((DATA / fixture).read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    assert results, "the rule fired: a fix would have been written for it"
    for result in results:
        assert "fixes" not in result
    assert _facets(cls).fix_available.state is FacetState.NA


def test_checkov_fixed_definition_stays_na() -> None:
    assert _facets(CheckovScanner).fix_available.state is FacetState.NA
    assert "34 of 34" in _facets(CheckovScanner).fix_available.reason


# --------------------------------------------------------------------------
# guarddog: scan mode names no package.
# --------------------------------------------------------------------------


def test_a_guarddog_scan_names_no_package_or_version() -> None:
    scans = sorted((DATA / "guarddog" / "captured").glob("scan_*.json"))
    assert len(scans) >= 8
    for path in scans:
        document = json.loads(path.read_text(encoding="utf-8"))
        assert set(document) == {
            "errors",
            "issues",
            "package",
            "results",
            "risk_score",
            "risks",
        }, path.name
        assert document["package"].startswith("<scanned-dir>/"), path.name


def test_guarddog_package_cells_say_scan_mode_names_nothing() -> None:
    facets = _facets(GuardDogScanner)
    assert "scan mode names no package" in facets.package_name.reason
    assert "scan mode names no version" in facets.package_version.reason


# --------------------------------------------------------------------------
# snyk: priorityScore is carried, not graded.
# --------------------------------------------------------------------------


def test_snyk_priority_score_survives_into_the_flat_properties() -> None:
    result = Result.model_validate(
        {
            "ruleId": "python/Sqli",
            "level": "error",
            "message": {"text": "tainted"},
            "properties": {"priorityScore": 500, "isAutofixable": False},
        }
    )
    flat = FlatVulnerability.from_sarif_result(result, "snyk-code", "SAST")
    assert json.loads(flat.properties)["priorityScore"] == 500


# --------------------------------------------------------------------------
# npm-audit: advisory CWEs reach the cwe_id column.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cwe", "expected"),
    [
        (["CWE-79", "CWE-1321"], ["CWE-79", "CWE-1321"]),
        ("CWE-22", ["CWE-22"]),
        (["NVD-CWE-Other", "CWE-79"], ["CWE-79"]),
        ([], []),
        (None, []),
        (5, []),
    ],
)
def test_cwe_tags(cwe, expected) -> None:
    assert _cwe_tags(cwe) == expected


def test_an_npm_advisory_cwe_reaches_the_flat_cwe_column(test_plugin_context) -> None:
    scanner = NpmAuditScanner(
        context=test_plugin_context, config=NpmAuditScannerConfig()
    )
    scanner.exit_code = 0
    document = {
        "vulnerabilities": {
            "lodash": {
                "name": "lodash",
                "severity": "high",
                "isDirect": True,
                "via": [
                    {
                        "source": 1,
                        "name": "lodash",
                        "title": "Prototype Pollution",
                        "url": "https://github.com/advisories/GHSA-x",
                        "severity": "high",
                        "cwe": ["CWE-1321", "CWE-770"],
                        "cvss": {"score": 7.5},
                        "range": "<4.17.21",
                    }
                ],
                "effects": [],
                "range": "<4.17.21",
                "nodes": ["node_modules/lodash"],
                "fixAvailable": True,
            }
        }
    }
    sarif: SarifReport = scanner._convert_npm_audit_to_sarif(document, "/fake")
    run = sarif.runs[0]
    (result,) = run.results
    assert isinstance(result.properties, PropertyBag)
    flat = FlatVulnerability.from_sarif_result(result, "npm-audit", "SCA", run)
    assert flat.cwe_id == "CWE-1321, CWE-770"


# --------------------------------------------------------------------------
# semgrep, opengrep: the level lives on the rule, not on the result.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "cls"),
    [
        ("semgrep/captured/semgrep-1.187.0-m0.sarif", SemgrepScanner),
        ("opengrep/captured/opengrep-2.0.0-m0.sarif", OpengrepScanner),
    ],
    ids=["semgrep", "opengrep"],
)
def test_the_severity_cell_names_the_rule_level_the_capture_carries(
    fixture, cls
) -> None:
    """The cell read ``results[].level`` while no result carried a level.

    A cell that names a field the capture lacks is the defect class the corpus
    gate cannot see (the flat severity defaults to MEDIUM, so the column reads
    populated either way). Pin both halves: no result has a level, every rule
    carries ``defaultConfiguration.level``, and the declaration names the rule.
    """
    sarif = json.loads((DATA / fixture).read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    assert run["results"], "the capture holds results"
    assert all("level" not in result for result in run["results"])
    rules = run["tool"]["driver"]["rules"]
    assert rules and all(r["defaultConfiguration"]["level"] for r in rules)
    severity = _facets(cls).severity
    assert severity.state is FacetState.MAPPED
    assert severity.native_field == "tool.driver.rules[].defaultConfiguration.level"
    # the property bag the extras cell passes through is empty in the capture
    assert all(result["properties"] == {} for result in run["results"])


# --------------------------------------------------------------------------
# guarddog: a correlated risk's severity is GuardDog's own.
# --------------------------------------------------------------------------


def test_the_guarddog_severity_cell_names_the_risk_severity_it_maps() -> None:
    risks = []
    for path in sorted((DATA / "guarddog" / "captured").glob("scan_*.json")):
        risks += json.loads(path.read_text(encoding="utf-8")).get("risks", [])
    assert risks, "the captures hold correlated risks"
    assert {risk["severity"] for risk in risks} <= {"high", "medium", "low"}
    severity = _facets(GuardDogScanner).severity
    assert 'risks[] "severity"' in severity.native_field
    assert "_risk_severity" in severity.native_field
    # one to one, and the classes GuardDog does not rate are fixed by the adapter
    assert [_risk_severity(s) for s in ("high", "medium", "low")] == [
        "HIGH",
        "MEDIUM",
        "LOW",
    ]
    for adapter_fixed in ("LOW", "MEDIUM", "INFO"):
        assert adapter_fixed in severity.reason


# --------------------------------------------------------------------------
# npm-audit: yarn and pnpm results carry no install path.
# --------------------------------------------------------------------------


def test_an_npm_audit_v1_advisory_carries_no_package_path(test_plugin_context) -> None:
    """The package_path cell is the npm 7+ path; the v1 path writes none."""
    scanner = NpmAuditScanner(
        context=test_plugin_context, config=NpmAuditScannerConfig()
    )
    record = NpmAuditScanner._v1_advisory_record(
        {
            "module_name": "lodash",
            "id": 1,
            "title": "Prototype Pollution",
            "url": "https://github.com/advisories/GHSA-x",
            "severity": "high",
            "cwe": "CWE-1321",
            "vulnerable_versions": "<4.17.21",
            "patched_versions": ">=4.17.21",
            "findings": [{"version": "4.17.20", "paths": ["app>lodash"]}],
        }
    )
    assert record is not None
    results: list = []
    scanner._add_yarn_results([record], {}, results)
    (result,) = results
    flat = FlatVulnerability.from_sarif_result(result, "npm-audit", "SCA", None)
    assert flat.package_path is None
    assert flat.package_name == "lodash" and flat.package_version == "4.17.20"
    cell = _facets(NpmAuditScanner).package_path
    assert cell.state is FacetState.MAPPED
    assert "yarn and pnpm" in cell.reason and "None" in cell.reason
