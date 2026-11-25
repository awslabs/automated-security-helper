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
from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
    GuardDogScanner,
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
# opengrep (which serves the semgrep name on this branch): no SARIF fixes.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "cls"),
    [
        ("opengrep/captured/opengrep-2.0.0-fix-rule.sarif", OpengrepScanner),
    ],
    ids=["opengrep"],
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
