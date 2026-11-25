# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""bundler-audit over its captured output, and its facets declarations.

The corpus is ``tests/test_data/scanners/bundler_audit/captured`` (see its README): the
JSON a real bundler-audit 0.9.3 run wrote, and the SARIF the adapter converts it to.
The facets-corpus gate (tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py)
keeps a central table of corpora that does not list this scanner yet, so this module runs
that gate's own verdict function over this scanner's corpus. It is the module-local half
of the same check, not a replacement for the central one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.base.scanner_facets import (
    FACET_NAMES,
    SCANNER_FACETS_ATTR,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_operational_facets import (
    OPERATIONAL_FACETS_ATTR,
    ScannerOperationalFacets,
)
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_bundler_audit_plugins.bundler_audit_scanner import (
    BundlerAuditScanner,
    convert_bundler_audit_report,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from tests.unit.plugin_modules.test_scanner_facets_corpus_consistency import (
    FACET_COLUMNS,
    judge,
)

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "bundler_audit"
    / "captured"
)
SCANNER_NAME = "bundler-audit"


def _json(name: str) -> dict:
    return json.loads((CAPTURED / f"{name}.json").read_text(encoding="utf-8"))


def _lines() -> list[str]:
    return (CAPTURED / "positive.Gemfile.lock").read_text(encoding="utf-8").splitlines()


def _converted(name: str) -> dict:
    return convert_bundler_audit_report(
        _json(name), lockfile_uri="Gemfile.lock", lines=_lines()
    )


def test_the_committed_sarif_is_what_the_converter_makes_of_the_real_capture() -> None:
    for name in ("positive", "negative"):
        committed = json.loads((CAPTURED / f"{name}.sarif").read_text(encoding="utf-8"))
        assert committed == _converted(name), name


def test_the_real_capture_has_the_shapes_the_converter_reads() -> None:
    """Guards the fixture itself: a capture with no findings would make every
    mapping test below vacuous."""
    kinds = [r["type"] for r in _json("positive")["results"]]
    assert kinds.count("unpatched_gem") == 7
    assert kinds.count("insecure_source") == 1
    assert _json("negative")["results"] == []


def test_every_result_of_the_real_capture_maps_to_the_documented_severity() -> None:
    sarif = _converted("positive")
    by_rule = {
        r["ruleId"]: (r["properties"]["issue_severity"], r["level"])
        for r in sarif["runs"][0]["results"]
    }
    native = {
        r["advisory"]["id"]: r["advisory"]["criticality"]
        for r in _json("positive")["results"]
        if r["type"] == "unpatched_gem"
    }
    assert native == {
        "CVE-2021-28965": "high",
        "CVE-2024-35176": "medium",
        "CVE-2024-39908": "medium",
        "CVE-2024-41123": "medium",
        "CVE-2024-41946": "medium",
        "CVE-2024-43398": "medium",
        "CVE-2024-49761": "high",
    }
    for rule, criticality in native.items():
        expected = ("HIGH", "error") if criticality == "high" else ("MEDIUM", "warning")
        assert by_rule[rule] == expected, rule
    assert by_rule["insecure-source"] == ("MEDIUM", "warning")


def test_the_real_capture_locates_each_gem_on_its_lockfile_line() -> None:
    lines = _lines()
    sarif = _converted("positive")
    for result in sarif["runs"][0]["results"]:
        line = result["locations"][0]["physicalLocation"]["region"]["startLine"]
        text = lines[line - 1]
        if result["ruleId"] == "insecure-source":
            assert text.strip() == "remote: git://github.com/example/insecure.git"
        else:
            assert text.strip() == "rexml (3.2.4)"


def test_the_clean_capture_converts_to_a_run_with_no_results() -> None:
    sarif = _converted("negative")
    assert sarif["runs"][0]["results"] == []


def test_the_scanner_declares_both_registers() -> None:
    assert isinstance(vars(BundlerAuditScanner).get(SCANNER_FACETS_ATTR), ScannerFacets)
    assert isinstance(
        vars(BundlerAuditScanner).get(OPERATIONAL_FACETS_ATTR),
        ScannerOperationalFacets,
    )


def _observed() -> dict[str, tuple[int, int]]:
    report = SarifReport.model_validate(
        json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
    )
    run = report.runs[0]
    flats = [
        FlatVulnerability.from_sarif_result(r, SCANNER_NAME, ScannerToolType.SCA, run)
        for r in run.results
    ]
    assert len(flats) == 8
    counts: dict[str, tuple[int, int]] = {}
    for facet, observation in FACET_COLUMNS.items():
        if observation.excluded is not None:
            continue
        populated = sum(
            1
            for flat in flats
            if observation.populated(*(getattr(flat, c) for c in observation.columns))
        )
        counts[facet] = (populated, len(flats))
    return counts


@pytest.mark.parametrize("facet", FACET_NAMES)
def test_declared_facets_agree_with_the_observed_corpus(facet: str) -> None:
    declared = getattr(vars(BundlerAuditScanner)[SCANNER_FACETS_ATTR], facet).state
    verdict = judge(
        SCANNER_NAME,
        facet,
        declared,
        _observed().get(facet),
        corpus_hint="tests/test_data/scanners/bundler_audit/captured",
    )
    assert verdict.outcome in ("ok", "excluded"), verdict.detail


def test_the_corpus_gate_is_not_vacuous_here() -> None:
    """Planted control: a MAPPED claim over a column the corpus leaves empty fails."""
    verdict = judge(
        SCANNER_NAME,
        "references",
        FacetState.MAPPED,
        _observed()["references"],
    )
    assert verdict.outcome == "FAIL"


def test_the_operational_row_mirrors_the_class_declarations() -> None:
    ops = vars(BundlerAuditScanner)[OPERATIONAL_FACETS_ATTR]
    assert ops.scanner_name == "bundler_audit"
    assert ops.network.offline_strategy is BundlerAuditScanner.offline_strategy
    assert ops.exit_codes.success_exit_codes == tuple(
        sorted(BundlerAuditScanner.success_exit_codes)
    )
    assert ops.network.sandbox_network.value == "online"
    assert BundlerAuditScanner.sandbox_requirements.network is True
    assert BundlerAuditScanner.nothing_to_scan_reason is not None, (
        "a lockfile prerequisite needs a skip reason"
    )
