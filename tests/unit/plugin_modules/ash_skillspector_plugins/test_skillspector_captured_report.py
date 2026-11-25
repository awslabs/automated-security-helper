# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The SkillSpector converter over a REAL capture.

``tests/test_data/scanners/skillspector/captured/skillspector-2.13.7-seeded.sarif``
is the unedited output of ``skillspector==2.13.7 scan --no-llm --format=sarif``
over the committed ``fixture_repo/seeded`` skill (see ``captured/README.md``);
``skillspector-2.13.7-benign.sarif`` is the same run over ``fixture_repo/benign``.
``positive.sarif`` is what ``convert_skillspector_sarif`` wrote from the seeded
capture, and is the file the facets corpus gate reads.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_skillspector_plugins.skillspector_scanner import (
    SEVERITY_MAP,
    SkillSpectorScanner,
    convert_skillspector_sarif,
    coverage_gaps,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "skillspector"
    / "captured"
)


@pytest.fixture(scope="module")
def seeded():
    return json.loads(
        (CAPTURED / "skillspector-2.13.7-seeded.sarif").read_text(encoding="utf-8")
    )


@pytest.fixture(scope="module")
def benign():
    return json.loads(
        (CAPTURED / "skillspector-2.13.7-benign.sarif").read_text(encoding="utf-8")
    )


@pytest.fixture(scope="module")
def converted(seeded):
    return convert_skillspector_sarif(seeded)


def test_the_capture_is_skillspector_2_13_7_sarif(seeded, benign):
    for document in (seeded, benign):
        driver = document["runs"][0]["tool"]["driver"]
        assert (driver["name"], driver["version"]) == ("skillspector", "2.13.7")
        assert document["version"] == "2.1.0"


def test_the_seeded_skill_is_flagged_and_the_benign_one_is_not(
    seeded, benign, converted
):
    results, _rules = converted
    assert {r.ruleId for r in results} == {"P1", "P2", "SC2", "YR4"}
    assert benign["runs"][0]["results"] == []
    assert convert_skillspector_sarif(benign) == ([], {})


def test_the_marker_and_the_fetch_line_sit_on_the_lines_that_hold_them(converted):
    results, _rules = converted
    lines = {
        (r.ruleId, r.locations[0].physicalLocation.root.region.startLine)
        for r in results
    }
    assert ("P1", 10) in lines and ("P2", 10) in lines
    assert ("SC2", 12) in lines
    seeded_text = (CAPTURED.parent / "fixture_repo" / "seeded" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    source = seeded_text.splitlines()
    assert "ASH-TEST-MARKER" in source[10 - 1]
    assert "example.invalid" in source[12 - 1]


def test_every_captured_severity_is_one_the_mapping_knows(seeded):
    seen = {r["properties"]["severity"] for r in seeded["runs"][0]["results"]}
    assert seen and seen <= set(SEVERITY_MAP)


def test_severity_and_level_agree_over_every_captured_result(converted):
    results, _rules = converted
    assert results
    for result in results:
        level = getattr(result.level, "value", result.level)
        severity = result.properties.model_dump()["issue_severity"]
        assert SEVERITY_MAP[severity][1] == level
        # The capture is all HIGH: pin the actual row, not just the agreement.
        assert (severity, level) == ("HIGH", "error")


def test_fingerprints_are_unique(converted):
    results, _rules = converted
    prints = [r.partialFingerprints["skillspector/v1"] for r in results]
    assert len(prints) == len(set(prints))


def test_the_capture_reads_complete(seeded, benign):
    assert coverage_gaps(seeded) == []
    assert coverage_gaps(benign) == []


def test_the_scanner_class_declares_the_facets_the_converter_writes():
    facets = SkillSpectorScanner.facets
    assert (
        facets.severity.native_field and "severity_of" in facets.severity.native_field
    )
    assert "skillspector/v1" in facets.fingerprints.native_field


def test_the_committed_sarif_is_what_the_converter_writes(converted):
    """The fixture the facets corpus gate reads does not drift from the code."""
    results, _rules = converted
    committed = SarifReport.model_validate(
        json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
    )
    committed_results = committed.runs[0].results
    assert [r.ruleId for r in committed_results] == [r.ruleId for r in results]
    assert [r.partialFingerprints for r in committed_results] == [
        r.partialFingerprints for r in results
    ]
