# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The agent-scan converter over the CAPTURED ``snyk-agent-scan 0.7.1`` output.

``tests/test_data/scanners/agent-scan/captured/scan-skill-marked-0.7.1.json`` and
``scan-skill-clean-0.7.1.json`` are the stdout of the pinned tool's
``scan --json --skills`` over a staged skill directory (see ``captured/README.md``:
the tool's own envelope, with the risk values supplied by a local stub analysis
service, because the real service needs a token and receives the skill files).
``positive.sarif`` is what ``convert_agent_scan_document`` wrote from the marked one.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_agent_scan_plugins.agent_scan_scanner import (
    SKILL_RISK_NAMES,
    convert_agent_scan_document,
    parse_agent_scan_document,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "agent-scan"
    / "captured"
)
SKILL_LABEL = "skills/marked-skill"


@pytest.fixture(scope="module")
def marked():
    return json.loads((CAPTURED / "scan-skill-marked-0.7.1.json").read_text("utf-8"))


@pytest.fixture(scope="module")
def clean():
    return json.loads((CAPTURED / "scan-skill-clean-0.7.1.json").read_text("utf-8"))


@pytest.fixture(scope="module")
def converted(marked):
    return convert_agent_scan_document(marked, skill_label=SKILL_LABEL)


def test_both_captures_parse_under_the_locked_models(marked, clean):
    assert parse_agent_scan_document(marked)
    assert parse_agent_scan_document(clean)


def test_the_capture_holds_one_risk_in_each_score_band(marked):
    """Control: the raw capture spans all four bands, so the band rows below are
    not vacuous."""
    risks = marked["scan_path_responses"][0]["skill_risks"][0]["risk_indexes"]
    scores = sorted(r["score"] for r in risks.values())
    assert scores == [150, 250, 450, 650, 800, 1000]
    assert set(risks) <= set(SKILL_RISK_NAMES)


def test_one_result_per_risk_and_location(converted):
    assert converted.problems == []
    assert sorted(r.ruleId for r in converted.results) == sorted(
        [
            "malicious_code",
            "prompt_injection_skill_instructions",
            "secret_detection",
            "suspicious_download_url",
            "third_party_content_exposure",
            "unverifiable_dependencies",
        ]
    )


def test_severity_and_level_per_captured_score(converted):
    by_rule = {
        r.ruleId: (
            r.properties.agent_scan_score,
            r.properties.issue_severity,
            r.level.value if hasattr(r.level, "value") else r.level,
        )
        for r in converted.results
    }
    assert by_rule == {
        "unverifiable_dependencies": (150, "LOW", "note"),
        "third_party_content_exposure": (250, "LOW", "note"),
        "secret_detection": (450, "MEDIUM", "warning"),
        "prompt_injection_skill_instructions": (650, "HIGH", "error"),
        "suspicious_download_url": (800, "HIGH", "error"),
        "malicious_code": (1000, "CRITICAL", "error"),
    }


def test_results_sit_on_the_skill_file_and_the_captured_line(converted):
    where = {}
    for r in converted.results:
        physical = r.locations[0].physicalLocation.root
        where[r.ruleId] = (
            physical.artifactLocation.uri,
            physical.region.startLine if physical.region else None,
        )
    assert where["prompt_injection_skill_instructions"] == (
        "skills/marked-skill/SKILL.md",
        10,
    )
    assert where["malicious_code"] == ("skills/marked-skill/SKILL.md", 10)
    assert where["secret_detection"] == ("skills/marked-skill/SKILL.md", None)


def test_the_captured_url_lists_reach_the_result_properties(converted):
    by_rule = {r.ruleId: r.properties.model_dump() for r in converted.results}
    assert by_rule["suspicious_download_url"]["malicious_urls"] == [
        "https://example.invalid/payload"
    ]
    assert by_rule["unverifiable_dependencies"]["unverifiable_urls"] == [
        "https://example.invalid/dependency"
    ]


def test_the_clean_capture_is_the_negative_control(clean):
    converted = convert_agent_scan_document(clean, skill_label="skills/clean")
    assert (converted.results, converted.rules, converted.problems) == ([], {}, [])


def test_fingerprints_are_unique(converted):
    prints = [r.partialFingerprints["agent-scan/v1"] for r in converted.results]
    assert len(prints) == len(set(prints))


def test_the_committed_sarif_is_what_the_converter_writes(converted):
    """The fixture the facets corpus gate reads does not drift from the code."""
    committed = SarifReport.model_validate(
        json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
    )
    committed_results = committed.runs[0].results
    assert [r.ruleId for r in committed_results] == [
        r.ruleId for r in converted.results
    ]
    assert [r.partialFingerprints for r in committed_results] == [
        r.partialFingerprints for r in converted.results
    ]
    assert [r.level for r in committed_results] == [r.level for r in converted.results]


def _load_stub():
    spec = importlib.util.spec_from_file_location(
        "agent_scan_stub_analysis_server", CAPTURED / "stub_analysis_server.py"
    )
    assert spec is not None and spec.loader is not None
    stub = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stub)
    return stub


def test_the_committed_stub_answers_the_capture_it_produced(marked):
    """The capture is reproducible: the stub flags the documented marker with the
    risk names and scores the capture holds, and flags nothing without it."""
    stub = _load_stub()
    risks = marked["scan_path_responses"][0]["skill_risks"][0]["risk_indexes"]
    file = {"path": "SKILL.md", "content": f"text\n<!-- {stub.MARKER} -->\n"}
    answered = stub._risks_for({"files": [file]})
    assert {k: v["score"] for k, v in answered.items()} == {
        k: v["score"] for k, v in risks.items()
    }
    assert (
        stub._risks_for({"files": [{"path": "SKILL.md", "content": "benign\n"}]}) == {}
    )
