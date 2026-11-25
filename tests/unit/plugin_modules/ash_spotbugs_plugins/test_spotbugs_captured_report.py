# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: F811
# (fixtures imported from the behavior module are redefined by name in the signatures)

"""SpotBugsScanner over SARIF that SpotBugs 4.10.5 actually wrote.

tests/test_data/scanners/spotbugs/captured/README.md has the argv and the input. The
scan() tests replace the subprocess with a fake that serves those captures, so they
run on every platform without Java. The expected rows are written out by hand from
the capture, not derived from the code under test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.schemas.sarif_schema_model import SarifReport

from .test_spotbugs_scanner_behavior import (  # noqa: F401  (fixtures)
    FakeSpotBugs,
    _run,
    _scanner,
    on_path,
    tree,
)

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "spotbugs"
    / "captured"
)

#: The capture holds 300 results: 270 note, 15 warning, 15 error. Thirteen belong to
#: rules tagged SECURITY: 3 error and 10 warning.
SECURITY_RESULTS = 13


def _findings(report: SarifReport):
    """(ruleId, SARIF level, ASH severity, start line or None) for every result.

    Some captured results name a class and carry no region, so the line is optional.
    """
    out = []
    for r in report.get_all_results():
        region = r.locations[0].physicalLocation.root.region
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
                region.startLine if region else None,
            )
        )
    return out


def _text(name: str) -> str:
    return (CAPTURED / name).read_text(encoding="utf-8")


def test_the_captures_are_what_the_tests_below_assume():
    positive = json.loads(_text("positive.sarif"))["runs"][0]
    assert len(positive["results"]) == 300
    assert [e["name"] for e in positive["tool"]["extensions"]] == [
        "edu.umd.cs.findbugs.plugins.core",
        "com.h3xstream.findsecbugs",
    ]
    negative = json.loads(_text("negative.sarif"))["runs"][0]
    assert negative["results"] == []


def test_the_default_keeps_the_security_results_and_rates_them_by_level(
    tree, tmp_path, on_path, monkeypatch
):
    report = _run(
        _scanner(tree, tmp_path),
        FakeSpotBugs(text=_text("positive.sarif"), exit_code=3),
        monkeypatch,
    )
    assert isinstance(report, SarifReport)
    findings = _findings(report)
    assert len(findings) == SECURITY_RESULTS
    by_level = {}
    for _rule, level, severity, _line in findings:
        by_level.setdefault((level, severity), 0)
        by_level[(level, severity)] += 1
    assert by_level == {("error", "HIGH"): 3, ("warning", "MEDIUM"): 10}
    assert (
        "USO_UNSAFE_METHOD_SYNCHRONIZATION",
        "error",
        "HIGH",
        89,
    ) in findings
    assert ("XXE_XMLREADER", "warning", "MEDIUM", 67) in findings


def test_turning_security_only_off_keeps_every_result_and_rates_notes_low(
    tree, tmp_path, on_path, monkeypatch
):
    report = _run(
        _scanner(tree, tmp_path, security_only=False),
        FakeSpotBugs(text=_text("positive.sarif"), exit_code=3),
        monkeypatch,
    )
    findings = _findings(report)
    assert len(findings) == 300
    counts = {}
    for _rule, level, severity, _line in findings:
        counts[(level, severity)] = counts.get((level, severity), 0) + 1
    assert counts == {
        ("note", "LOW"): 270,
        ("warning", "MEDIUM"): 15,
        ("error", "HIGH"): 15,
    }
    assert (
        "EI_EXPOSE_REP",
        "note",
        "LOW",
        333,
    ) in findings


def test_the_negative_capture_is_a_clean_scan_although_classes_were_missing(
    tree, tmp_path, on_path, monkeypatch
):
    # SpotBugs exited 2 (classes needed for the analysis were missing) on the
    # negative run; that is a finished run with no results, not a failure.
    report = _run(
        _scanner(tree, tmp_path),
        FakeSpotBugs(text=_text("negative.sarif"), exit_code=2),
        monkeypatch,
    )
    assert isinstance(report, SarifReport)
    assert _findings(report) == []
