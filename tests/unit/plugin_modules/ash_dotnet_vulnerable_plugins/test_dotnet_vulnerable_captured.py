# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""dotnet-vulnerable over a real captured ``dotnet list package`` run.

``tests/test_data/scanners/dotnet_vulnerable/captured/`` holds what the .NET SDK
10.0.404 printed for the scanner's exact argv (see its README). These tests read those
files, so the report shape and the conversion are pinned over output the tool
produced, not over a hand-built document. The hand-built ``reports/`` beside it keep
the severity rows a real run cannot be made to produce.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_dotnet_vulnerable_plugins import (
    dotnet_vulnerable_scanner as ds,
)
from automated_security_helper.utils.package_identity import extract_package_identity

from .test_dotnet_vulnerable_scanner_behavior import _scanner

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "dotnet_vulnerable"
    / "captured"
)

#: The uri the scanner computes for the captured project: source-relative, as the run
#: was made from the directory that holds ``pos/``.
PROJECT_URI = "pos/App.csproj"

#: (package, version) -> (rule id, ASH severity, SARIF level, dependency kind), read
#: from the captured report by hand.
EXPECTED = {
    ("Microsoft.Extensions.Caching.Memory", "8.0.0"): (
        "GHSA-qj66-m88j-hmgj",
        "HIGH",
        "error",
        "transitive",
    ),
    ("Newtonsoft.Json", "12.0.1"): (
        "GHSA-5crp-9r3c-p9vr",
        "HIGH",
        "error",
        "top-level",
    ),
    ("Npgsql", "8.0.0"): ("GHSA-x9vc-6hfv-hg8c", "HIGH", "error", "transitive"),
    ("System.Text.Encodings.Web", "4.5.0"): (
        "GHSA-ghhp-997w-qr28",
        "CRITICAL",
        "error",
        "top-level",
    ),
}


def _load(name: str) -> dict:
    return json.loads((CAPTURED / name).read_text(encoding="utf-8"))


def _results():
    return ds.convert_report(_load("positive.json"), project_uri=PROJECT_URI)


def test_the_captures_are_reports_of_the_scanners_argv():
    for name in ("positive.json", "negative.json"):
        document = ds.parse_report(json.dumps(_load(name)))
        assert document["version"] == 1
        assert document["parameters"] == "--vulnerable --include-transitive"
        assert ds.error_problems(document) == []


def test_a_project_with_nothing_vulnerable_carries_only_its_path():
    (project,) = _load("negative.json")["projects"]
    assert set(project) == {"path"}
    assert ds.convert_report(_load("negative.json"), project_uri="neg/App.csproj") == []


def test_each_vulnerable_package_of_the_capture_is_one_result():
    got = {}
    for result in _results():
        name, version = extract_package_identity(result.properties)[:2]
        got[(name, version)] = (
            result.ruleId,
            result.properties.issue_severity,
            getattr(result.level, "value", result.level),
            result.properties.dependency_kind,
        )
    assert got == EXPECTED


def test_both_target_frameworks_are_named_on_each_result():
    results = _results()
    assert results
    for result in results:
        assert result.properties.target_frameworks == ["net10.0", "net8.0"]


def test_results_sit_on_line_one_of_the_project_file_and_are_failures():
    for result in _results():
        (location,) = result.locations
        physical = location.physicalLocation.root
        assert physical.artifactLocation.uri == PROJECT_URI
        assert physical.region.startLine == 1
        assert getattr(result.kind, "value", result.kind) == "fail"


def test_the_committed_sarif_is_what_the_scanner_writes(tmp_path):
    scanner = _scanner(tmp_path, tmp_path)
    written = scanner._empty_report(_results())
    committed = json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
    assert committed == json.loads(
        written.model_dump_json(by_alias=True, exclude_none=True)
    )
