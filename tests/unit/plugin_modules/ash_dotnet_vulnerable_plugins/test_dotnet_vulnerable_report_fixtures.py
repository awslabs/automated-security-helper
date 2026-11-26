# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""dotnet-vulnerable's conversion over the committed report fixtures.

The fixtures (tests/test_data/scanners/dotnet_vulnerable/reports) are written by
hand in NuGet's documented ``dotnet list package --format json`` shape; they are
not captures of an SDK run (see the README beside them). The severity mapping is
asserted row by row over the fixture, so a change to the map or to a SARIF level
fails here, and the negative fixture must convert to no result.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_dotnet_vulnerable_plugins import (
    dotnet_vulnerable_scanner as ds,
)
from automated_security_helper.utils.package_identity import extract_package_identity

pytestmark = pytest.mark.unit

_REPORTS = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "dotnet_vulnerable"
    / "reports"
)

#: package id -> (rule id, ASH severity, SARIF level)
EXPECTED = {
    "Example.Critical": ("GHSA-aaaa-bbbb-cccc", "CRITICAL", "error"),
    "Newtonsoft.Json": ("GHSA-5crp-9r3c-p9vr", "HIGH", "error"),
    "Example.Transitive": ("GHSA-dddd-eeee-ffff", "MEDIUM", "warning"),
    "Example.Low": ("GHSA-gggg-hhhh-iiii", "LOW", "note"),
    "Example.Unrated": ("NUGET-VULNERABLE-PACKAGE", "MEDIUM", "warning"),
    "Example.Future": ("GHSA-jjjj-kkkk-llll", "HIGH", "error"),
}


def _load(name: str) -> dict:
    return json.loads((_REPORTS / name).read_text(encoding="utf-8"))


def _by_package(results):
    return {extract_package_identity(r.properties)[0]: r for r in results}


def test_the_positive_fixture_maps_every_severity_row():
    results = ds.convert_report(_load("positive.json"), project_uri="App/App.csproj")
    by_package = _by_package(results)
    assert set(by_package) == set(EXPECTED)
    for package, (rule, severity, level) in EXPECTED.items():
        result = by_package[package]
        assert result.ruleId == rule, package
        assert result.properties.issue_severity == severity, package
        assert getattr(result.level, "value", result.level) == level, package
        assert getattr(result.kind, "value", result.kind) == "fail", package


def test_a_package_under_two_frameworks_is_one_result_naming_both():
    results = ds.convert_report(_load("positive.json"), project_uri="App/App.csproj")
    newtonsoft = [
        r
        for r in results
        if extract_package_identity(r.properties)[0] == "Newtonsoft.Json"
    ]
    assert len(newtonsoft) == 1
    assert newtonsoft[0].properties.target_frameworks == ["net6.0", "net8.0"]
    assert extract_package_identity(newtonsoft[0].properties)[:2] == (
        "Newtonsoft.Json",
        "9.0.1",
    )


def test_the_negative_fixture_yields_no_result():
    assert ds.convert_report(_load("negative.json"), project_uri="App/App.csproj") == []


def test_the_fixtures_are_the_documented_report_shape():
    for name in ("positive.json", "negative.json"):
        document = ds.parse_report(json.dumps(_load(name)))
        assert document["version"] == 1
        assert document["projects"][0]["frameworks"]
        assert ds.error_problems(document) == []
