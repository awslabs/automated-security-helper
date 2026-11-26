# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The install pin, and the scanner over real captured govulncheck runs.

``tests/test_data/scanners/govulncheck/captured/`` holds what govulncheck v1.9.0
wrote to standard output (see its README). These tests serve those bytes to the
scanner through the behavior tests' fake subprocess, so the parse, the severity
mapping and the flat rows the register declares are pinned over output the tool
produced, not over a hand-built document.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_govulncheck_plugins import (
    govulncheck_scanner as gs,
)
from automated_security_helper.plugin_modules.ash_govulncheck_plugins.govulncheck_scanner import (
    GovulncheckScanner,
)

from .test_govulncheck_scanner_behavior import FakeGovulncheck, _run, _scanner

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "govulncheck"
    / "captured"
)

#: The five results of the positive capture at level error: the code calls
#: Template.Execute and Reader.ReadMIMEHeader, and govulncheck follows the calls
#: on into net/http. Written out here, read from the capture by hand.
CALLED = {
    "GO-2026-6599",
    "GO-2026-6600",
    "GO-2026-6608",
    "GO-2026-6613",
    "GO-2026-6859",
}


def _stdout(name: str) -> str:
    return (CAPTURED / name).read_text(encoding="utf-8")


def _materialized(name: str, destination: Path) -> Path:
    """The committed input ``in/<name>`` with its ``.fixture`` suffixes dropped."""
    destination.mkdir()
    for path in sorted((CAPTURED / "in" / name).glob("*.fixture")):
        shutil.copyfile(path, destination / path.name[: -len(".fixture")])
    return destination


@pytest.fixture
def scanned(tmp_path, monkeypatch):
    """The scanner's report over the positive input, served the positive capture."""
    monkeypatch.setattr(gs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")
    monkeypatch.setattr(GovulncheckScanner, "_scanner_offline", lambda self: False)
    source = _materialized("pos", tmp_path / "src")
    scanner = _scanner(source, tmp_path)
    report = _run(
        scanner, FakeGovulncheck(stdout=_stdout("positive.sarif")), monkeypatch
    )
    return scanner, report


# ---------------------------------------------------------------------------
# The pin and the capture belong together
# ---------------------------------------------------------------------------


def test_the_capture_was_made_by_the_pinned_release():
    driver = json.loads(_stdout("positive.sarif"))["runs"][0]["tool"]["driver"]
    assert driver["name"] == "govulncheck"
    assert driver["semanticVersion"] == gs.GOVULNCHECK_VERSION == "v1.9.0"
    assert driver["properties"]["scan_level"] == "symbol"
    # The README records the checksum database line of the module that was built.
    readme = (CAPTURED / "README.md").read_text(encoding="utf-8")
    assert f"golang.org/x/vuln {gs.GOVULNCHECK_VERSION} h1:" in readme
    assert f"go install {gs.GOVULNCHECK_PACKAGE}@{gs.GOVULNCHECK_VERSION}" in readme


def test_the_inputs_are_committed_under_names_no_dependency_scanner_reads():
    committed = sorted(
        p.relative_to(CAPTURED).as_posix()
        for p in (CAPTURED / "in").rglob("*")
        if p.is_file()
    )
    assert committed == [
        "in/neg/go.mod.fixture",
        "in/neg/main.go.fixture",
        "in/pos/go.mod.fixture",
        "in/pos/main.go.fixture",
    ]


# ---------------------------------------------------------------------------
# The scanner over the captured runs
# ---------------------------------------------------------------------------


def test_every_captured_result_is_rated_and_its_level_agrees(scanned):
    scanner, report = scanned
    rated = {
        r.ruleId: (
            getattr(r.level, "value", r.level),
            getattr(r.properties, "issue_severity", None),
        )
        for r in report.get_all_results()
    }
    assert len(rated) == 15
    assert {rule for rule, (level, _) in rated.items() if level == "error"} == CALLED
    for rule, pair in rated.items():
        expected = ("error", "HIGH") if rule in CALLED else ("warning", "MEDIUM")
        assert pair == expected, rule
    assert scanner.tool_version == gs.GOVULNCHECK_VERSION


def test_every_captured_result_points_at_line_one_of_the_go_mod(scanned):
    _, report = scanned
    for result in report.get_all_results():
        (location,) = result.locations
        physical = location.physicalLocation.root
        assert physical.artifactLocation.uri == "go.mod"
        assert physical.region.startLine == 1
        assert physical.region.startColumn is None
        assert {"vulnerability", "security"} <= set(result.properties.tags)


def test_the_rules_link_the_advisory_and_tag_its_cve_aliases(scanned):
    _, report = scanned
    rules = report.runs[0].tool.driver.rules
    assert len(rules) == 15
    for rule in rules:
        assert str(rule.helpUri) == f"https://pkg.go.dev/vuln/{rule.id}"
        assert rule.properties.tags, rule.id
        assert all(re.fullmatch(r"CVE-\d{4}-\d+", t) for t in rule.properties.tags)


def test_the_flat_rows_carry_what_the_register_declares(scanned):
    """The register's cells over the captured run, one row per result.

    MAPPED: rule id, severity, file, line, message, references, tags. DROPPED: the
    CVE alias (rule tags) and the package (message text and frames) are not
    written, so a change that starts writing them must redeclare those cells.
    """
    _, report = scanned
    run = report.runs[0]
    for result in report.get_all_results():
        flat = FlatVulnerability.from_sarif_result(result, "govulncheck", "SCA", run)
        assert flat.rule_id == result.ruleId
        assert flat.severity == ("HIGH" if result.ruleId in CALLED else "MEDIUM")
        assert (flat.file_path, flat.line_start) == ("go.mod", 1)
        assert flat.description
        assert json.loads(flat.references) == [
            f"https://pkg.go.dev/vuln/{result.ruleId}"
        ]
        tags = json.loads(flat.tags)
        assert {"vulnerability", "security"} <= set(tags)
        assert not any(tag.startswith("CVE-") for tag in tags)
        assert flat.cve_id is None
        assert flat.package_name is None and flat.package_version is None


def test_the_negative_capture_is_a_clean_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(gs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")
    monkeypatch.setattr(GovulncheckScanner, "_scanner_offline", lambda self: False)
    source = _materialized("neg", tmp_path / "src")
    scanner = _scanner(source, tmp_path)
    report = _run(
        scanner, FakeGovulncheck(stdout=_stdout("negative.sarif")), monkeypatch
    )
    assert report.get_all_results() == []
    assert scanner.tool_version == gs.GOVULNCHECK_VERSION
