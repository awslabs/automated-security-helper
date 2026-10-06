# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""zizmor against the real binary.

These tests do not skip when zizmor is absent. The scanner's own dependency
resolution installs it (``uv tool install`` within the scanner's version
constraint) exactly as ``ash dependencies install`` would, and a failure to do
so fails the test: an integration test that quietly skipped would let the CI
leg pass with the scanner never having run.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
    ZizmorScanner,
    ZizmorScannerConfig,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.integration

FIXTURE_REPO = Path(__file__).parents[2] / "test_data" / "scanners" / "zizmor" / "repo"

#: Findings any zizmor in the supported range must report on the fixture:
#: (rule, file). Line numbers and the full set are pinned by the unit tests
#: against the captured 1.30.1 output; this asserts the real binary agrees on
#: what matters without failing when a later 1.x adds an audit.
REQUIRED_FINDINGS = {
    ("zizmor/template-injection", ".github/workflows/vulnerable.yml"),
    ("zizmor/dangerous-triggers", ".github/workflows/vulnerable.yml"),
    ("zizmor/unpinned-uses", ".github/workflows/vulnerable.yml"),
    ("zizmor/template-injection", "actions/greet/action.yml"),
}
NEGATIVE_FILES = {
    ".github/workflows/clean.yml",
    "actions/clean/action.yaml",
    "other/action.yml",
}


def _scanner(source_dir: Path) -> ZizmorScanner:
    output_dir = source_dir / ".ash" / "ash_output"
    return ZizmorScanner(
        context=PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=output_dir / "converted",
            config=get_default_config(),
        ),
        config=ZizmorScannerConfig(enabled=True),
    )


def _findings(report: SarifReport):
    rows = []
    for run in report.runs:
        for result in run.results or []:
            physical = result.locations[0].physicalLocation.root
            rows.append(
                (
                    result.ruleId,
                    physical.artifactLocation.uri,
                    result.properties.issue_severity,
                )
            )
    return rows


@pytest.fixture
def source(tmp_path) -> Path:
    target = tmp_path / "src"
    shutil.copytree(FIXTURE_REPO, target)
    return target


def _scan(source_dir: Path):
    scanner = _scanner(source_dir)
    assert scanner.validate_plugin_dependencies() is True, (
        "zizmor could not be resolved or installed: "
        f"{scanner.dependency_unavailable_reason}"
    )
    report = scanner.scan(source_dir, "source", [])
    assert isinstance(report, SarifReport), report
    return scanner, report


def test_real_zizmor_finds_the_fixture_positives_and_not_the_negatives(source):
    scanner, report = _scan(source)
    findings = _findings(report)
    found = {(rule, uri) for rule, uri, _ in findings}
    assert REQUIRED_FINDINGS <= found, findings
    assert not {uri for _, uri in found} & NEGATIVE_FILES, findings
    assert not any("node_modules" in uri or "nested" in uri for _, uri in found)
    assert {severity for _, _, severity in findings} <= {
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    }
    # other/action.yml is not an Actions definition: dropped from the count.
    assert scanner.targets_attempted == 4
    assert scanner.targets_failed == 0
    assert report.runs[0].invocations[0].executionSuccessful is True
    assert "--offline" in report.runs[0].invocations[0].arguments


def test_real_zizmor_paths_are_relative_to_a_scanned_subdirectory(tmp_path):
    """zizmor reports URIs from the git root; ASH must report them from source_dir."""
    repository = tmp_path / "repository"
    shutil.copytree(FIXTURE_REPO, repository / "service")
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    _, report = _scan(repository / "service")
    found = {(rule, uri) for rule, uri, _ in _findings(report)}
    assert REQUIRED_FINDINGS <= found, found


def test_real_zizmor_with_nothing_to_audit_is_skipped_cleanly(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('hello')\n")
    scanner, report = _scan(source_dir)
    assert report.runs[0].results == []
    assert scanner.targets_attempted == 0


def test_real_zizmor_offline(source, monkeypatch):
    # Resolve (and if needed install) online first, as `ash dependencies install`
    # would before a machine goes offline.
    _scan(source)
    monkeypatch.setenv("ASH_OFFLINE", "true")
    monkeypatch.setenv("GH_TOKEN", "must-not-be-used")
    _, report = _scan(source)
    found = {(rule, uri) for rule, uri, _ in _findings(report)}
    assert REQUIRED_FINDINGS <= found


def test_ash_scan_with_zizmor_applies_rule_path_and_line_suppressions(source):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    config = {
        "project_name": "zizmor-suppressions",
        "fail_on_findings": False,
        "global_settings": {
            "suppressions": [
                {
                    "rule_id": "zizmor/template-injection",
                    "path": "actions/greet/action.yml",
                    "reason": "rule and path",
                },
                {
                    "rule_id": "zizmor/dangerous-triggers",
                    "path": ".github/workflows/vulnerable.yml",
                    "line_start": 2,
                    "line_end": 2,
                    "reason": "rule, path and line",
                },
                {
                    # Wrong line: must NOT suppress.
                    "rule_id": "zizmor/unpinned-uses",
                    "path": ".github/workflows/vulnerable.yml",
                    "line_start": 3,
                    "line_end": 3,
                    "reason": "does not match",
                },
            ]
        },
        "scanners": {"zizmor": {"enabled": True}},
    }
    config_path = source / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.safe_dump(config))
    output_dir = source.parent / "out"

    run_ash_scan(
        source_dir=str(source),
        output_dir=str(output_dir),
        config=str(config_path),
        scanners=["zizmor"],
        progress=False,
        show_summary=False,
        fail_on_findings=False,
        fail_on_incomplete_scanners=False,
    )

    sarif = json.loads((output_dir / "reports" / "ash.sarif").read_text())
    rows = []
    for run in sarif["runs"]:
        for result in run.get("results", []):
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            rows.append((result["ruleId"], uri, bool(result.get("suppressions"))))
    by_key = {}
    for rule, uri, suppressed in rows:
        by_key.setdefault((rule, uri), set()).add(suppressed)

    assert by_key[("zizmor/template-injection", "actions/greet/action.yml")] == {True}
    assert by_key[
        ("zizmor/dangerous-triggers", ".github/workflows/vulnerable.yml")
    ] == {True}
    assert by_key[("zizmor/unpinned-uses", ".github/workflows/vulnerable.yml")] == {
        False
    }
    assert by_key[
        ("zizmor/template-injection", ".github/workflows/vulnerable.yml")
    ] == {False}
