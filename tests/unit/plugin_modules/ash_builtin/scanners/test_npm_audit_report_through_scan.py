# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One small npm 7+ report read through ``scan()``, not the conversion alone.

The per-advisory grading, the by-name result for an entry with no nodes and
the root refs of a transitive finding were pinned at the conversion function.
This runs one report through the scan: a package with two advisories of
different severity (one with no CVSS object, one with npm's zero score and
null vector), an entry that lists no node, and a transitive entry whose root
lists no node. The results, their grades after the normalizer copies rule
scores onto them, and the root refs are read from the report the scan returns.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from automated_security_helper.utils.sarif_utils import (
    normalize_sarif_result_severities,
)
from automated_security_helper.utils.severity_ladder import result_severity

pytestmark = pytest.mark.unit


def _via(name, severity, **cvss):
    entry = {
        "source": 1,
        "name": name,
        "title": f"{severity} advisory in {name}",
        "url": f"https://github.com/advisories/GHSA-{name}-{severity}",
        "severity": severity,
        "cwe": [],
        "range": "<1.0.0",
    }
    entry.update(cvss)
    return entry


def _entry(name, severity, via, nodes, effects=()):
    return {
        "name": name,
        "severity": severity,
        "isDirect": not any(isinstance(v, str) for v in via),
        "via": via,
        "effects": list(effects),
        "range": "*",
        "nodes": nodes,
        "fixAvailable": True,
    }


REPORT = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        # Two advisories of different severity on one package: one with no
        # CVSS object at all, one with npm's zero score and null vector.
        "pkg": _entry(
            "pkg",
            "critical",
            [
                _via("pkg", "low"),
                _via("pkg", "critical", cvss={"score": 0, "vectorString": None}),
            ],
            ["node_modules/pkg"],
        ),
        # An entry npm lists no node for.
        "bare": _entry("bare", "moderate", [_via("bare", "moderate")], []),
        # A transitive entry whose root lists no node.
        "root": _entry("root", "high", [_via("root", "high")], [], effects=["child"]),
        "child": _entry("child", "high", ["root"], ["node_modules/child"]),
    },
    "metadata": {
        "vulnerabilities": {
            "info": 0,
            "low": 1,
            "moderate": 1,
            "high": 2,
            "critical": 1,
            "total": 5,
        },
        "dependencies": {"prod": 5, "dev": 0, "total": 5},
    },
}


@pytest.fixture
def context(tmp_path, monkeypatch):
    # Not the machine's: ASH_OFFLINE set in the environment makes scan() record
    # the lockfile as MISSING, and a missing npm on PATH makes it a failed
    # target; either failed the four tests below without saying why.
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setattr(
        npm_audit_scanner, "find_executable", lambda name: str(tmp_path / name)
    )
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    app = context.work_dir / "app"
    app.mkdir()
    (app / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    (app / "package-lock.json").write_text("{}\n", encoding="utf-8")
    return context


def _answer(self, command, **kwargs):
    if "--version" in command:
        return {"stdout": "10.9.4\n", "stderr": "", "returncode": 0}
    response = {"stdout": json.dumps(REPORT), "stderr": "", "returncode": 1}
    self._process_command_response(response)
    return response


def _scanned(context):
    scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
    scanner.dependencies_satisfied = True
    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=_answer
    ):
        report = scanner.scan(target=context.work_dir, target_type="converted")
    assert scanner.errors == [], scanner.errors
    return normalize_sarif_result_severities(report)


def _uri(result):
    location = result.locations[0].model_dump(by_alias=True, exclude_none=True)
    return location["physicalLocation"]["artifactLocation"]["uri"]


def test_each_advisory_is_graded_by_its_own_severity_through_the_scan(context):
    report = _scanned(context)

    grades = {
        (r.ruleId, _uri(r)): result_severity(r)
        for r in report.runs[0].results
        if r.properties.model_extra["package_name"] == "pkg"
    }
    assert grades == {
        ("GHSA-pkg-low", "node_modules/pkg/package.json"): "LOW",
        ("GHSA-pkg-critical", "node_modules/pkg/package.json"): "CRITICAL",
    }, grades
    by_id = {rule.id: rule for rule in report.runs[0].tool.driver.rules}
    for rule_id in ("GHSA-pkg-low", "GHSA-pkg-critical"):
        assert "security_severity" not in (by_id[rule_id].properties.model_extra or {})


def test_an_entry_with_no_nodes_is_one_result_by_name_through_the_scan(context):
    report = _scanned(context)

    (bare,) = [r for r in report.runs[0].results if r.ruleId == "GHSA-bare-moderate"]
    assert _uri(bare) == "node_modules/bare/package.json"
    assert "package_path" not in bare.properties.model_extra
    assert result_severity(bare) == "MEDIUM"


def test_a_transitive_result_refers_to_its_rootless_root_through_the_scan(context):
    report = _scanned(context)

    (root,) = [r for r in report.runs[0].results if r.ruleId == "GHSA-root-high"]
    (child,) = [
        r for r in report.runs[0].results if r.ruleId == "npm-audit-transitive-child"
    ]
    assert child.properties.model_extra["root_advisories"] == [
        {"rule_id": "GHSA-root-high", "uri": _uri(root)}
    ]
    assert _uri(root) == "node_modules/root/package.json"
    # The root's own result is graded by its word; the transitive result's
    # grade is the SARIF level's reading (it carries no word grade and its rule
    # no score), which is not pinned here.
    assert result_severity(root) == "HIGH"


def test_the_run_carries_the_report_s_metrics(context):
    report = _scanned(context)

    metrics = report.runs[0].properties.model_extra["metrics"]
    assert metrics["total"] == 5 and metrics["critical"] == 1, metrics
