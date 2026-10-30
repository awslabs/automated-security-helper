# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An npm 7+ advisory is reported against the copies its range covers.

npm audit lists every installed copy (node) of a package under each of the
package's advisories. The conversion paired every node with every advisory,
so a copy at a fixed version carried another copy's advisory, and one GHSA
split into several ranges (minimist's ``<0.2.4`` and ``>=1.0.0 <1.2.6``) was
reported once per range on every copy. When the lockfile gives a copy's
installed version and the advisory's own range excludes it, no result is
made; when the answer is uncertain (no version, an unparsable range, a
prerelease) the result is kept as before.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
    _version_in_range,
)
from automated_security_helper.utils.package_identity import identity_properties

pytestmark = pytest.mark.unit

GHSA = "https://github.com/advisories/GHSA-xvch-5gv4-984h"


def _via(rng):
    return {
        "source": 1179,
        "name": "minimist",
        "title": "Prototype Pollution in minimist",
        "url": GHSA,
        "severity": "critical",
        "cwe": ["CWE-1321"],
        "cvss": {"score": 9.8, "vectorString": "CVSS:3.1/AV:N"},
        "range": rng,
    }


def _report(nodes, ranges=("<0.2.4", ">=1.0.0 <1.2.6")):
    return {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "minimist": {
                "name": "minimist",
                "severity": "critical",
                "isDirect": False,
                "via": [_via(r) for r in ranges],
                "effects": ["mkdirp"],
                "range": " || ".join(ranges),
                "nodes": list(nodes),
                "fixAvailable": True,
            }
        },
        "metadata": {"vulnerabilities": {"critical": 1}},
    }


@pytest.fixture
def scanner(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for d in (context.source_dir, context.output_dir, context.work_dir):
        d.mkdir(parents=True)
    return NpmAuditScanner(context=context, config=NpmAuditScannerConfig())


def _versions(monkeypatch, by_node):
    """Stand in for the lockfile index: each node's installed version."""

    def identity(pkg_name, node_path, lock_rel, lock_index):
        return identity_properties(pkg_name, by_node.get(node_path), node_path)

    monkeypatch.setattr(NpmAuditScanner, "_node_identity", staticmethod(identity))


def _rows(report):
    return sorted(
        (
            r.properties.model_extra.get("package_path"),
            r.properties.model_extra["vulnerable_versions"],
        )
        for r in report.runs[0].results
    )


def test_each_copy_takes_the_range_that_covers_it(scanner, monkeypatch):
    old, new = "node_modules/mkdirp/node_modules/minimist", "node_modules/minimist"
    _versions(monkeypatch, {old: "0.0.8", new: "1.2.5"})

    report = scanner._convert_npm_audit_to_sarif(
        _report([old, new]), scanner.context.source_dir
    )

    # One row per copy, each on the range that covers its version; _rows sorts
    # by path, and "node_modules/minimist" sorts before "node_modules/mkdirp/".
    assert _rows(report) == sorted([(old, "<0.2.4"), (new, ">=1.0.0 <1.2.6")])
    assert len(report.runs[0].tool.driver.rules) == 1


def test_a_fixed_copy_carries_no_advisory_meant_for_another(scanner, monkeypatch):
    old, fixed = "node_modules/a/node_modules/minimist", "node_modules/minimist"
    _versions(monkeypatch, {old: "0.0.8", fixed: "1.2.8"})

    report = scanner._convert_npm_audit_to_sarif(
        _report([old, fixed]), scanner.context.source_dir
    )

    assert _rows(report) == [(old, "<0.2.4")]


def test_an_unknown_version_keeps_every_pairing(scanner, monkeypatch):
    """Control: with no installed version the answer is uncertain, so every
    advisory is still reported on every copy, as before."""
    node = "node_modules/minimist"
    _versions(monkeypatch, {})

    report = scanner._convert_npm_audit_to_sarif(
        _report([node]), scanner.context.source_dir
    )

    assert _rows(report) == [(node, "<0.2.4"), (node, ">=1.0.0 <1.2.6")]


def test_an_unparsable_range_keeps_the_result(scanner, monkeypatch):
    node = "node_modules/minimist"
    _versions(monkeypatch, {node: "1.2.8"})

    report = scanner._convert_npm_audit_to_sarif(
        _report([node], ranges=("^1.0.0",)), scanner.context.source_dir
    )

    assert _rows(report) == [(node, "^1.0.0")]


def test_a_prerelease_copy_keeps_the_result(scanner, monkeypatch):
    node = "node_modules/minimist"
    _versions(monkeypatch, {node: "1.3.0-beta.1"})

    report = scanner._convert_npm_audit_to_sarif(
        _report([node], ranges=("<1.2.6",)), scanner.context.source_dir
    )

    assert _rows(report) == [(node, "<1.2.6")]


@pytest.mark.parametrize(
    ("version", "vulnerable_range", "expected"),
    [
        ("0.0.8", "<0.2.4", True),
        ("1.2.5", "<0.2.4", False),
        ("1.2.5", "<0.2.4 || >=1.0.0 <1.2.6", True),
        ("1.2.6", "<0.2.4 || >=1.0.0 <1.2.6", False),
        ("4.17.21", ">=4.0.0 <=4.17.23", True),
        ("4.17.24", ">=4.0.0 <=4.17.23", False),
        ("3.0.0", "=3.0.0", True),
        ("3.0.1", "3.0.0", False),
        ("v1.0.0", "<2.0.0", True),
        ("1.0.0", "*", True),
        ("1.0.0", "", True),
        ("1.0.0", "^1.0.0", None),
        ("1.0.0", "1.0.0 - 2.0.0", None),
        ("1.0.0-rc.1", "<2.0.0", None),
        ("2.0.0", ">=2.0.0-0", None),
        ("not a version", "<2.0.0", None),
        (None, "<2.0.0", None),
        ("1.0.0", None, None),
    ],
)
def test_version_in_range(version, vulnerable_range, expected):
    assert _version_in_range(version, vulnerable_range) is expected
