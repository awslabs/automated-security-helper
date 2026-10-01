# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Dependency converters must carry package identity into SARIF.

A package-scoped suppression can only match what the SARIF result says about
the package. Before this change:

- grype's SARIF put every finding at line 1 of the lockfile with the package
  only in the message text, so ``brace-expansion`` 1.1.18 and a copy bundled
  inside ``aws-cdk-lib`` at 5.0.9 differed in nothing structured.
- npm-audit merged the audit output of every lockfile into one dict keyed by
  package name, so a package vulnerable in two lockfiles kept only the last
  lockfile's nodes. Its ``installed_version`` held the advisory range, not the
  installed version, and nothing recorded which lockfile a node came from.

The converters now write ``package_name``, ``package_version`` and, where the
lockfile pins it down, ``package_path`` into ``result.properties``.
``package_path`` is where the package is installed relative to the scan root:
the lockfile's directory joined with its ``packages`` key.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

BUNDLED_KEY = "node_modules/aws-cdk-lib/node_modules/brace-expansion"
TOP_KEY = "node_modules/brace-expansion"


def write_lockfile(project: Path, entries: dict) -> Path:
    """Write an npm v3 lockfile, formatted the way npm formats it (indent 2)."""
    project.mkdir(parents=True, exist_ok=True)
    (project / "package.json").write_text('{"name": "p", "version": "1.0.0"}')
    packages = {"": {"name": "p", "version": "1.0.0"}}
    packages.update(entries)
    lock = {"name": "p", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}
    path = project / "package-lock.json"
    path.write_text(json.dumps(lock, indent=2) + "\n")
    return path


def bundled_and_top_level(top_version: str) -> dict:
    return {
        "node_modules/aws-cdk-lib": {"version": "2.272.0"},
        BUNDLED_KEY: {"version": "5.0.9", "inBundle": True},
        TOP_KEY: {"version": top_version},
    }


def props(result) -> dict:
    return result.properties.model_dump(exclude_none=True) if result.properties else {}


# --------------------------------------------------------------------------- grype


def grype_result(rule: str, name: str, version: str, uri: str) -> Result:
    """A result shaped exactly like grype's SARIF presenter emits it."""
    return Result(
        ruleId=f"{rule}-{name}",
        message=Message(
            text=(
                f"A high vulnerability in npm package: {name}, version {version} "
                f"was found at: /{uri}"
            )
        ),
        locations=[
            Location(
                physicalLocation=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri=f"/{uri}"),
                    region=Region(startLine=1, startColumn=1, endLine=1, endColumn=1),
                )
            )
        ],
    )


def grype_report(*results: Result) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(tool=Tool(driver=ToolComponent(name="grype")), results=list(results))
        ],
    )


@pytest.fixture
def grype_scanner(test_plugin_context):
    return GrypeScanner(context=test_plugin_context)


class TestGrypeIdentity:
    def test_name_version_and_unique_path(self, grype_scanner, tmp_path):
        write_lockfile(tmp_path / "deploy/cdk", bundled_and_top_level("1.1.18"))
        uri = "deploy/cdk/package-lock.json"
        report = grype_report(
            grype_result("GHSA-6j4f-fj2g-mc7p", "brace-expansion", "5.0.9", uri),
            grype_result("GHSA-6j4f-fj2g-mc7p", "brace-expansion", "1.1.18", uri),
        )
        out = grype_scanner._post_process_sarif(report, [], tmp_path)
        bundled, top = out.runs[0].results
        assert props(bundled)["package_name"] == "brace-expansion"
        assert props(bundled)["package_version"] == "5.0.9"
        assert props(bundled)["package_path"] == f"deploy/cdk/{BUNDLED_KEY}"
        assert props(top)["package_version"] == "1.1.18"
        assert props(top)["package_path"] == f"deploy/cdk/{TOP_KEY}"
        # The URI is left as it was, so existing path-based suppressions hold.
        assert bundled.locations[0].physicalLocation.root.artifactLocation.uri == uri

    def test_collision_gets_no_path(self, grype_scanner, tmp_path):
        """Two lockfile entries with the same name and version: grype cannot say
        which one a finding is, so no path is claimed and a path-scoped
        suppression fails closed."""
        write_lockfile(tmp_path / "deploy/cc", bundled_and_top_level("5.0.9"))
        uri = "deploy/cc/package-lock.json"
        report = grype_report(
            grype_result("GHSA-6j4f-fj2g-mc7p", "brace-expansion", "5.0.9", uri),
        )
        out = grype_scanner._post_process_sarif(report, [], tmp_path)
        p = props(out.runs[0].results[0])
        assert p["package_name"] == "brace-expansion"
        assert p["package_version"] == "5.0.9"
        assert "package_path" not in p

    def test_unrecognised_message_attaches_nothing(self, grype_scanner, tmp_path):
        result = grype_result(
            "GHSA-x", "brace-expansion", "5.0.9", "a/package-lock.json"
        )
        result.message = Message(text="some other wording")
        out = grype_scanner._post_process_sarif(grype_report(result), [], tmp_path)
        p = props(out.runs[0].results[0])
        assert "package_name" not in p
        assert "package_version" not in p

    def test_non_npm_manifest_gets_name_and_version_only(self, grype_scanner, tmp_path):
        result = grype_result("GHSA-x", "pyjwt", "2.8.0", "uv.lock")
        result.message = Message(
            text=(
                "A high vulnerability in python package: pyjwt, version 2.8.0 "
                "was found at: /uv.lock"
            )
        )
        out = grype_scanner._post_process_sarif(grype_report(result), [], tmp_path)
        p = props(out.runs[0].results[0])
        assert p["package_name"] == "pyjwt"
        assert p["package_version"] == "2.8.0"
        assert "package_path" not in p


# ------------------------------------------------------------------------ npm-audit


def audit_json(nodes: list, range_: str = "<=1.1.20 || 4.0.0 - 5.0.11") -> str:
    return json.dumps(
        {
            "vulnerabilities": {
                "brace-expansion": {
                    "name": "brace-expansion",
                    "severity": "high",
                    "via": [
                        {
                            "source": 1,
                            "name": "brace-expansion",
                            "title": "DoS",
                            "url": "https://github.com/advisories/GHSA-6j4f-fj2g-mc7p",
                            "severity": "high",
                            "range": range_,
                        }
                    ],
                    "range": range_,
                    "nodes": nodes,
                    "fixAvailable": True,
                }
            },
            "metadata": {"vulnerabilities": {"high": 1}},
        }
    )


@pytest.fixture
def npm_scanner(test_plugin_context):
    scanner = NpmAuditScanner(
        context=test_plugin_context, config=NpmAuditScannerConfig()
    )
    scanner.exit_code = 1
    scanner.dependencies_satisfied = True
    scanner.tool_version = "1.0.0"
    return scanner


def run_npm_scan(npm_scanner, root: Path, projects: dict):
    """Run NpmAuditScanner.scan over ``projects`` ({dir: audit stdout})."""
    npm_scanner.context.source_dir = root

    def fake_run(command, results_dir, cwd, **kwargs):
        return {"stdout": projects[Path(cwd)]}

    with (
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.scan_set",
            return_value=[str(p / "package.json") for p in projects],
        ),
        patch.object(npm_scanner, "_pre_scan", return_value=True),
        patch.object(npm_scanner, "_post_scan"),
        patch.object(npm_scanner, "_run_subprocess", side_effect=fake_run),
    ):
        return npm_scanner.scan(target=root, target_type="source")


class TestNpmAuditIdentity:
    def test_every_lockfile_keeps_its_findings(self, npm_scanner, tmp_path):
        """Two lockfiles vulnerable to the same package: both keep their nodes.

        Before, the second lockfile's ``vulnerabilities`` dict replaced the
        first's under the shared package name, dropping its findings."""
        cdk = tmp_path / "deploy/cdk"
        cc = tmp_path / "deploy/cdk-constructs"
        write_lockfile(cdk, bundled_and_top_level("1.1.18"))
        write_lockfile(cc, bundled_and_top_level("5.0.9"))
        # Different node lists per lockfile, so a conversion that read one
        # lockfile's document for another would show up as a wrong path set.
        report = run_npm_scan(
            npm_scanner,
            tmp_path,
            {cdk: audit_json([BUNDLED_KEY, TOP_KEY]), cc: audit_json([BUNDLED_KEY])},
        )
        paths = sorted(props(r)["package_path"] for r in report.runs[0].results)
        assert paths == [
            f"deploy/cdk-constructs/{BUNDLED_KEY}",
            f"deploy/cdk/{BUNDLED_KEY}",
            f"deploy/cdk/{TOP_KEY}",
        ]

    def test_version_comes_from_the_lockfile(self, npm_scanner, tmp_path):
        cdk = tmp_path / "deploy/cdk"
        write_lockfile(cdk, bundled_and_top_level("1.1.18"))
        report = run_npm_scan(
            npm_scanner, tmp_path, {cdk: audit_json([BUNDLED_KEY, TOP_KEY])}
        )
        by_path = {props(r)["package_path"]: props(r) for r in report.runs[0].results}
        bundled = by_path[f"deploy/cdk/{BUNDLED_KEY}"]
        top = by_path[f"deploy/cdk/{TOP_KEY}"]
        assert bundled["package_name"] == "brace-expansion"
        assert bundled["package_version"] == "5.0.9"
        assert top["package_version"] == "1.1.18"
        # installed_version used to repeat the advisory range.
        assert bundled["installed_version"] == "5.0.9"
        assert bundled["vulnerable_versions"] == "<=1.1.20 || 4.0.0 - 5.0.11"

    def test_uri_is_unchanged(self, npm_scanner, tmp_path):
        """Existing npm-audit suppressions match on this URI; it must not move."""
        cdk = tmp_path / "deploy/cdk"
        write_lockfile(cdk, bundled_and_top_level("1.1.18"))
        report = run_npm_scan(npm_scanner, tmp_path, {cdk: audit_json([BUNDLED_KEY])})
        uri = (
            report.runs[0]
            .results[0]
            .locations[0]
            .physicalLocation.root.artifactLocation.uri
        )
        assert uri == "node_modules/aws-cdk-lib/brace-expansion/package.json"

    def test_node_missing_from_lockfile_gets_no_version(self, npm_scanner, tmp_path):
        cdk = tmp_path / "deploy/cdk"
        write_lockfile(cdk, {})
        report = run_npm_scan(npm_scanner, tmp_path, {cdk: audit_json([TOP_KEY])})
        p = props(report.runs[0].results[0])
        assert p["package_path"] == f"deploy/cdk/{TOP_KEY}"
        assert "package_version" not in p


# ------------------------------------------------------------------- end to end


class TestSuppressionEndToEnd:
    """Through apply_suppressions_to_sarif, the real suppression entry point."""

    def _context(self, test_source_dir, test_output_dir, *suppressions):
        config = AshConfig(
            project_name="p",
            global_settings={"suppressions": list(suppressions)},
        )
        return PluginContext(
            source_dir=test_source_dir, output_dir=test_output_dir, config=config
        )

    def _two_copies(self) -> SarifReport:
        """Two results identical on rule, path and region; only properties differ."""
        results = []
        for version, key in (("5.0.9", BUNDLED_KEY), ("1.1.18", TOP_KEY)):
            r = grype_result(
                "GHSA-6j4f-fj2g-mc7p",
                "brace-expansion",
                version,
                "deploy/cdk/package-lock.json",
            )
            r.locations[
                0
            ].physicalLocation.root.artifactLocation.uri = (
                "deploy/cdk/package-lock.json"
            )
            r.properties = {
                "package_name": "brace-expansion",
                "package_version": version,
                "package_path": f"deploy/cdk/{key}",
            }
            results.append(r)
        return grype_report(*results)

    def test_package_scoped_entry_suppresses_only_the_bundled_copy(
        self, test_source_dir, test_output_dir
    ):
        supp = AshSuppression(
            rule_id="GHSA-6j4f-fj2g-mc7p*",
            path="deploy/cdk/package-lock.json",
            package_name="brace-expansion",
            package_version="5.0.9",
            package_path="**/node_modules/aws-cdk-lib/node_modules/brace-expansion",
            reason="bundled",
        )
        used: set = set()
        out = apply_suppressions_to_sarif(
            self._two_copies(),
            self._context(test_source_dir, test_output_dir, supp),
            used,
        )
        bundled, top = out.runs[0].results
        assert bundled.suppressions and len(bundled.suppressions) == 1
        assert not top.suppressions
        assert used == {supp.id}

    def test_legacy_entry_still_suppresses_both(self, test_source_dir, test_output_dir):
        supp = AshSuppression(
            rule_id="GHSA-6j4f-fj2g-mc7p*",
            path="deploy/cdk/package-lock.json",
            reason="legacy",
        )
        out = apply_suppressions_to_sarif(
            self._two_copies(), self._context(test_source_dir, test_output_dir, supp)
        )
        assert all(r.suppressions for r in out.runs[0].results)

    def test_expired_package_scoped_entry_suppresses_nothing(
        self, test_source_dir, test_output_dir
    ):
        supp = AshSuppression(
            rule_id="GHSA-6j4f-fj2g-mc7p*",
            path="deploy/cdk/package-lock.json",
            package_path="**/node_modules/aws-cdk-lib/node_modules/brace-expansion",
            reason="expired",
            expiration="2020-01-01",
        )
        out = apply_suppressions_to_sarif(
            self._two_copies(), self._context(test_source_dir, test_output_dir, supp)
        )
        assert not any(r.suppressions for r in out.runs[0].results)
