# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppressed root advisory must reach the transitive findings it causes.

npm audit reports an advisory once on the vulnerable package, then once more on
every package whose ``via`` chain leads to it. The npm-audit converter turns
each of those into an ``npm-audit-transitive-<package>`` result with no advisory
id. Before this change, a suppression on the advisory left every one of them
failing the scan: braces GHSA-vfj7-8cjw-p6xm came with 32 such findings across
two lockfiles, and each needed its own suppression entry.

The converter now records, on every transitive result, the root advisories its
chain resolves to and which copy of the root package each one is about
(``root_advisories``). apply_suppressions_to_sarif treats a transitive result
as suppressed when every one of those root findings is present in the report
and suppressed. A root it cannot find, or one that is not suppressed, leaves
the transitive result visible.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

BRACES = "GHSA-vfj7-8cjw-p6xm"
PICOMATCH = "GHSA-0000-pico-0000"


def write_lockfile(project: Path, entries: dict) -> Path:
    project.mkdir(parents=True, exist_ok=True)
    (project / "package.json").write_text('{"name": "p", "version": "1.0.0"}')
    packages = {"": {"name": "p", "version": "1.0.0"}}
    packages.update(entries)
    lock = {"name": "p", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}
    path = project / "package-lock.json"
    path.write_text(json.dumps(lock, indent=2) + "\n")
    return path


LOCK_ENTRIES = {
    "node_modules/braces": {"version": "3.0.3"},
    "node_modules/picomatch": {"version": "2.3.1"},
    "node_modules/micromatch": {"version": "4.0.8"},
    "node_modules/jest": {"version": "29.7.0"},
}


def advisory(name: str, ghsa: str) -> dict:
    return {
        "name": name,
        "severity": "high",
        "via": [
            {
                "source": 1,
                "name": name,
                "title": f"{name} advisory",
                "url": f"https://github.com/advisories/{ghsa}",
                "severity": "high",
                "range": "*",
            }
        ],
        "range": "*",
        "nodes": [f"node_modules/{name}"],
        "fixAvailable": False,
    }


def transitive(name: str, via: list) -> dict:
    return {
        "name": name,
        "severity": "high",
        "via": via,
        "range": "*",
        "nodes": [f"node_modules/{name}"],
        "fixAvailable": False,
    }


def audit_json(micromatch_via=("braces",)) -> str:
    vulns = {
        "braces": advisory("braces", BRACES),
        "micromatch": transitive("micromatch", list(micromatch_via)),
        "jest": transitive("jest", ["micromatch"]),
    }
    if "picomatch" in micromatch_via:
        vulns["picomatch"] = advisory("picomatch", PICOMATCH)
    return json.dumps({"vulnerabilities": vulns})


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


def props(result) -> dict:
    return result.properties.model_dump(exclude_none=True) if result.properties else {}


def by_key(report) -> dict:
    """{(rule id, package_path): result} over every run."""
    return {
        (r.ruleId, props(r).get("package_path")): r
        for run in report.runs
        for r in run.results or []
    }


def suppress_root(name: str, ghsa: str, lockdir: str) -> AshSuppression:
    return AshSuppression(
        rule_id=ghsa,
        path=f"node_modules/{name}/package.json",
        package_name=name,
        package_path=f"{lockdir}/node_modules/{name}",
        reason="root",
    )


def apply(report, root: Path, output: Path, *suppressions, ignore=False):
    config = AshConfig(
        project_name="p", global_settings={"suppressions": list(suppressions)}
    )
    context = PluginContext(
        source_dir=root,
        output_dir=output,
        config=config,
        ignore_suppressions=ignore,
    )
    return apply_suppressions_to_sarif(report, context)


@pytest.fixture
def cdk(tmp_path):
    project = tmp_path / "deploy/cdk"
    write_lockfile(project, LOCK_ENTRIES)
    return project


class TestScannerRecordsRoots:
    def test_multi_level_chain_resolves_to_the_root_copy(
        self, npm_scanner, tmp_path, cdk
    ):
        report = run_npm_scan(npm_scanner, tmp_path, {cdk: audit_json()})
        results = by_key(report)
        expected = [
            {
                "rule_id": BRACES,
                "package_path": "deploy/cdk/node_modules/braces",
                "uri": "node_modules/braces/package.json",
            }
        ]
        jest = results[("npm-audit-transitive-jest", "deploy/cdk/node_modules/jest")]
        micromatch = results[
            ("npm-audit-transitive-micromatch", "deploy/cdk/node_modules/micromatch")
        ]
        assert props(jest)["root_advisories"] == expected
        assert props(micromatch)["root_advisories"] == expected

    def test_rule_ids_are_unchanged(self, npm_scanner, tmp_path, cdk):
        report = run_npm_scan(npm_scanner, tmp_path, {cdk: audit_json()})
        assert sorted(rule for rule, _ in by_key(report)) == [
            BRACES,
            "npm-audit-transitive-jest",
            "npm-audit-transitive-micromatch",
        ]

    def test_direct_finding_carries_no_roots(self, npm_scanner, tmp_path, cdk):
        report = run_npm_scan(npm_scanner, tmp_path, {cdk: audit_json()})
        direct = by_key(report)[(BRACES, "deploy/cdk/node_modules/braces")]
        assert "root_advisories" not in props(direct)

    def test_two_roots_are_both_recorded(self, npm_scanner, tmp_path, cdk):
        report = run_npm_scan(
            npm_scanner, tmp_path, {cdk: audit_json(("braces", "picomatch"))}
        )
        jest = by_key(report)[
            ("npm-audit-transitive-jest", "deploy/cdk/node_modules/jest")
        ]
        # Sorted by rule id, so the property is stable across runs.
        assert [r["rule_id"] for r in props(jest)["root_advisories"]] == [
            PICOMATCH,
            BRACES,
        ]

    def test_cycle_without_a_root_records_nothing(self, npm_scanner, tmp_path, cdk):
        audit = json.dumps(
            {
                "vulnerabilities": {
                    "micromatch": transitive("micromatch", ["jest"]),
                    "jest": transitive("jest", ["micromatch"]),
                }
            }
        )
        report = run_npm_scan(npm_scanner, tmp_path, {cdk: audit})
        assert all("root_advisories" not in props(r) for r in by_key(report).values())


class TestRootSuppressionReachesTransitive:
    def test_suppressed_root_suppresses_its_transitive_findings(
        self, npm_scanner, tmp_path, cdk, test_output_dir
    ):
        report = run_npm_scan(npm_scanner, tmp_path, {cdk: audit_json()})
        out = apply(
            report,
            tmp_path,
            test_output_dir,
            suppress_root("braces", BRACES, "deploy/cdk"),
        )
        results = by_key(out)
        assert all(r.suppressions for r in results.values())
        jest = results[("npm-audit-transitive-jest", "deploy/cdk/node_modules/jest")]
        justification = jest.suppressions[0].justification
        assert BRACES in justification
        assert "deploy/cdk/node_modules/braces" in justification

    def test_second_unsuppressed_root_keeps_transitive_visible(
        self, npm_scanner, tmp_path, cdk, test_output_dir
    ):
        report = run_npm_scan(
            npm_scanner, tmp_path, {cdk: audit_json(("braces", "picomatch"))}
        )
        out = apply(
            report,
            tmp_path,
            test_output_dir,
            suppress_root("braces", BRACES, "deploy/cdk"),
        )
        results = by_key(out)
        assert results[(BRACES, "deploy/cdk/node_modules/braces")].suppressions
        assert not results[
            (PICOMATCH, "deploy/cdk/node_modules/picomatch")
        ].suppressions
        for name in ("micromatch", "jest"):
            key = (f"npm-audit-transitive-{name}", f"deploy/cdk/node_modules/{name}")
            assert not results[key].suppressions

    def test_every_root_suppressed_suppresses_transitive(
        self, npm_scanner, tmp_path, cdk, test_output_dir
    ):
        report = run_npm_scan(
            npm_scanner, tmp_path, {cdk: audit_json(("braces", "picomatch"))}
        )
        out = apply(
            report,
            tmp_path,
            test_output_dir,
            suppress_root("braces", BRACES, "deploy/cdk"),
            suppress_root("picomatch", PICOMATCH, "deploy/cdk"),
        )
        assert all(r.suppressions for r in by_key(out).values())

    def test_no_root_suppressed_changes_nothing(
        self, npm_scanner, tmp_path, cdk, test_output_dir
    ):
        report = run_npm_scan(npm_scanner, tmp_path, {cdk: audit_json()})
        before = report.model_dump_json()
        out = apply(report, tmp_path, test_output_dir)
        assert not any(r.suppressions for r in by_key(out).values())
        assert out.model_dump_json() == before

    def test_root_suppressed_in_one_lockfile_only(
        self, npm_scanner, tmp_path, cdk, test_output_dir
    ):
        constructs = tmp_path / "deploy/cdk-constructs"
        write_lockfile(constructs, LOCK_ENTRIES)
        report = run_npm_scan(
            npm_scanner, tmp_path, {cdk: audit_json(), constructs: audit_json()}
        )
        out = apply(
            report,
            tmp_path,
            test_output_dir,
            suppress_root("braces", BRACES, "deploy/cdk"),
        )
        for (rule, path), result in by_key(out).items():
            if path.startswith("deploy/cdk/"):
                assert result.suppressions, (rule, path)
            else:
                assert not result.suppressions, (rule, path)

    def test_root_with_one_unsuppressed_copy_keeps_transitive_visible(
        self, npm_scanner, tmp_path, test_output_dir
    ):
        project = tmp_path / "deploy/cdk"
        write_lockfile(
            project,
            {
                **LOCK_ENTRIES,
                "node_modules/jest/node_modules/braces": {"version": "3.0.2"},
            },
        )
        vulns = json.loads(audit_json())["vulnerabilities"]
        vulns["braces"]["nodes"].append("node_modules/jest/node_modules/braces")
        report = run_npm_scan(
            npm_scanner, tmp_path, {project: json.dumps({"vulnerabilities": vulns})}
        )
        out = apply(
            report,
            tmp_path,
            test_output_dir,
            suppress_root("braces", BRACES, "deploy/cdk"),
        )
        results = by_key(out)
        assert not results[
            ("npm-audit-transitive-jest", "deploy/cdk/node_modules/jest")
        ].suppressions

    def test_root_missing_from_the_report_keeps_transitive_visible(
        self, npm_scanner, tmp_path, cdk, test_output_dir
    ):
        """A root nobody reported cannot vouch for the transitive finding."""
        report = run_npm_scan(npm_scanner, tmp_path, {cdk: audit_json()})
        for run in report.runs:
            run.results = [r for r in run.results if r.ruleId != BRACES]
        out = apply(
            report,
            tmp_path,
            test_output_dir,
            suppress_root("braces", BRACES, "deploy/cdk"),
        )
        results = by_key(out)
        assert results and not any(r.suppressions for r in results.values())

    def test_ignore_suppressions_leaves_transitive_visible(
        self, npm_scanner, tmp_path, cdk, test_output_dir
    ):
        report = run_npm_scan(npm_scanner, tmp_path, {cdk: audit_json()})
        out = apply(
            report,
            tmp_path,
            test_output_dir,
            suppress_root("braces", BRACES, "deploy/cdk"),
            ignore=True,
        )
        assert not any(r.suppressions for r in by_key(out).values())

    def test_ignore_suppressions_with_a_pre_suppressed_root(
        self, npm_scanner, tmp_path, cdk, test_output_dir
    ):
        """A root already suppressed in the incoming SARIF (a re-merged report)
        must not propagate when --ignore-suppressions is set."""
        from automated_security_helper.schemas.sarif_schema_model import (
            Kind1,
            Suppression,
        )

        report = run_npm_scan(npm_scanner, tmp_path, {cdk: audit_json()})
        direct = by_key(report)[(BRACES, "deploy/cdk/node_modules/braces")]
        direct.suppressions = [Suppression(kind=Kind1.inSource, justification="x")]
        out = apply(report, tmp_path, test_output_dir, ignore=True)
        transitive = [r for k, r in by_key(out).items() if k[0] != BRACES]
        assert transitive and not any(r.suppressions for r in transitive)

    def test_does_not_count_as_a_used_suppression(
        self, npm_scanner, tmp_path, cdk, test_output_dir
    ):
        report = run_npm_scan(npm_scanner, tmp_path, {cdk: audit_json()})
        supp = suppress_root("braces", BRACES, "deploy/cdk")
        config = AshConfig(project_name="p", global_settings={"suppressions": [supp]})
        context = PluginContext(
            source_dir=tmp_path, output_dir=test_output_dir, config=config
        )
        used: set = set()
        apply_suppressions_to_sarif(report, context, used)
        assert used == {supp.id}
