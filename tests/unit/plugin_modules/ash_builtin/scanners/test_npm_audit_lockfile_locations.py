# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""npm-audit locates each advisory at the lockfile it came from.

npm audit, yarn audit and pnpm audit name no file. The scanner used to write
``node_modules/<package>/package.json`` for every advisory, a path that usually
is not in the checkout and that matches the most common ignore path of all,
``**/node_modules/**``. With that ignore in ``global_settings.ignore_paths`` every
npm-audit finding was dropped and the scan read 0 findings, PASSED, while the
package manager listed advisories.

An advisory is now located at the lockfile the audit ran against: it exists in
the checkout, no ``node_modules`` glob reaches it, and it is where the fix lands.
Findings of one lockfile share that location, so what keeps them apart is the
package identity in the result's properties and in ``partialFingerprints``.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

pytestmark = pytest.mark.unit

BRACES = "GHSA-vfj7-8cjw-p6xm"
PICOMATCH = "GHSA-0000-pico-0000"

#: The partialFingerprints key a lockfile-located result carries, as a literal:
#: importing the scanner's constant failed collection on a tree without the
#: lockfile-location change, so the whole module errored instead of these
#: assertions failing. ``test_fingerprint_key_matches_the_scanner_constant``
#: pins the literal against the source constant.
IDENTITY_FINGERPRINT_KEY = "ashNpmAuditFinding/v1"


def identity_fingerprint(result):
    """The result's identity fingerprint, or None when it carries none, which
    is what a tree without the lockfile-location change answers: the
    assertions over these values then fail as assertions."""
    return (result.partialFingerprints or {}).get(IDENTITY_FINGERPRINT_KEY)


def test_fingerprint_key_matches_the_scanner_constant():
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        npm_audit_scanner,
    )

    assert npm_audit_scanner.IDENTITY_FINGERPRINT_KEY == IDENTITY_FINGERPRINT_KEY


def write_npm_lockfile(project: Path, entries: dict) -> Path:
    project.mkdir(parents=True, exist_ok=True)
    (project / "package.json").write_text('{"name": "p", "version": "1.0.0"}')
    packages = {"": {"name": "p", "version": "1.0.0"}}
    packages.update(entries)
    lock = {"name": "p", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}
    path = project / "package-lock.json"
    path.write_text(json.dumps(lock, indent=2) + "\n")
    return path


def line_of(lockfile: Path, key: str) -> int:
    """The 1-based line the lockfile's ``packages`` key sits on."""
    needle = f'"{key}": {{'
    for number, text in enumerate(lockfile.read_text().split("\n"), start=1):
        if text.strip().startswith(needle):
            return number
    raise AssertionError(f"{key} is not a key of {lockfile}")


def vulnerability(name: str, ghsa: str, nodes: list[str]) -> dict:
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
        "nodes": nodes,
        "fixAvailable": False,
    }


def npm_report(*vulnerabilities: dict) -> dict:
    return {"vulnerabilities": {v["name"]: v for v in vulnerabilities}}


def pnpm_report(*advisories: tuple[int, str, str, str, list[str]]) -> dict:
    """An npm v1 report, as ``pnpm audit --json`` writes it.

    Each advisory is (id, package, ghsa, installed version, dependency paths).
    """
    return {
        "advisories": {
            str(number): {
                "id": number,
                "module_name": package,
                "title": f"{package} advisory",
                "url": f"https://github.com/advisories/{ghsa}",
                "severity": "high",
                "vulnerable_versions": "<9.0.0",
                "patched_versions": ">=9.0.0",
                "findings": [{"version": version, "paths": paths}],
            }
            for number, package, ghsa, version, paths in advisories
        },
        "metadata": {"vulnerabilities": {"high": len(advisories)}},
    }


@pytest.fixture
def scanner(test_plugin_context):
    scanner = NpmAuditScanner(
        context=test_plugin_context, config=NpmAuditScannerConfig()
    )
    scanner.exit_code = 1
    scanner.dependencies_satisfied = True
    scanner.tool_version = "1.0.0"
    return scanner


def uri_of(result) -> str:
    return result.locations[0].physicalLocation.root.artifactLocation.uri


def region_of(result):
    return result.locations[0].physicalLocation.root.region


def props(result) -> dict:
    return result.properties.model_dump(exclude_none=True) if result.properties else {}


def results_of(report) -> list:
    return [r for run in report.runs for r in run.results or []]


def apply(report, root: Path, output: Path, *, ignore_paths=(), suppressions=()):
    config = AshConfig(
        project_name="p",
        global_settings={
            "ignore_paths": [
                {"path": p, "reason": "third-party code"} for p in ignore_paths
            ],
            "suppressions": list(suppressions),
        },
    )
    context = PluginContext(source_dir=root, output_dir=output, config=config)
    return apply_suppressions_to_sarif(report, context)


class TestAdvisoryIsLocatedAtItsLockfile:
    def test_a_node_modules_ignore_path_no_longer_drops_the_finding(
        self, scanner, tmp_path, test_output_dir
    ):
        """The issue's repro: a planted advisory plus ``**/node_modules/**``.

        Red before the change: the result sat at node_modules/braces/package.json,
        the ignore path matched it, and the report held no result at all.
        """
        lock = write_npm_lockfile(
            tmp_path / "deploy/cdk", {"node_modules/braces": {"version": "3.0.3"}}
        )
        report = scanner._convert_npm_audit_to_sarif(
            npm_report(vulnerability("braces", BRACES, ["node_modules/braces"])),
            tmp_path,
            lock_file=lock,
        )
        assert len(results_of(report)) == 1

        kept = apply(
            report, tmp_path, test_output_dir, ignore_paths=["**/node_modules/**"]
        )

        (result,) = results_of(kept)
        assert result.ruleId == BRACES
        assert uri_of(result) == "deploy/cdk/package-lock.json"
        assert not result.suppressions

    def test_a_pnpm_advisory_survives_the_same_ignore_path(
        self, scanner, tmp_path, test_output_dir
    ):
        (tmp_path / "app").mkdir()
        lock = tmp_path / "app/pnpm-lock.yaml"
        lock.write_text("lockfileVersion: '9.0'\n")
        report = scanner._convert_npm_audit_to_sarif(
            pnpm_report(
                (1, "minimist", "GHSA-xvch-5gv4-984h", "1.2.5", [".>minimist"])
            ),
            tmp_path,
            lock_file=lock,
        )

        kept = apply(
            report, tmp_path, test_output_dir, ignore_paths=["**/node_modules/**"]
        )

        (result,) = results_of(kept)
        assert uri_of(result) == "app/pnpm-lock.yaml"
        assert region_of(result) is None, "no line is made up for a pnpm lockfile"
        assert props(result)["package_name"] == "minimist"

    def test_an_ignore_path_on_the_lockfile_still_drops_it(
        self, scanner, tmp_path, test_output_dir
    ):
        """Control: the ignore path does its job where the user aimed it."""
        lock = write_npm_lockfile(
            tmp_path, {"node_modules/braces": {"version": "3.0.3"}}
        )
        report = scanner._convert_npm_audit_to_sarif(
            npm_report(vulnerability("braces", BRACES, ["node_modules/braces"])),
            tmp_path,
            lock_file=lock,
        )

        kept = apply(
            report, tmp_path, test_output_dir, ignore_paths=["**/package-lock.json"]
        )

        assert results_of(kept) == []

    def test_the_region_is_the_packages_lockfile_entry(self, scanner, tmp_path):
        lock = write_npm_lockfile(
            tmp_path,
            {
                "node_modules/braces": {"version": "3.0.3"},
                "node_modules/picomatch": {"version": "2.3.1"},
            },
        )
        report = scanner._convert_npm_audit_to_sarif(
            npm_report(
                vulnerability("braces", BRACES, ["node_modules/braces"]),
                vulnerability("picomatch", PICOMATCH, ["node_modules/picomatch"]),
            ),
            tmp_path,
            lock_file=lock,
        )

        lines = {r.ruleId: region_of(r).startLine for r in results_of(report)}

        assert lines == {
            BRACES: line_of(lock, "node_modules/braces"),
            PICOMATCH: line_of(lock, "node_modules/picomatch"),
        }
        assert lines[BRACES] != lines[PICOMATCH]

    def test_a_node_with_no_lockfile_entry_has_no_region(self, scanner, tmp_path):
        lock = write_npm_lockfile(
            tmp_path, {"node_modules/other": {"version": "1.0.0"}}
        )
        report = scanner._convert_npm_audit_to_sarif(
            npm_report(vulnerability("braces", BRACES, ["node_modules/braces"])),
            tmp_path,
            lock_file=lock,
        )

        (result,) = results_of(report)
        assert uri_of(result) == "package-lock.json"
        assert region_of(result) is None

    def test_a_report_with_no_lockfile_keeps_the_install_location(
        self, scanner, tmp_path
    ):
        report = scanner._convert_npm_audit_to_sarif(
            npm_report(vulnerability("braces", BRACES, ["node_modules/braces"])),
            tmp_path,
        )

        (result,) = results_of(report)
        assert uri_of(result) == "node_modules/braces/package.json"
        assert not result.partialFingerprints


class TestFindingsOfOneLockfileStayDistinct:
    def test_two_advisories_in_one_lockfile_are_two_findings(self, scanner, tmp_path):
        lock = write_npm_lockfile(
            tmp_path,
            {
                "node_modules/braces": {"version": "3.0.3"},
                "node_modules/picomatch": {"version": "2.3.1"},
            },
        )
        report = scanner._convert_npm_audit_to_sarif(
            npm_report(
                vulnerability("braces", BRACES, ["node_modules/braces"]),
                vulnerability("picomatch", PICOMATCH, ["node_modules/picomatch"]),
            ),
            tmp_path,
            lock_file=lock,
        )

        by_rule = {r.ruleId: r for r in results_of(report)}
        braces, picomatch = by_rule[BRACES], by_rule[PICOMATCH]
        assert {uri_of(braces), uri_of(picomatch)} == {"package-lock.json"}
        prints = {r.ruleId: identity_fingerprint(r) for r in (braces, picomatch)}
        assert prints[BRACES] is not None
        assert prints[BRACES] != prints[PICOMATCH]
        assert props(braces)["package_name"] == "braces"
        assert props(braces)["package_version"] == "3.0.3"
        assert props(picomatch)["package_name"] == "picomatch"
        assert props(picomatch)["package_version"] == "2.3.1"

    def test_two_copies_of_one_package_are_two_findings(self, scanner, tmp_path):
        lock = write_npm_lockfile(
            tmp_path,
            {
                "node_modules/braces": {"version": "3.0.3"},
                "node_modules/a": {"version": "1.0.0"},
                "node_modules/a/node_modules/braces": {"version": "2.3.2"},
            },
        )
        report = scanner._convert_npm_audit_to_sarif(
            npm_report(
                vulnerability(
                    "braces",
                    BRACES,
                    ["node_modules/braces", "node_modules/a/node_modules/braces"],
                )
            ),
            tmp_path,
            lock_file=lock,
        )

        results = results_of(report)
        assert len(results) == 2
        assert {props(r)["package_path"] for r in results} == {
            "node_modules/braces",
            "node_modules/a/node_modules/braces",
        }
        prints = {identity_fingerprint(r) for r in results}
        assert None not in prints and len(prints) == 2
        assert len({region_of(r).startLine for r in results}) == 2

    def test_two_pnpm_advisories_in_one_lockfile_are_two_findings(
        self, scanner, tmp_path
    ):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text("lockfileVersion: '9.0'\n")
        report = scanner._convert_npm_audit_to_sarif(
            pnpm_report(
                (1, "minimist", "GHSA-xvch-5gv4-984h", "1.2.5", [".>minimist"]),
                (2, "braces", BRACES, "3.0.3", [".>micromatch>braces"]),
            ),
            tmp_path,
            lock_file=lock,
        )

        by_package = {props(r)["package_name"]: r for r in results_of(report)}
        minimist, braces = by_package["minimist"], by_package["braces"]
        assert uri_of(minimist) == uri_of(braces) == "pnpm-lock.yaml"
        assert identity_fingerprint(minimist) is not None
        assert identity_fingerprint(minimist) != identity_fingerprint(braces)
        assert props(braces)["package_version"] == "3.0.3"
        assert props(braces)["dependency_paths"] == [".>micromatch>braces"]

    def test_the_fingerprint_is_stable_across_runs(self, scanner, tmp_path):
        lock = write_npm_lockfile(
            tmp_path, {"node_modules/braces": {"version": "3.0.3"}}
        )
        audit = npm_report(vulnerability("braces", BRACES, ["node_modules/braces"]))

        first = scanner._convert_npm_audit_to_sarif(audit, tmp_path, lock_file=lock)
        second = scanner._convert_npm_audit_to_sarif(audit, tmp_path, lock_file=lock)

        (a,), (b,) = results_of(first), results_of(second)
        assert a.partialFingerprints == b.partialFingerprints

    def test_a_transitive_finding_is_located_and_told_apart_too(
        self, scanner, tmp_path
    ):
        lock = write_npm_lockfile(
            tmp_path,
            {
                "node_modules/braces": {"version": "3.0.3"},
                "node_modules/micromatch": {"version": "4.0.8"},
            },
        )
        micromatch = {
            "name": "micromatch",
            "severity": "high",
            "via": ["braces"],
            "range": "*",
            "nodes": ["node_modules/micromatch"],
            "fixAvailable": False,
        }
        report = scanner._convert_npm_audit_to_sarif(
            npm_report(
                vulnerability("braces", BRACES, ["node_modules/braces"]), micromatch
            ),
            tmp_path,
            lock_file=lock,
        )

        by_rule = {r.ruleId: r for r in results_of(report)}
        transitive = by_rule["npm-audit-transitive-micromatch"]
        assert uri_of(transitive) == "package-lock.json"
        assert region_of(transitive).startLine == line_of(
            lock, "node_modules/micromatch"
        )
        assert identity_fingerprint(transitive) is not None
        assert identity_fingerprint(transitive) != identity_fingerprint(by_rule[BRACES])
        (root,) = props(transitive)["root_advisories"]
        assert root["uri"] == uri_of(by_rule[BRACES])


class TestAttributionAcrossLockfiles:
    def test_an_advisory_lands_on_its_own_lockfile(self, scanner, tmp_path):
        lock_a = write_npm_lockfile(
            tmp_path / "svc-a", {"node_modules/braces": {"version": "3.0.3"}}
        )
        lock_b = write_npm_lockfile(
            tmp_path / "svc-b", {"node_modules/picomatch": {"version": "2.3.1"}}
        )
        audit_a = npm_report(vulnerability("braces", BRACES, ["node_modules/braces"]))
        audit_b = npm_report(
            vulnerability("picomatch", PICOMATCH, ["node_modules/picomatch"])
        )

        report = scanner._convert_per_lockfile(
            [(lock_a, audit_a), (lock_b, audit_b)],
            {"metadata": {"vulnerabilities": {}}},
            tmp_path,
        )

        located = {r.ruleId: uri_of(r) for r in results_of(report)}
        assert located == {
            BRACES: "svc-a/package-lock.json",
            PICOMATCH: "svc-b/package-lock.json",
        }

    def test_one_advisory_in_two_lockfiles_is_a_finding_in_each(
        self, scanner, tmp_path
    ):
        entries = {"node_modules/braces": {"version": "3.0.3"}}
        lock_a = write_npm_lockfile(tmp_path / "svc-a", entries)
        lock_b = write_npm_lockfile(tmp_path / "svc-b", entries)
        audit = npm_report(vulnerability("braces", BRACES, ["node_modules/braces"]))

        report = scanner._convert_per_lockfile(
            [(lock_a, audit), (lock_b, audit)],
            {"metadata": {"vulnerabilities": {}}},
            tmp_path,
        )

        results = results_of(report)
        assert sorted(uri_of(r) for r in results) == [
            "svc-a/package-lock.json",
            "svc-b/package-lock.json",
        ]


class TestSuppressionsAreRekeyedToTheLockfile:
    def test_a_suppression_at_the_lockfile_path_matches(
        self, scanner, tmp_path, test_output_dir
    ):
        lock = write_npm_lockfile(
            tmp_path / "deploy/cdk", {"node_modules/braces": {"version": "3.0.3"}}
        )
        report = scanner._convert_npm_audit_to_sarif(
            npm_report(vulnerability("braces", BRACES, ["node_modules/braces"])),
            tmp_path,
            lock_file=lock,
        )
        rekeyed = AshSuppression(
            rule_id=BRACES,
            path="deploy/cdk/package-lock.json",
            package_name="braces",
            package_version="3.0.3",
            reason="accepted",
        )

        out = apply(report, tmp_path, test_output_dir, suppressions=[rekeyed])

        (result,) = results_of(out)
        assert result.suppressions

    def test_a_suppression_at_the_old_install_path_no_longer_matches(
        self, scanner, tmp_path, test_output_dir
    ):
        lock = write_npm_lockfile(
            tmp_path / "deploy/cdk", {"node_modules/braces": {"version": "3.0.3"}}
        )
        report = scanner._convert_npm_audit_to_sarif(
            npm_report(vulnerability("braces", BRACES, ["node_modules/braces"])),
            tmp_path,
            lock_file=lock,
        )
        old = AshSuppression(
            rule_id=BRACES,
            path="node_modules/braces/package.json",
            package_name="braces",
            reason="accepted",
        )

        out = apply(report, tmp_path, test_output_dir, suppressions=[old])

        (result,) = results_of(out)
        assert not result.suppressions
