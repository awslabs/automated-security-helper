# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""trivy-repo must carry package identity into SARIF, one result per copy.

trivy dedupes packages by name and version before matching, so two lockfile
entries with the same name and version -- a top-level ``brace-expansion``
5.0.9 and the 5.0.9 bundled inside ``aws-cdk-lib`` -- become ONE result with
TWO locations. A suppression either covers a result or it does not, so no
suppression could cover one copy without the other.

trivy's locations are the line ranges of each copy's entry in the lockfile.
The scanner now splits such a result into one result per location and, for an
npm lockfile, resolves each location's line to its ``packages`` key, giving
``package_path``. ``package_name`` and ``package_version`` come from the
``Package:`` and ``Installed Version:`` lines of trivy's message.
"""

import json
from pathlib import Path

from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

BUNDLED_KEY = "node_modules/aws-cdk-lib/node_modules/brace-expansion"
TOP_KEY = "node_modules/brace-expansion"


def write_lockfile(project: Path, entries: dict) -> tuple[Path, dict]:
    project.mkdir(parents=True, exist_ok=True)
    packages = {"": {"name": "p", "version": "1.0.0"}}
    packages.update(entries)
    lock = {"name": "p", "lockfileVersion": 3, "packages": packages}
    path = project / "package-lock.json"
    text = json.dumps(lock, indent=2) + "\n"
    path.write_text(text)
    lines = {}
    for number, line in enumerate(text.splitlines(), start=1):
        for key in entries:
            if line.strip().startswith(json.dumps(key) + ":"):
                lines[key] = number
    return path, lines


def trivy_result(rule: str, uri: str, version: str, starts: list) -> dict:
    """A result shaped the way trivy's SARIF writer emits a vulnerability."""
    return {
        "ruleId": rule,
        "level": "error",
        "message": {
            "text": (
                f"Package: brace-expansion\nInstalled Version: {version}\n"
                f"Vulnerability {rule}\nSeverity: HIGH\nFixed Version: 5.0.10\n"
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "ROOTPATH"},
                    "region": {
                        "startLine": start,
                        "startColumn": 1,
                        "endLine": start + 10,
                        "endColumn": 1,
                    },
                },
                "message": {"text": f"{uri}: brace-expansion@{version}"},
            }
            for start in starts
        ],
    }


def report(*results: dict) -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": list(results)}],
        }
    )


def props(result) -> dict:
    return result.properties.model_dump(exclude_none=True) if result.properties else {}


def scanner(mock_plugin_context) -> TrivyRepoScanner:
    return TrivyRepoScanner(context=mock_plugin_context)


def test_collision_is_split_into_one_result_per_copy(mock_plugin_context, tmp_path):
    root = tmp_path / "src"
    _, lines = write_lockfile(
        root / "deploy/cc",
        {
            "node_modules/aws-cdk-lib": {"version": "2.272.0"},
            BUNDLED_KEY: {"version": "5.0.9", "inBundle": True},
            TOP_KEY: {"version": "5.0.9"},
        },
    )
    uri = "deploy/cc/package-lock.json"
    sarif = report(
        trivy_result(
            "CVE-2026-102276", uri, "5.0.9", [lines[BUNDLED_KEY], lines[TOP_KEY]]
        )
    )
    out = scanner(mock_plugin_context)._attach_package_identity(sarif, root)
    results = out.runs[0].results
    assert len(results) == 2
    got = sorted(
        (
            props(r)["package_path"],
            r.locations[0].physicalLocation.root.region.startLine,
        )
        for r in results
    )
    assert got == sorted(
        [
            (f"deploy/cc/{BUNDLED_KEY}", lines[BUNDLED_KEY]),
            (f"deploy/cc/{TOP_KEY}", lines[TOP_KEY]),
        ]
    )
    for r in results:
        assert r.ruleId == "CVE-2026-102276"
        assert len(r.locations) == 1
        assert props(r)["package_name"] == "brace-expansion"
        assert props(r)["package_version"] == "5.0.9"


def test_single_location_gets_its_path(mock_plugin_context, tmp_path):
    root = tmp_path / "src"
    _, lines = write_lockfile(
        root / "deploy/cdk",
        {BUNDLED_KEY: {"version": "5.0.9"}, TOP_KEY: {"version": "1.1.18"}},
    )
    uri = "deploy/cdk/package-lock.json"
    sarif = report(
        trivy_result("CVE-2026-102276", uri, "1.1.18", [lines[TOP_KEY]]),
        trivy_result("CVE-2026-102276", uri, "5.0.9", [lines[BUNDLED_KEY]]),
    )
    out = scanner(mock_plugin_context)._attach_package_identity(sarif, root)
    top, bundled = out.runs[0].results
    assert props(top)["package_path"] == f"deploy/cdk/{TOP_KEY}"
    assert props(top)["package_version"] == "1.1.18"
    assert props(bundled)["package_path"] == f"deploy/cdk/{BUNDLED_KEY}"


def test_line_that_is_no_lockfile_key_gets_no_path(mock_plugin_context, tmp_path):
    root = tmp_path / "src"
    write_lockfile(root, {TOP_KEY: {"version": "1.1.18"}})
    sarif = report(trivy_result("CVE-1", "package-lock.json", "1.1.18", [1]))
    out = scanner(mock_plugin_context)._attach_package_identity(sarif, root)
    (r,) = out.runs[0].results
    assert "package_path" not in props(r)
    assert props(r)["package_name"] == "brace-expansion"


def test_non_package_result_is_untouched(mock_plugin_context, tmp_path):
    sarif = report(
        {
            "ruleId": "AVD-AWS-0001",
            "message": {"text": "Artifact: main.tf\nType: terraform\n"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "main.tf"},
                        "region": {"startLine": 3},
                    }
                },
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "main.tf"},
                        "region": {"startLine": 9},
                    }
                },
            ],
        }
    )
    out = scanner(mock_plugin_context)._attach_package_identity(sarif, tmp_path)
    (r,) = out.runs[0].results
    assert len(r.locations) == 2
    assert "package_name" not in props(r)


def test_license_result_gets_its_package_name(mock_plugin_context, tmp_path):
    # trivy writes a license result's package as "PkgName:", not "Package:",
    # and gives no version. Without the name a package-scoped license approval
    # matches nothing.
    root = tmp_path / "src"
    write_lockfile(root, {"node_modules/lightningcss": {"version": "1.33.0"}})
    sarif = report(
        {
            "ruleId": "lightningcss:MPL-2.0",
            "message": {
                "text": (
                    "Artifact: package-lock.json\nLicense MPL-2.0\n"
                    "PkgName: lightningcss\n Classification: reciprocal\n"
                    " Path: package-lock.json"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "package-lock.json"},
                        "region": {"startLine": 1, "endLine": 1},
                    }
                }
            ],
        }
    )
    out = scanner(mock_plugin_context)._attach_package_identity(sarif, root)
    (r,) = out.runs[0].results
    assert props(r)["package_name"] == "lightningcss"
    assert "package_version" not in props(r)
    assert "package_path" not in props(r)
