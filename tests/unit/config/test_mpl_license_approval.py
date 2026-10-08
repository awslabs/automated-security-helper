# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""MPL-2.0 is approved for three (file, package) pairs and nowhere else.

The self-scan (.ash/.ash_community_plugins.yaml, trivy-repo with the license
scanner on) reports MPL-2.0 for 12 lightningcss packages in
scripts/e2e/inspector/package-lock.json and for certifi in
deploy/kubernetes-operator/requirements.txt. Those are approved there. MPL-2.0
for any other package or in any other file must still be an active finding,
and so must any other copyleft license in the approved files.

trivy names a license result ``<package>:<license>``, places it on line 1 of
the manifest, and writes the package only as a ``PkgName:`` line in the
message. The approvals are scoped with ``package_name``, which the trivy-repo
scanner reads from that line. Without it the approved findings stay active,
which the first test shows.

Every finding here goes through the same two steps a real scan applies:
``TrivyRepoScanner._attach_package_identity`` and then
``apply_suppressions_to_sarif`` with the suppressions loaded from the
repository's config file. The result shape is copied from trivy 0.69.3's SARIF
output for this repository.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG = REPO_ROOT / ".ash" / ".ash_community_plugins.yaml"
INSPECTOR_LOCK = "scripts/e2e/inspector/package-lock.json"
OPERATOR_REQUIREMENTS = "deploy/kubernetes-operator/requirements.txt"


def _lightningcss_packages() -> list[str]:
    packages = json.loads((REPO_ROOT / INSPECTOR_LOCK).read_text())["packages"]
    names = {
        key.rsplit("node_modules/", 1)[-1]
        for key in packages
        if key.rsplit("node_modules/", 1)[-1].startswith("lightningcss")
    }
    return sorted(names)


LIGHTNINGCSS = _lightningcss_packages()


def license_result(package: str, license_id: str, uri: str) -> dict:
    """A license result in the shape trivy 0.69.3 writes it."""
    return {
        "ruleId": f"{package}:{license_id}",
        "level": "warning",
        "message": {
            "text": (
                f"Artifact: {uri}\nLicense {license_id}\nPkgName: {package}\n"
                f" Classification: reciprocal\n Path: {uri}"
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "ROOTPATH"},
                    "region": {
                        "startLine": 1,
                        "startColumn": 1,
                        "endLine": 1,
                        "endColumn": 1,
                    },
                },
                "message": {"text": ""},
            }
        ],
    }


@pytest.fixture(scope="module")
def suppressions():
    return AshConfig.from_file(CONFIG).global_settings.suppressions


def _context(suppressions) -> MagicMock:
    ctx = MagicMock(spec=PluginContext)
    ctx.source_dir = REPO_ROOT
    ctx.output_dir = REPO_ROOT / ".ash" / "ash_output"
    ctx.ignore_suppressions = False
    ctx.global_ignore_paths = []
    ctx.config = MagicMock()
    ctx.config.global_settings.ignore_paths = []
    ctx.config.global_settings.suppressions = list(suppressions)
    return ctx


def _scan(suppressions, results: list[dict]) -> dict[str, bool]:
    """Map each result's ``ruleId@uri`` to whether it ended up suppressed."""
    sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": results}],
        }
    )
    scanner = TrivyRepoScanner(context=_context(suppressions))
    sarif = scanner._attach_package_identity(sarif, REPO_ROOT)
    sarif = apply_suppressions_to_sarif(sarif, _context(suppressions))
    out = {}
    for result in sarif.runs[0].results or []:
        uri = result.locations[0].physicalLocation.root.artifactLocation.uri
        out[f"{result.ruleId}@{uri}"] = bool(result.suppressions)
    return out


def test_the_lockfile_still_holds_the_twelve_lightningcss_packages():
    # Ties the approval to the dependency tree it was written for. A change in
    # this count means the inspector's tree moved and the approval needs review.
    assert len(LIGHTNINGCSS) == 12, LIGHTNINGCSS
    assert "lightningcss" in LIGHTNINGCSS


def test_the_approved_mpl_findings_are_suppressed(suppressions):
    results = [license_result(p, "MPL-2.0", INSPECTOR_LOCK) for p in LIGHTNINGCSS]
    results.append(license_result("certifi", "MPL-2.0", OPERATOR_REQUIREMENTS))
    outcome = _scan(suppressions, results)
    assert len(outcome) == 13
    active = [key for key, suppressed in outcome.items() if not suppressed]
    assert active == []


@pytest.mark.parametrize(
    "package,uri",
    [
        # The same packages, in other manifests.
        ("lightningcss", "deploy/cdk/package-lock.json"),
        ("lightningcss-linux-x64-gnu", "editors/vscode/package-lock.json"),
        ("certifi", "requirements.txt"),
        ("certifi", "deploy/kubernetes-operator/build-requirements.txt"),
        # A planted lockfile anywhere else in the tree.
        ("lightningcss", "planted/package-lock.json"),
        ("certifi", "planted/requirements.txt"),
        # A sibling file whose name starts with an approved one.
        ("lightningcss", "scripts/e2e/inspector/package-lock.json.bak"),
        # A new MPL-2.0 package in an approved file.
        ("some-new-package", INSPECTOR_LOCK),
        ("lightningcs", INSPECTOR_LOCK),
        ("requests", OPERATOR_REQUIREMENTS),
        # Each approval names one file's packages, not the other file's.
        ("certifi", INSPECTOR_LOCK),
        ("lightningcss", OPERATOR_REQUIREMENTS),
    ],
)
def test_mpl_anywhere_else_still_fails(suppressions, package, uri):
    outcome = _scan(suppressions, [license_result(package, "MPL-2.0", uri)])
    assert outcome == {f"{package}:MPL-2.0@{uri}": False}


@pytest.mark.parametrize(
    "license_id",
    ["GPL-3.0-only", "LGPL-2.1-or-later", "AGPL-3.0-only", "EPL-2.0", "MPL-1.1"],
)
@pytest.mark.parametrize(
    "package,uri",
    [
        ("lightningcss", INSPECTOR_LOCK),
        ("lightningcss-win32-x64-msvc", INSPECTOR_LOCK),
        ("certifi", OPERATOR_REQUIREMENTS),
    ],
)
def test_another_copyleft_license_in_the_approved_files_still_fails(
    suppressions, license_id, package, uri
):
    outcome = _scan(suppressions, [license_result(package, license_id, uri)])
    assert outcome == {f"{package}:{license_id}@{uri}": False}
