# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A lockfile entry at the reported line counts only when it is the package named.

``_attach_package_identity`` resolves each result location's line to the npm
lockfile's ``packages`` key at that line and records it as ``package_path``.
trivy's line is the line of the copy's key in the lockfile, and a lockfile that
moved since the scan, or a result trivy placed at line 1, would otherwise give the
result another package's path. The entry found is compared with the name and
version the result's message states.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

TOP_KEY = "node_modules/brace-expansion"
OTHER_KEY = "node_modules/other-package"


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


def trivy_result(name: str, version: str, start: int) -> dict:
    return {
        "ruleId": "CVE-2026-1",
        "level": "error",
        "message": {
            "text": (
                f"Package: {name}\nInstalled Version: {version}\n"
                "Vulnerability CVE-2026-1\nSeverity: HIGH\nFixed Version: 9\n"
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "package-lock.json",
                        "uriBaseId": "ROOTPATH",
                    },
                    "region": {
                        "startLine": start,
                        "startColumn": 1,
                        "endLine": start + 3,
                        "endColumn": 1,
                    },
                }
            }
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


def _attach(mock_plugin_context, root: Path, *results: dict):
    out = TrivyRepoScanner(context=mock_plugin_context)._attach_package_identity(
        report(*results), root
    )
    (result,) = out.runs[0].results
    return props(result)


def test_an_entry_of_another_version_at_the_line_gives_no_path(
    mock_plugin_context, tmp_path
):
    root = tmp_path / "src"
    _, lines = write_lockfile(root, {TOP_KEY: {"version": "1.1.18"}})

    got = _attach(
        mock_plugin_context,
        root,
        trivy_result("brace-expansion", "5.0.9", lines[TOP_KEY]),
    )

    assert "package_path" not in got
    assert got["package_name"] == "brace-expansion"
    assert got["package_version"] == "5.0.9"


def test_an_entry_of_another_package_at_the_line_gives_no_path(
    mock_plugin_context, tmp_path
):
    root = tmp_path / "src"
    _, lines = write_lockfile(root, {OTHER_KEY: {"version": "5.0.9"}})

    got = _attach(
        mock_plugin_context,
        root,
        trivy_result("brace-expansion", "5.0.9", lines[OTHER_KEY]),
    )

    assert "package_path" not in got


def test_control_the_entry_the_result_names_gets_its_path(
    mock_plugin_context, tmp_path
):
    root = tmp_path / "src"
    _, lines = write_lockfile(root, {TOP_KEY: {"version": "5.0.9"}})

    got = _attach(
        mock_plugin_context,
        root,
        trivy_result("brace-expansion", "5.0.9", lines[TOP_KEY]),
    )

    assert got["package_path"] == TOP_KEY


NESTED_KEY = "node_modules/a/node_modules/brace-expansion"
SCOPED_KEY = "node_modules/@types/node"
ALIAS_KEY = "node_modules/brace-alias"


def test_a_nested_copy_gets_its_own_path(mock_plugin_context, tmp_path):
    """The same name and version at the top level and nested: the line decides
    which copy, and the nested key is the path."""
    root = tmp_path / "src"
    _, lines = write_lockfile(
        root, {TOP_KEY: {"version": "5.0.9"}, NESTED_KEY: {"version": "5.0.9"}}
    )

    got = _attach(
        mock_plugin_context,
        root,
        trivy_result("brace-expansion", "5.0.9", lines[NESTED_KEY]),
    )

    assert got["package_path"] == NESTED_KEY


def test_a_scoped_package_is_matched_by_its_scoped_name(mock_plugin_context, tmp_path):
    root = tmp_path / "src"
    _, lines = write_lockfile(root, {SCOPED_KEY: {"version": "20.0.0"}})

    got = _attach(
        mock_plugin_context,
        root,
        trivy_result("@types/node", "20.0.0", lines[SCOPED_KEY]),
    )

    assert got["package_path"] == SCOPED_KEY
    assert got["package_name"] == "@types/node"


def test_an_aliased_install_is_matched_by_the_name_the_entry_states(
    mock_plugin_context, tmp_path
):
    """``npm install brace-alias@npm:brace-expansion`` writes the key under the
    alias and the real name in the entry; trivy names the real package."""
    root = tmp_path / "src"
    _, lines = write_lockfile(
        root, {ALIAS_KEY: {"name": "brace-expansion", "version": "5.0.9"}}
    )

    got = _attach(
        mock_plugin_context,
        root,
        trivy_result("brace-expansion", "5.0.9", lines[ALIAS_KEY]),
    )

    assert got["package_path"] == ALIAS_KEY


def test_a_result_placed_at_line_one_gets_no_path(mock_plugin_context, tmp_path):
    """Line 1 is the lockfile's opening brace, not a packages key: the result keeps
    its name and version and claims no copy."""
    root = tmp_path / "src"
    write_lockfile(root, {TOP_KEY: {"version": "5.0.9"}})

    got = _attach(
        mock_plugin_context, root, trivy_result("brace-expansion", "5.0.9", 1)
    )

    assert "package_path" not in got
    assert got["package_name"] == "brace-expansion"
    assert got["package_version"] == "5.0.9"
