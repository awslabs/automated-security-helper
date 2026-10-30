# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The merged results.json keeps every yarn lockfile's advisories.

Each lockfile's audit converts to SARIF on its own, so the findings were never
lost there; the merged raw output written to results.json had merge branches
for npm's ``vulnerabilities`` and pnpm's ``advisories`` but none for yarn's
records, so every yarn lockfile after the first was dropped from that file.
"""

from __future__ import annotations

import json
from pathlib import Path
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

pytestmark = pytest.mark.unit

CAPTURES = (
    Path(__file__).resolve().parents[4] / "test_data" / "scanners" / "npmaudit" / "yarn"
)
#: Lockfile ``a`` answers with the CLEAN report and ``b`` with the advisories,
#: and the walk is pinned to audit ``a`` first. A merge that kept only the first
#: lockfile's records then saved nothing, where ``b``'s records are expected;
#: with the vulnerable capture first (the shape before), the "first only" merge
#: saved exactly the expected set and the test passed on the bug.
CAPTURE = CAPTURES / "classic-vuln.json"
CLEAN_CAPTURE = CAPTURES / "classic-clean.json"


@pytest.fixture
def plugin_context(tmp_path, monkeypatch):
    monkeypatch.setattr(
        npm_audit_scanner, "find_executable", lambda name: str(tmp_path / name)
    )
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for d in (context.source_dir, context.output_dir, context.work_dir):
        d.mkdir(parents=True)
    return context


def _project(root):
    """A yarn project named after its directory, so the responder can tell
    ``a`` from ``b`` by the manifest it finds in the audit's working directory."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": root.name}) + "\n", encoding="utf-8"
    )
    (root / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")


def test_two_yarn_lockfiles_keep_both_sets_of_records(plugin_context):
    """Lockfile ``a`` is audited first and answers with the clean capture;
    ``b`` is audited second and answers with the vulnerable one. The merged
    file then holds exactly ``b``'s records, the SECOND lockfile's: a merge that
    kept the first lockfile's records and dropped every lockfile after it saved
    none, where the earlier arrangement (vulnerable first) gave that merge the
    expected set for free. The walk is pinned to list ``a`` before ``b`` so the
    order does not depend on the filesystem, and the audits are recorded by the
    package they ran in."""
    vuln = json.loads(CAPTURE.read_text(encoding="utf-8"))
    clean = json.loads(CLEAN_CAPTURE.read_text(encoding="utf-8"))
    assert vuln["yarn_version"].split(".")[0] == clean["yarn_version"].split(".")[0]
    by_project = {"a": clean, "b": vuln}
    _project(plugin_context.work_dir / "a")
    _project(plugin_context.work_dir / "b")
    audits = []

    def respond(self, command, **kwargs):
        if "--version" in command:
            return {
                "stdout": f"{vuln['yarn_version']}\n",
                "stderr": "",
                "returncode": 0,
            }
        manifest = json.loads((Path(kwargs["cwd"]) / "package.json").read_text())
        audits.append(manifest["name"])
        capture = by_project[manifest["name"]]
        response = {
            "stdout": capture["stdout"],
            "stderr": capture["stderr"],
            "returncode": capture["returncode"],
        }
        self._process_command_response(response)
        return response

    walk = NpmAuditScanner._package_manifests

    def a_first(self, *args, **kwargs):
        found = walk(self, *args, **kwargs)
        return sorted(found, key=lambda m: 0 if Path(m).parent.name == "a" else 1)

    scanner = NpmAuditScanner(context=plugin_context, config=NpmAuditScannerConfig())
    with (
        patch.object(NpmAuditScanner, "_package_manifests", a_first),
        patch.object(
            NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=respond
        ),
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert audits == ["a", "b"], audits
    one_lockfile, _ = NpmAuditScanner._parse_yarn_audit(
        1,
        {
            "stdout": vuln["stdout"],
            "stderr": vuln["stderr"],
            "returncode": vuln["returncode"],
        },
    )
    expected = one_lockfile["yarn_advisories"]
    assert len(expected) > 0
    # The SARIF already had both lockfiles' findings; results.json now does too:
    # exactly b's records (the second lockfile's), and none from a (it had
    # none). The raw records carry no lockfile field of their own; the SARIF
    # results do, so the lockfile each finding came from is read there.
    assert len(report.runs[0].results) == len(expected)
    assert {
        r.properties.model_extra.get("lockfile") for r in report.runs[0].results
    } == {"b/yarn.lock"}
    saved = json.loads(
        scanner.results_dir.joinpath("converted", "results.json").read_text()
    )
    assert len(saved["yarn_advisories"]) == len(expected)
    assert sorted(r["url"] for r in saved["yarn_advisories"]) == sorted(
        r["url"] for r in expected
    )
