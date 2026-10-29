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

CAPTURE = (
    Path(__file__).resolve().parents[4]
    / "test_data"
    / "scanners"
    / "npmaudit"
    / "yarn"
    / "classic-vuln.json"
)


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
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    (root / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")


def test_two_yarn_lockfiles_keep_both_sets_of_records(plugin_context):
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))
    _project(plugin_context.work_dir / "a")
    _project(plugin_context.work_dir / "b")
    audits = []

    def respond(self, command, **kwargs):
        if "--version" in command:
            return {
                "stdout": f"{capture['yarn_version']}\n",
                "stderr": "",
                "returncode": 0,
            }
        audits.append(list(command))
        response = {
            "stdout": capture["stdout"],
            "stderr": capture["stderr"],
            "returncode": capture["returncode"],
        }
        self._process_command_response(response)
        return response

    scanner = NpmAuditScanner(context=plugin_context, config=NpmAuditScannerConfig())
    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=respond
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert len(audits) == 2
    one_lockfile, _ = NpmAuditScanner._parse_yarn_audit(
        1,
        {
            "stdout": capture["stdout"],
            "stderr": capture["stderr"],
            "returncode": capture["returncode"],
        },
    )
    per_lockfile = len(one_lockfile["yarn_advisories"])
    assert per_lockfile > 0
    # The SARIF already had both lockfiles' findings; results.json now does too.
    assert len(report.runs[0].results) == 2 * per_lockfile
    saved = json.loads(
        scanner.results_dir.joinpath("converted", "results.json").read_text()
    )
    assert len(saved["yarn_advisories"]) == 2 * per_lockfile
