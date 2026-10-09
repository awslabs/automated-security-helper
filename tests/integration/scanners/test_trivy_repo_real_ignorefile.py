# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Real trivy: a .trivyignore in the scanned tree does not remove trivy-repo findings.

trivy reads .trivyignore from its working directory when --ignorefile is not given
(measured with trivy 0.75.0), and trivy-repo runs it in the source directory. The
fixture is a git repository with one generated GitHub token, which trivy's secret
scanner reports as ``github-pat``; secret scanning needs no vulnerability database.
Skipped when trivy is not installed.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
)

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name == "nt", reason="POSIX paths"),
]

# Built at run time so this file holds no token-shaped string. The in-tree
# .trivyignore names the first and the operator's file names the second.
_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6Q7r8"
_OTHER = "glpat-" + "Z9y8X7w6V5u4" + "T3s2R1q0"


def _trivy() -> str:
    found = shutil.which("trivy")
    if found is None:
        pytest.skip("trivy is not installed")
    return found


def _repo(tmp_path: Path) -> Path:
    source = tmp_path / "repo"
    source.mkdir()
    (source / "creds.txt").write_text(f'token = "{_TOKEN}"\nother = "{_OTHER}"\n')
    (source / ".trivyignore").write_text("github-pat\n")
    for args in (
        ["init", "-q", "."],
        ["add", "-A"],
        ["-c", "user.email=a@b", "-c", "user.name=n", "commit", "-qm", "fixture"],
    ):
        subprocess.run(["git", *args], cwd=source, check=True)  # nosec B603 B607
    return source


def _ash_rule_ids(tmp_path: Path, source: Path, options=None) -> set:
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    scanner = TrivyRepoScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=AshConfig()),
        config=TrivyRepoScannerConfig(
            options={"scanners": ["secret"], "offline": True, **(options or {})}
        ),
    )
    report = scanner.scan(target=source, target_type="source")
    return {r.ruleId for run in report.runs or [] for r in run.results or []}


def test_a_trivyignore_in_the_tree_does_not_remove_findings(tmp_path, monkeypatch):
    trivy = _trivy()
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("TRIVY_IGNOREFILE", raising=False)
    source = _repo(tmp_path)

    # The control: run as trivy-repo used to be, and the file hides the finding.
    out = tmp_path / "control.json"
    subprocess.run(  # nosec B603 - fixed argv, trivy from PATH
        [
            trivy,
            "repository",
            "--scanners",
            "secret",
            "--skip-db-update",
            "--skip-check-update",
            "--disable-telemetry",
            "--format",
            "json",
            "--output",
            str(out),
            ".",
        ],
        cwd=source,
        capture_output=True,
        check=False,
    )
    control = json.loads(out.read_text())
    control_ids = {
        s["RuleID"] for r in control.get("Results", []) for s in r.get("Secrets") or []
    }
    assert "github-pat" not in control_ids and control_ids

    assert {"github-pat"} <= _ash_rule_ids(tmp_path, source)


def test_an_operator_ignore_file_still_applies(tmp_path, monkeypatch):
    _trivy()
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("TRIVY_IGNOREFILE", raising=False)
    source = _repo(tmp_path)
    # The operator's file names the other token, so its effect cannot be confused
    # with the in-tree .trivyignore's.
    operator = tmp_path / "operator" / "trivyignore"
    operator.parent.mkdir()
    operator.write_text("gitlab-pat\n")
    found = _ash_rule_ids(tmp_path, source, {"ignore_file": str(operator)})
    assert "gitlab-pat" not in found
    assert "github-pat" in found
