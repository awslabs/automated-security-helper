# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""actionlint end to end, with the real binary.

The unit tests in ``tests/unit/plugin_modules/ash_builtin/test_actionlint_scanner.py``
replace the subprocess with output captured from actionlint 1.7.12. These run the
installed binary, so a version whose output drifts from the capture, or an argv the
binary rejects, fails here.

CI installs the pinned binary with ``ash dependencies install --tool actionlint`` and
sets ``ASH_REQUIRE_ACTIONLINT=1``, which turns the skip below into a failure: this
file must run in CI, not skip.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_actionlint_plugins.actionlint_scanner import (
    ActionlintScanner,
    ActionlintScannerConfig,
    ActionlintScannerConfigOptions,
)
from automated_security_helper.utils.subprocess_utils import find_executable

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_REPO = REPO_ROOT / "tests" / "test_data" / "scanners" / "actionlint" / "repo"

#: (ruleId, SARIF level, ASH severity, startLine) for the fixture, in order.
EXPECTED = [
    ("credentials", "error", "HIGH", 17),
    ("expression", "error", "HIGH", 20),
    ("deprecated-commands", "note", "LOW", 22),
    ("deprecated-commands", "warning", "MEDIUM", 24),
    ("if-cond", "warning", "MEDIUM", 26),
    ("job-needs", "note", "LOW", 28),
    ("runner-label", "note", "LOW", 36),
    ("syntax-check", "note", "LOW", 37),
]


def _require_actionlint() -> str:
    found = find_executable("actionlint")
    if found:
        return found
    if os.environ.get("ASH_REQUIRE_ACTIONLINT", "").strip().upper() in (
        "1",
        "YES",
        "TRUE",
    ):
        pytest.fail(
            "ASH_REQUIRE_ACTIONLINT is set but actionlint is not installed. "
            "This test must run in CI, not skip."
        )
    pytest.skip("actionlint is not installed")


@pytest.fixture
def repo(tmp_path) -> Path:
    target = tmp_path / "repo"
    shutil.copytree(FIXTURE_REPO, target)
    return target


def _ash(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "automated_security_helper.cli.main", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        env=env,
    )


def test_the_real_binary_reports_the_fixture_findings(repo, tmp_path):
    _require_actionlint()
    scanner = ActionlintScanner(
        context=PluginContext(
            source_dir=repo,
            output_dir=tmp_path / "out",
            config=get_default_config(),
        ),
        config=ActionlintScannerConfig(
            enabled=True, options=ActionlintScannerConfigOptions()
        ),
    )

    report = scanner.scan(target=repo, target_type="source")

    rows = [
        (
            r.ruleId,
            getattr(r.level, "value", r.level),
            r.properties.issue_severity,
            r.locations[0].physicalLocation.root.region.startLine,
        )
        for r in report.runs[0].results
    ]
    assert rows == EXPECTED
    assert {
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.runs[0].results
    } == {".github/workflows/vulnerable.yml"}
    assert scanner.exit_code == 1
    assert report.runs[0].tool.driver.version.startswith("1.")


def test_a_full_scan_with_actionlint_selected(repo, tmp_path):
    """``--scanners actionlint`` runs it, offline, and fails on the HIGH findings."""
    _require_actionlint()
    output = tmp_path / "out"
    env = {**os.environ, "ASH_OFFLINE": "true"}

    result = _ash(
        "scan",
        "--ash-plugin-modules",
        "automated_security_helper.plugin_modules.ash_actionlint_plugins",
        "--mode",
        "local",
        "--source-dir",
        str(repo),
        "--output-dir",
        str(output),
        "--scanners",
        "actionlint",
        "--no-progress",
        env=env,
    )

    assert result.returncode == 2, result.stdout[-3000:] + result.stderr[-3000:]
    aggregated = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    status = aggregated["scanner_results"]["actionlint"]
    assert status["status"] == "FAILED", status
    sarif = json.loads((output / "reports" / "ash.sarif").read_text(encoding="utf-8"))
    levels = sorted(
        r["level"]
        for run in sarif["runs"]
        for r in run["results"]
        if r["ruleId"] in {"credentials", "expression"}
    )
    assert levels == ["error", "error"]


def test_enabled_but_missing_is_missing_and_exits_one(repo, tmp_path):
    """An enabled opt-in scanner without its binary fails the completeness gate."""
    if Path("/usr/local/bin/actionlint").exists():
        pytest.skip("/usr/local/bin/actionlint exists and is always searched")
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    output = tmp_path / "out"
    env = {
        **os.environ,
        "PATH": os.pathsep.join([str(Path(sys.executable).parent)]),
        "ASH_BIN_PATH": str(empty_bin),
    }

    result = _ash(
        "scan",
        "--ash-plugin-modules",
        "automated_security_helper.plugin_modules.ash_actionlint_plugins",
        "--mode",
        "local",
        "--source-dir",
        str(repo),
        "--output-dir",
        str(output),
        "--scanners",
        "actionlint",
        "--no-progress",
        env=env,
    )

    assert result.returncode == 1, result.stdout[-3000:] + result.stderr[-3000:]
    aggregated = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    assert aggregated["scanner_results"]["actionlint"]["status"] == "MISSING"


# --------------------------------------------------------------------------- #
# The scanned tree's config cannot choose the program actionlint pipes run:
# scripts to. actionlint runs it as `<program> --norc -f json -x --shell bash
# ... -` from the scan root, so `shellcheck: bash` makes bash execute a file
# named `json` that the repository committed. Each case plants a program that
# leaves a marker when run; the operator case is the control that proves a
# planted program does run when it is allowed to.
# --------------------------------------------------------------------------- #

MODULE = "automated_security_helper.plugin_modules.ash_actionlint_plugins"


def _marker_program(path: Path, marker: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\ntouch '{marker}'\necho '[]'\n")
    path.chmod(0o755)
    return path


def _repo_config(repo: Path, **options: str) -> None:
    lines = [
        "ash_plugin_modules:",
        f"  - {MODULE}",
        "scanners:",
        "  actionlint:",
        "    options:",
        *(f"      {name}: {json.dumps(value)}" for name, value in options.items()),
    ]
    (repo / ".ash").mkdir(exist_ok=True)
    (repo / ".ash" / ".ash.yaml").write_text("\n".join(lines) + "\n")


def _scan(repo: Path, output: Path, *extra: str) -> subprocess.CompletedProcess:
    return _ash(
        "scan",
        "--ash-plugin-modules",
        MODULE,
        "--mode",
        "local",
        "--source-dir",
        str(repo),
        "--output-dir",
        str(output),
        "--scanners",
        "actionlint",
        "--no-progress",
        "--fail-on-findings",
        "false",
        *extra,
        env={**os.environ, "ASH_OFFLINE": "true"},
    )


def _actionlint_sarif(output: Path) -> str:
    found = sorted((output / "scanners" / "actionlint").rglob("actionlint.sarif"))
    assert found, f"actionlint wrote no SARIF under {output}"
    return found[0].read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell and execute bit")
def test_shellcheck_bash_from_the_scanned_tree_never_runs_its_json(repo, tmp_path):
    _require_actionlint()
    if not shutil.which("bash"):
        pytest.skip("bash is not installed")
    marker = tmp_path / "json-ran"
    _marker_program(repo / "json", marker)
    _repo_config(repo, shellcheck="bash")
    output = tmp_path / "out"

    result = _scan(repo, output)

    assert not marker.exists(), "actionlint ran bash on the repository's json file"
    log = (output / "ash.log").read_text(encoding="utf-8", errors="replace")
    assert "Ignoring scanners.actionlint.options.shellcheck" in log, (
        result.stdout[-3000:] + result.stderr[-3000:]
    )
    assert "-shellcheck=bash" not in _actionlint_sarif(output)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell and execute bit")
@pytest.mark.parametrize("flag", ["shellcheck", "pyflakes"])
def test_a_program_planted_in_the_scanned_tree_never_runs(repo, tmp_path, flag):
    _require_actionlint()
    marker = tmp_path / "planted-ran"
    planted = _marker_program(repo / "tools" / "planted", marker)
    _repo_config(repo, **{flag: planted.as_posix()})
    output = tmp_path / "out"

    _scan(repo, output)

    assert not marker.exists()
    assert planted.as_posix() not in _actionlint_sarif(output)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell and execute bit")
def test_the_operator_can_name_a_program_outside_the_tree(repo, tmp_path):
    """The control: the same kind of program does run when the operator names it."""
    _require_actionlint()
    marker = tmp_path / "operator-ran"
    program = _marker_program(tmp_path / "operator-bin" / "shellcheck", marker)
    _repo_config(repo, shellcheck="bash")
    output = tmp_path / "out"

    _scan(
        repo,
        output,
        "--config-overrides",
        f"scanners.actionlint.options.shellcheck={program.as_posix()}",
    )

    assert marker.exists(), "the operator's shellcheck never ran"
