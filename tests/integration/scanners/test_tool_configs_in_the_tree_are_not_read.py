# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Real tools: a config or ignore file in the scanned tree does not narrow the scan.

Each test runs the tool as it would run without ASH's handling (the control),
showing the in-tree file hides a finding, then runs ASH's scanner over the same
tree and checks the finding is reported. Measured with bandit 1.9.4, grype
0.118.0, syft 1.51.1, semgrep 1.180.0 and opengrep 1.15.1 and 1.30.0:

* bandit finds a ``.bandit`` anywhere under the target unless ``--ini`` names one;
* grype and syft read ``.grype.yaml`` and ``.syft.yaml`` from their working
  directory, the source directory, unless ``--config`` names one;
* semgrep and opengrep honor a ``.semgrepignore`` in the tree unless
  ``--x-ignore-semgrepignore-files`` is passed.

Each test is skipped when its tool is not installed; grype's also needs a
vulnerability database already in its cache.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Set

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig

PluginContext.model_rebuild()

MARKER = "ASH_TOOL_CONFIG_MARKER_7f3a"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name == "nt", reason="POSIX paths"),
]


def _tool(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        pytest.skip(f"{name} is not installed")
    return found


def _context(tmp_path: Path, source: Path) -> PluginContext:
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    return PluginContext(source_dir=source, output_dir=output, config=AshConfig())


def _rule_ids(report: Any) -> Set[str]:
    assert report, f"the scanner reported nothing: {report!r}"
    return {r.ruleId for run in report.runs or [] for r in run.results or []}


def _uris(report: Any) -> Set[str]:
    assert report, f"the scanner reported nothing: {report!r}"
    return {
        loc.physicalLocation.root.artifactLocation.uri
        for run in report.runs or []
        for r in run.results or []
        for loc in r.locations or []
    }


# ---------------------------------------------------------------------------
# bandit
# ---------------------------------------------------------------------------


def test_a_dot_bandit_in_the_tree_does_not_skip_tests(tmp_path: Path) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
        BanditScannerConfig,
    )

    bandit = _tool("bandit")
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text(
        'import subprocess\nsubprocess.call("ls", shell=True)\n', encoding="utf-8"
    )
    (source / ".bandit").write_text("[bandit]\nskips: B602\n", encoding="utf-8")

    control = subprocess.run(  # nosec B603 - fixed argv, bandit from PATH
        [bandit, "-r", str(source), "-f", "json", "-q"],
        capture_output=True,
        text=True,
        check=False,
    )
    control_ids = {item["test_id"] for item in json.loads(control.stdout)["results"]}
    assert "B602" not in control_ids and control_ids, control.stdout

    scanner = BanditScanner(
        context=_context(tmp_path, source), config=BanditScannerConfig()
    )
    assert "B602" in _rule_ids(scanner.scan(target=source, target_type="source"))


# ---------------------------------------------------------------------------
# grype and syft
# ---------------------------------------------------------------------------


def _python_project(tmp_path: Path) -> Path:
    source = tmp_path / "repo"
    source.mkdir()
    (source / "requirements.txt").write_text("requests==2.19.1\n", encoding="utf-8")
    return source


def test_a_grype_yaml_in_the_tree_does_not_ignore_vulnerabilities(
    tmp_path: Path,
) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
        GrypeScannerConfigOptions,
    )

    grype = _tool("grype")
    source = _python_project(tmp_path)
    env: Dict[str, str] = {**os.environ, "GRYPE_DB_AUTO_UPDATE": "false"}
    baseline = subprocess.run(  # nosec B603 - fixed argv, grype from PATH
        [grype, f"dir:{source}", "-o", "json", "-q"],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if baseline.returncode != 0 or not json.loads(baseline.stdout or "{}").get(
        "matches"
    ):
        pytest.skip("grype has no usable vulnerability database in its cache")

    (source / ".grype.yaml").write_text(
        "ignore:\n  - package:\n      name: requests\n", encoding="utf-8"
    )
    control = subprocess.run(  # nosec B603 - fixed argv, grype from PATH
        [grype, f"dir:{source}", "-o", "json", "-q"],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert not json.loads(control.stdout).get("matches"), control.stdout

    scanner = GrypeScanner(
        context=_context(tmp_path, source),
        config=GrypeScannerConfig(options=GrypeScannerConfigOptions(offline=True)),
    )
    assert _rule_ids(scanner.scan(target=source, target_type="source"))


def test_a_syft_yaml_in_the_tree_does_not_drop_components(tmp_path: Path) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScanner,
        SyftScannerConfig,
    )

    syft = _tool("syft")
    source = _python_project(tmp_path)
    (source / ".syft.yaml").write_text(
        "exclude:\n  - ./requirements.txt\n", encoding="utf-8"
    )
    control = subprocess.run(  # nosec B603 - fixed argv, syft from PATH
        [syft, "scan", f"dir:{source}", "-o", "cyclonedx-json", "-q"],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
    )
    names = {c["name"] for c in json.loads(control.stdout).get("components", [])}
    assert "requests" not in names, control.stdout

    scanner = SyftScanner(
        context=_context(tmp_path, source), config=SyftScannerConfig()
    )
    report = scanner.scan(target=source, target_type="source")
    assert "requests" in {component.name for component in report.components or []}


# ---------------------------------------------------------------------------
# semgrep and opengrep
# ---------------------------------------------------------------------------


def _grep_tree(tmp_path: Path) -> Path:
    source = tmp_path / "repo"
    for relative in ("app.txt", "hidden/h.txt", "tests/t.txt"):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{MARKER}\n", encoding="utf-8")
    (source / ".semgrepignore").write_text("hidden/\n", encoding="utf-8")
    return source


def _rule_file(tmp_path: Path) -> Path:
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - id: marker\n"
        "    message: marker\n"
        "    severity: WARNING\n"
        "    languages: [generic]\n"
        f"    pattern-regex: {MARKER}\n",
        encoding="utf-8",
    )
    return rules


@pytest.mark.parametrize("tool", ["semgrep", "opengrep"])
def test_a_semgrepignore_in_the_tree_does_not_hide_files(
    tmp_path: Path, tool: str
) -> None:
    binary = _tool(tool)
    source = _grep_tree(tmp_path)
    rules = _rule_file(tmp_path)
    control_out = tmp_path / "control.sarif"
    subprocess.run(  # nosec B603 - fixed argv, the tool from PATH
        [
            binary,
            "scan",
            "--config",
            str(rules),
            *(["--metrics", "off"] if tool == "semgrep" else []),
            "--sarif-output",
            str(control_out),
            str(source),
        ],
        cwd=source,
        capture_output=True,
        check=False,
    )
    control = json.loads(control_out.read_text(encoding="utf-8"))
    control_uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for run in control["runs"]
        for r in run["results"]
    }
    assert not any("hidden/" in uri for uri in control_uris), control_uris

    if tool == "semgrep":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner as cls,
            SemgrepScannerConfig as cfg,
        )
    else:
        from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
            OpengrepScanner as cls,  # type: ignore[assignment]
            OpengrepScannerConfig as cfg,  # type: ignore[assignment]
        )
    scanner = cls(
        context=_context(tmp_path, source),
        config=cfg.model_validate({"options": {"config": str(rules)}}),
    )
    uris = _uris(scanner.scan(target=source, target_type="source"))
    assert any("hidden/h.txt" in uri for uri in uris), uris
    # The tools' own default exclusions still apply.
    assert not any("tests/t.txt" in uri for uri in uris), uris
