# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ashx scan`` with ferret-scan over the operator's auth module and its test.

``.ash/.ash_community_plugins.yaml`` suppresses ferret-scan's API_KEY_OR_SECRET
on one line of each file. This copies both files into a scratch project at their
repository paths, plants a hardcoded credential on two other lines of each (one
replaced in place, so the pinned line does not move, and one appended), and runs
the installed ``ashx`` with the repository's own ferret-scan options and its own
two entries. The pinned findings must come back suppressed and the planted ones
must not.

ferret-scan is not a Python dependency of ASH; the integration-test job installs
it against the plugin's declared constraint and sets ASH_REQUIRE_FERRET_SCAN, so
there a missing binary fails rather than skips.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = REPO_ROOT / ".ash" / ".ash_community_plugins.yaml"
RULE = "API_KEY_OR_SECRET"
FERRET_MODULE = "automated_security_helper.plugin_modules.ash_ferret_plugins"
PATHS = (
    "deploy/kubernetes-operator/ash_operator/auth.py",
    "deploy/kubernetes-operator/tests/test_auth.py",
)
# Line 2 of each file is replaced in place, so no line below it moves.
PLANTED_IN_PLACE = 2


def _ferret_binary() -> str:
    search = os.pathsep.join([str(Path(sys.executable).parent), os.environ["PATH"]])
    found = shutil.which("ferret-scan", path=search)
    if found:
        return found
    if os.environ.get("ASH_REQUIRE_FERRET_SCAN", "").strip().upper() in (
        "1",
        "YES",
        "TRUE",
    ):
        pytest.fail(
            "ASH_REQUIRE_FERRET_SCAN is set but ferret-scan is not on PATH. "
            "This test must run in CI, not skip."
        )
    pytest.skip("ferret-scan is not installed")


def _planted_line() -> str:
    # Built at run time so this file holds no credential-shaped literal itself.
    value = hashlib.sha256(b"planted by the operator auth pin test").hexdigest()
    return "pass" + f'word = "{value[:24]}"'


def _scan_config(community: dict[str, Any]) -> dict[str, Any]:
    entries = [
        entry
        for entry in community["global_settings"]["suppressions"]
        if entry.get("path") in PATHS and entry.get("rule_id") == RULE
    ]
    assert len(entries) == len(PATHS), entries
    return {
        "project_name": "operator-auth-ferret-pins",
        "fail_on_findings": False,
        "ash_plugin_modules": [FERRET_MODULE],
        "scanners": {"ferret-scan": community["scanners"]["ferret-scan"]},
        "global_settings": {"suppressions": entries},
    }


def test_pinned_lines_are_suppressed_and_planted_secrets_are_not(
    tmp_path: Path,
) -> None:
    ferret = _ferret_binary()
    community = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    config = _scan_config(community)
    pinned = {
        e["path"]: e["line_start"] for e in config["global_settings"]["suppressions"]
    }

    source = tmp_path / "project"
    planted: dict[str, set[int]] = {}
    for path in PATHS:
        lines = (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()
        assert PLANTED_IN_PLACE != pinned[path]
        lines[PLANTED_IN_PLACE - 1] = _planted_line()
        lines.append(_planted_line())
        planted[path] = {PLANTED_IN_PLACE, len(lines)}
        target = source / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    config_path = tmp_path / "ash.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    output = tmp_path / "out"
    ash = shutil.which("ashx", path=str(Path(sys.executable).parent))
    assert ash, f"no ashx entry point beside {sys.executable}"
    env = {
        **os.environ,
        "PATH": os.pathsep.join([str(Path(ferret).parent), os.environ["PATH"]]),
    }
    proc = subprocess.run(
        [
            ash,
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--config",
            str(config_path),
            "--scanners",
            "ferret-scan",
            "--no-progress",
            "--no-fail-on-findings",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
    )
    log = f"exit {proc.returncode}\nSTDOUT:\n{proc.stdout[-4000:]}\nSTDERR:\n{proc.stderr[-4000:]}"

    sarif_path = output / "reports" / "ash.sarif"
    assert sarif_path.exists(), log
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    found: dict[tuple[str, int], bool] = {}
    for run in sarif["runs"]:
        for result in run.get("results", []):
            if result.get("ruleId") != RULE:
                continue
            location = result["locations"][0]["physicalLocation"]
            uri = location["artifactLocation"]["uri"]
            path = next((p for p in PATHS if uri.endswith(p)), uri)
            found[(path, location["region"]["startLine"])] = bool(
                result.get("suppressions")
            )

    expected = {(path, pinned[path]): True for path in PATHS}
    for path, planted_lines in planted.items():
        expected.update({(path, line): False for line in planted_lines})
    assert found == expected, log
