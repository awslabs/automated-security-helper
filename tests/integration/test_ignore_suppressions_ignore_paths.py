# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan --ignore-suppressions`` end to end: ignore paths are lifted for every scanner.

The fixture's app.py carries a bandit finding and a detect-secrets finding, and
the repository's config lists app.py under ``ignore_paths``. Without the flag
both scanners report nothing for it and the scan exits 0. With the flag both
report it and the scan exits 2. Before, only bandit did: it reads the whole
directory, while detect-secrets is handed the file list left after the ignore
paths, and that list did not follow the flag.

ASH's own output directory is not an ignore path. Findings located there stay
out of the results with the flag set, which the last test checks with a file
planted in the output directory.

The scan runs as a subprocess of the installed ``ash`` entry point, so the exit
code is the one a user sees.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

import pytest
import yaml

pytestmark = pytest.mark.integration

# Built at runtime so this file holds no secret-shaped literal. AWS's documented
# example key, which detect-secrets reports.
PLANTED_KEY = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002

FINDINGS_PY = (
    "import subprocess\n"
    "\n"
    f'AWS_ACCESS_KEY_ID = "{PLANTED_KEY}"\n'
    "\n"
    "\n"
    "def run(command):\n"
    "    return subprocess.call(command, shell=True)\n"
)

SCANNERS = ("bandit", "detect-secrets")


def _ignored_tree(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "app.py").write_text(FINDINGS_PY, encoding="utf-8")
    # A file the ignore path does not name. With app.py the only Python file, the
    # ignore path leaves bandit nothing to scan, the run has shown the target to be
    # neither clean nor dirty, and it exits 1 (run_ash_scan.nothing_to_scan_message);
    # here the scan covers a clean file and the ignored one reports nothing.
    (root / "clean.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )
    (root / ".ash").mkdir()
    (root / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {
                "project_name": "ignore-paths-e2e",
                "global_settings": {
                    "ignore_paths": [{"path": "app.py", "reason": "test fixture"}]
                },
            }
        ),
        encoding="utf-8",
    )
    return root


def _scan(
    source: Path, output: Path, scanners: Tuple[str, ...], ignore_suppressions: bool
) -> Tuple[int, str]:
    ash = shutil.which("ash", path=str(Path(sys.executable).parent))
    assert ash, f"no ash entry point beside {sys.executable}"
    command = [
        ash,
        "scan",
        "--mode",
        "local",
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--no-progress",
        "--no-color",
        "--fail-on-findings",
    ]
    for scanner in scanners:
        command += ["--scanners", scanner]
    if ignore_suppressions:
        command.append("--ignore-suppressions")
    proc = subprocess.run(command, capture_output=True, text=True, timeout=600)
    log = (
        f"exit {proc.returncode}\nSTDOUT:\n{proc.stdout[-4000:]}\n"
        f"STDERR:\n{proc.stderr[-4000:]}"
    )
    return proc.returncode, log


def _findings(output: Path, log: str) -> List[Tuple[str, str, bool]]:
    """``(scanner, file name, suppressed)`` for every result in the aggregated SARIF."""
    results_path = output / "ash_aggregated_results.json"
    assert results_path.is_file(), log
    document = json.loads(results_path.read_text(encoding="utf-8"))
    found = []
    for run in document["sarif"]["runs"]:
        for result in run.get("results") or []:
            scanner = (result.get("properties") or {}).get("scanner_name")
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            found.append((scanner, Path(uri).name, bool(result.get("suppressions"))))
    return found


@pytest.mark.parametrize("scanner", SCANNERS)
def test_without_the_flag_the_ignored_file_reports_nothing(tmp_path, scanner):
    source = _ignored_tree(tmp_path / "src")
    output = tmp_path / "out"

    code, log = _scan(source, output, (scanner,), ignore_suppressions=False)

    assert code == 0, log
    assert [f for f in _findings(output, log) if f[1] == "app.py"] == [], log


@pytest.mark.parametrize("scanner", SCANNERS)
def test_with_the_flag_each_scanner_reports_the_ignored_file(tmp_path, scanner):
    source = _ignored_tree(tmp_path / "src")
    output = tmp_path / "out"

    code, log = _scan(source, output, (scanner,), ignore_suppressions=True)

    assert code == 2, log
    reported = [f for f in _findings(output, log) if f[1] == "app.py"]
    assert {f[0] for f in reported} == {scanner}, (reported, log)
    assert not any(f[2] for f in reported), (reported, log)


def test_with_the_flag_one_scan_reports_both_scanners_findings(tmp_path):
    source = _ignored_tree(tmp_path / "src")
    output = tmp_path / "out"

    code, log = _scan(source, output, SCANNERS, ignore_suppressions=True)

    assert code == 2, log
    reported = {f[0] for f in _findings(output, log) if f[1] == "app.py"}
    assert reported == set(SCANNERS), log


def test_a_finding_in_the_output_directory_stays_out_with_the_flag(tmp_path):
    """The output directory is left out whatever the flag says.

    The output directory is the default one, inside the scanned tree, and holds a
    file with the same two findings app.py has above. Those tests are the control:
    the same content elsewhere in the tree is reported.
    """
    source = tmp_path / "src"
    source.mkdir()
    (source / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / "planted.py").write_text(FINDINGS_PY, encoding="utf-8")

    code, log = _scan(source, output, SCANNERS, ignore_suppressions=True)

    assert code == 0, log
    assert [f for f in _findings(output, log) if f[1] == "planted.py"] == [], log
