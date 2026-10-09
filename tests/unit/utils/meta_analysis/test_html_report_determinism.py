# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sarif-fields HTML report must not depend on the interpreter's hash seed.

With two scanners present, the order of the scanner sections and of the
"Scanner Results" rows followed set iteration, the JQ element ids came from
``hash(path)``, and the example file chosen for each JQ command came from
iterating a set of scanner names. All three change with PYTHONHASHSEED, so the
same input rendered a different report on every run.

Hash randomization is fixed for the life of a process, so the only honest way to
vary it is to render in separate processes.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

RENDER = """
import sys
import typer
from automated_security_helper.utils.sarif_field_analysis import analyze_sarif_fields

try:
    analyze_sarif_fields(sarif_dir=sys.argv[1], output_dir=sys.argv[2])
except typer.Exit:
    pass  # exit 1 only signals unexpectedly missing fields
"""

# Several seeds so a single lucky agreement between two seeds cannot hide the
# defect; 0 disables randomization and is a valid point of comparison too.
SEEDS = ["0", "1", "2", "3", "4", "5"]


def _write_sarif(path: Path, results: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"runs": [{"results": results}]}), encoding="utf-8")


def _fixture(root: Path) -> Path:
    sarif_dir = root / "ash_output"
    shared = {"ruleId": "R1", "level": "error", "message": {"text": "m"}}
    _write_sarif(
        sarif_dir / "scanners" / "bandit" / "bandit.sarif",
        [{**shared, "kind": "fail"}],
    )
    _write_sarif(
        sarif_dir / "scanners" / "semgrep" / "semgrep.sarif",
        [{**shared, "rank": 1.0}],
    )
    _write_sarif(sarif_dir / "reports" / "ash.sarif", [shared])
    return sarif_dir


def _render(sarif_dir: Path, out_dir: Path, seed: str) -> str:
    env = {**os.environ, "PYTHONHASHSEED": seed, "COLUMNS": "200"}
    proc = subprocess.run(  # nosec B603 - fixed argv, test-only
        [sys.executable, "-c", RENDER, str(sarif_dir), str(out_dir)],
        env=env,
        capture_output=True,
        # The child draws a rich spinner whose braille frames are UTF-8 (one of
        # them encodes to a 0x90 byte), and the parent's locale encoding on
        # Windows is cp1252, which has no character for 0x90.
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    report = out_dir / "sarif_validation_report.html"
    assert report.exists(), f"seed {seed} produced no report:\n{proc.stderr}"
    return report.read_text(encoding="utf-8")


def test_html_report_is_identical_across_hash_seeds(tmp_path):
    sarif_dir = _fixture(tmp_path)

    rendered = {
        seed: _render(sarif_dir, tmp_path / f"out-{seed}", seed) for seed in SEEDS
    }

    baseline = rendered[SEEDS[0]]
    differing = [seed for seed, html in rendered.items() if html != baseline]
    assert differing == [], f"report differs from seed {SEEDS[0]} for seeds {differing}"


def test_scanners_are_listed_in_name_order(tmp_path):
    """Identical output alone would also pass if every run agreed on a bad order."""
    sarif_dir = _fixture(tmp_path)

    html = _render(sarif_dir, tmp_path / "out", "1")

    headers = [
        line.strip()
        for line in html.splitlines()
        if line.strip().startswith("<h3>") and line.strip().endswith("</h3>")
    ]
    assert headers == ["<h3>ash</h3>", "<h3>bandit</h3>", "<h3>semgrep</h3>"]
