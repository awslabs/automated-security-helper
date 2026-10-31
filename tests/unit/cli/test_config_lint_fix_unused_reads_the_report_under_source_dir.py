# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash config lint --fix-unused` finds the unused-suppressions report where
the scan wrote it: under --source-dir.

Without --output-dir the fixer looked for the report beside the config file,
but a scan writes its output under the directory it scans, and --config can
name a file anywhere. At the base a config kept apart from the scanned tree
gets "No unused suppressions report found" and stays as it is; at the tip the
report under --source-dir is read and the unused suppressions are commented
out.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app

pytestmark = pytest.mark.unit

UNUSED = {
    "path": "src/old_file.py",
    "rule_id": "B603",
    "line_start": 10,
    "line_end": 10,
    "reason": "File was deleted",
}
KEPT = {"path": "src/still_needed.py", "rule_id": "B101", "reason": "Still needed"}


def test_fix_unused_reads_the_report_the_scan_wrote_under_source_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config_path = tmp_path / "configs" / "ash.yaml"
    config_path.parent.mkdir()
    config_path.write_text(
        yaml.dump(
            {
                "project_name": "demo",
                "global_settings": {"suppressions": [UNUSED, KEPT]},
            },
            default_flow_style=False,
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    scanned = tmp_path / "scanned"
    reports = scanned / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.unused-suppressions.json").write_text(
        json.dumps({"unused_suppressions": [{**UNUSED, "expiration": None}]}),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        config_app,
        [
            "lint",
            "--config",
            str(config_path),
            "--source-dir",
            str(scanned),
            "--fix-unused",
            "--yes",
        ],
    )

    assert "No unused suppressions report found" not in result.output
    assert "Commented out 1 unused suppression(s)" in result.output, result.output
    written = config_path.read_text(encoding="utf-8")
    assert "# [ash-lint" in written
    assert "# - path: src/old_file.py" in written
    assert "- path: src/still_needed.py" in written
