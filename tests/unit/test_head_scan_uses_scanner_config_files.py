# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The informational head scan passes the same scanner config files as the gating scan.

A config file inside the scanned tree no longer chooses a scanner's own config
file, so a caller that omits ``ash-args`` runs bandit without ``.ash/bandit.yaml``
and grype without ``.ash/.grype.yaml``. Without the bandit file the test suite's
asserts are reported by the thousands and the report phase outgrows every
timeout. Both callers must carry the same two overrides so they cannot drift
apart again.
"""

from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
GATING = WORKFLOWS / "ash-repo-scan.yml"
HEAD = WORKFLOWS / "ash-repo-scan-pr-head.yml"

OVERRIDES = (
    "scanners.bandit.options.config_file=.ash/bandit.yaml",
    "scanners.grype.options.config_file=.ash/.grype.yaml",
)


def _ash_args(workflow: Path) -> str:
    doc: Dict[str, Any] = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    calls = [
        job["with"]
        for job in doc["jobs"].values()
        if str(job.get("uses", "")).endswith("run-ash-security-scan.yml")
    ]
    assert len(calls) == 1, f"{workflow.name} has {len(calls)} calls of the scan"
    return str(calls[0].get("ash-args", ""))


@pytest.mark.parametrize("workflow", [GATING, HEAD], ids=lambda path: path.name)
def test_both_scan_callers_pass_the_scanner_config_files(workflow: Path) -> None:
    ash_args = _ash_args(workflow)

    for override in OVERRIDES:
        assert override in ash_args, f"{workflow.name} does not pass {override}"
