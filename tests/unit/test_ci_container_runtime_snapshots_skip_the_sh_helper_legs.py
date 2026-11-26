# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The container-runtime snapshot step does not rerun on the sh-helper legs.

``utils/ash_helpers.sh``'s ``invoke-ash`` runs ``ashx --mode container``. The
sh-helper legs of the scan matrix exist to run that forwarding end to end, and the
container-runtime snapshot modules (``tests/snapshot/container/runtime``) never source
the helper, so on those legs the step repeats what the ``python-container`` leg with
the same OS and runner already compared, at the cost of the leg's runtime on every
pull request, merge-queue run and push. (The ``bash`` method that drove the root
``ash`` script was the counterpart until that script was removed; every ``bash`` cell
had a ``python-container`` cell on the same OS and runner, and that leg runs the same
``ashx --mode container`` the helper runs.)

Two things are pinned: the step's condition excludes ``sh-helper``, and every
``sh-helper`` row has a ``python-container`` row with the same OS and OCI runner, so
the runtime output the step compares is still compared for each runner the helper is
used with.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIFIED_CI = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
RUN_SCAN_TEST = REPO_ROOT / ".github" / "actions" / "run-scan-test" / "action.yml"
SNAPSHOT_STEP = "Snapshot the container-runtime output"
SCAN_ACTION = "./.github/actions/run-scan-test"


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _scan_matrix_rows() -> list[dict[str, Any]]:
    jobs = _load(UNIFIED_CI)["jobs"]
    rows = [
        job["strategy"]["matrix"]["include"]
        for job in jobs.values()
        if any(step.get("uses") == SCAN_ACTION for step in job.get("steps", []))
    ]
    assert len(rows) == 1, (
        f"expected one job that uses {SCAN_ACTION}, found {len(rows)}"
    )
    return rows[0]


def _snapshot_condition() -> str:
    steps = _load(RUN_SCAN_TEST)["runs"]["steps"]
    named = [step for step in steps if step.get("name") == SNAPSHOT_STEP]
    assert len(named) == 1, f"expected one step named {SNAPSHOT_STEP!r}"
    return str(named[0]["if"])


def test_the_snapshot_step_is_not_run_by_the_sh_helper_method():
    condition = _snapshot_condition()
    assert "inputs.method != 'sh-helper'" in condition, condition
    # The legs the step is for stay in: only python-local and sh-helper are excluded.
    assert "inputs.method != 'python-local'" in condition, condition
    assert "!cancelled()" in condition, condition
    assert "||" not in condition, condition


def test_every_sh_helper_row_has_a_python_container_row_on_the_same_os_and_runner():
    rows = _scan_matrix_rows()
    python_container = {
        (row["os"], row.get("oci-runner"))
        for row in rows
        if row["method"] == "python-container"
    }
    sh_helper = {
        (row["os"], row.get("oci-runner"))
        for row in rows
        if row["method"] == "sh-helper"
    }
    assert sh_helper, "the matrix has no sh-helper row; this guard has nothing to check"
    assert sh_helper <= python_container, (
        "an sh-helper row whose OS and runner no python-container row covers would "
        "lose its container-runtime snapshot comparison: "
        f"{sorted(sh_helper - python_container)}"
    )
