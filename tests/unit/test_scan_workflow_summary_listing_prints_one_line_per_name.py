# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan job's step summary lists the output directory without issuing commands.

Why this file exists
--------------------
The "Update step summary" step prints ``tree`` of the output directory. The
listing holds names the scanned repository chose: an extracted archive member keeps
the name it had in the archive. The runner reads a line as a workflow command when it
holds the legacy ``##[`` marker anywhere, and ``tree`` leaves printable markers alone,
so a member named ``##[warning]...`` issued a command of the repository's choosing.
Every other repository-influenced string in the workflow goes through ``one_line``;
the listing now does too, one line at a time.

What this asserts
-----------------
1. A listing that holds ``##[`` and ``::`` inside names prints no line the runner
   would read as a workflow command, and the names are still readable.
2. A listing without either keeps every line unchanged, including the tree glyphs.
3. The check can fail: the same cell run on the step with the listing printed raw
   finds the planted lines.

``tree`` is a stub that prints a fixed listing, so what runs is the step's own
pipeline. What it does not cover is ``tree``'s own escaping of control characters.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from tests.utils import github_actions as ga

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.name == "nt" or shutil.which("bash") is None,
        reason="the step under test is a bash step that runs on ubuntu-latest",
    ),
]

SCAN_WORKFLOW = ga.WORKFLOWS_DIR / "run-ash-security-scan.yml"
STEP_NAME = "Update step summary"
ASH_REPO = "awslabs/automated-security-helper"

#: The step's listing pipeline, as the workflow writes it. The mutant replaces it with
#: the raw `tree` call the step ran before.
LISTING_PIPELINE = (
    'tree "${ASH_OUTPUT_DIR}" | while IFS= read -r line || [ -n "${line}" ]; do\n'
    '  one_line "${line}"\n'
    "  printf '\\n'\n"
    "done"
)
RAW_LISTING = 'tree "${ASH_OUTPUT_DIR}"'

PLANTED = [
    "ash_output",
    "├── ##[warning]planted-legacy-marker",
    "├── name::error::planted-double-colon",
    "└── reports",
]
CLEAN = [
    "ash_output",
    "├── reports",
    "│   ├── ash.sarif",
    "│   └── ash.summary.md",
    "└── ash_aggregated_results.json",
]


def _workflow_and_job() -> tuple[ga.Workflow, dict[str, Any]]:
    workflow = ga.load_workflow(SCAN_WORKFLOW)
    return workflow, workflow.jobs["ash"]


def _step() -> dict[str, Any]:
    _, job = _workflow_and_job()
    found = [s for s in job.get("steps") or [] if s.get("name") == STEP_NAME]
    assert len(found) == 1, [s.get("name") for s in job.get("steps") or []]
    return found[0]


def _context() -> dict[str, Any]:
    context = ga.base_context(
        event_name="push",
        repository=ASH_REPO,
        repository_owner="awslabs",
        ref="refs/heads/main",
        event={"repository": {"default_branch": "main", "full_name": ASH_REPO}},
    )
    workflow, _ = _workflow_and_job()
    caller = {"with": {"ash-version": "main", "ash-repo": ASH_REPO}}
    return ga.with_inputs(context, ga.call_inputs(caller, workflow, context))


def _run(tmp_path: Path, listing: list[str], step: dict[str, Any]) -> ga.StepRun:
    workflow, job = _workflow_and_job()
    context = _context()
    sandbox = ga.StepSandbox(tmp_path / "runner")
    output_dir = context["steps"][ga.INPUT_CHECK_STEP_ID]["outputs"]["output_dir"]
    summary = sandbox.workspace / output_dir / "reports" / "ash.summary.md"
    summary.parent.mkdir(parents=True)
    summary.write_text("summary\n", encoding="utf-8")
    listing_file = tmp_path / "listing.txt"
    listing_file.write_text("\n".join(listing) + "\n", encoding="utf-8")
    tree = sandbox.stub_dir / "tree"
    tree.write_text(f'#!/bin/sh\nexec cat "{listing_file}"\n', encoding="utf-8")
    tree.chmod(0o755)
    return ga.run_step(sandbox, workflow, job, step, context)


class TestTheListingIsPrintedOneNameAtATime:
    def test_a_name_with_a_command_marker_issues_no_command(self, tmp_path):
        run = _run(tmp_path, PLANTED, _step())
        assert run.proc.returncode == 0, run.describe()
        assert ga.workflow_command_lines(run.proc.stdout, run.proc.stderr) == [], (
            run.describe()
        )
        # Neutralized, not dropped: the names are still readable.
        assert "planted-legacy-marker" in run.proc.stdout, run.describe()
        assert "planted-double-colon" in run.proc.stdout, run.describe()
        assert "##[" not in run.proc.stdout and "::" not in run.proc.stdout, (
            run.describe()
        )
        assert len(run.proc.stdout.splitlines()) == len(PLANTED), run.describe()

    def test_a_listing_without_markers_is_printed_unchanged(self, tmp_path):
        run = _run(tmp_path, CLEAN, _step())
        assert run.proc.returncode == 0, run.describe()
        assert run.proc.stdout.splitlines() == CLEAN, run.describe()

    def test_the_cell_finds_the_planted_lines_when_the_listing_is_raw(self, tmp_path):
        step = _step()
        assert LISTING_PIPELINE in step["run"], step["run"]
        mutant = {**step, "run": step["run"].replace(LISTING_PIPELINE, RAW_LISTING)}
        run = _run(tmp_path, PLANTED, mutant)
        assert run.proc.returncode == 0, run.describe()
        found = ga.workflow_command_lines(run.proc.stdout, run.proc.stderr)
        assert found == [PLANTED[1]], (found, run.describe())
