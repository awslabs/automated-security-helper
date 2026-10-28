# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The job and check-run counts written in ash-unified-ci.yml match its matrices.

Why this file exists
--------------------
The workflow's comments size its own cost from a job count: the note at the top of
the file prices a queued merge that also pushes to main, and the note on the
required-checks job breaks the count down per job and adds the junit check runs.
Those numbers are prose, so nothing failed when they went stale. When the
ubuntu-24.04-arm Homebrew leg was excluded, install-validation went from 33 legs to
32 and every figure stayed put, and the per-job list had already missed actionlint,
warm-image-layers, sandbox and sandbox-scanner-parity, which landed after the run the
chain is anchored on.

This expands each job's matrix the way GitHub does and holds the comments to it: the
per-job list names every job with its leg count, the totals are its sum, and the
pull-request figures leave out the jobs whose ``if`` runs them only on a push.

What it does not cover
----------------------
These are derived counts. GitHub's own job census for a run is the measurement, and
the comments say which link of the chain was measured. A job whose ``if`` depends on
something other than the event, such as required-checks' ``always()`` or a
``needs`` output, is counted as running.
"""

from __future__ import annotations

import itertools
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
UNIFIED_CI = WORKFLOWS / "ash-unified-ci.yml"
IAC_DRIFT = WORKFLOWS / "ash-iac-drift.yml"

#: The unit-test matrix is three jobs, one per runner pool, so each pool has its own
#: max-parallel cap. The workflow's comments count the three as one family, "unit-test",
#: which is also what every one of their check names starts with.
UNIT_TEST_JOB_IDS = ("unit-test-linux", "unit-test-macos", "unit-test-windows")


def _jobs(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]


def _cells(job: dict[str, Any]) -> list[dict[str, Any]]:
    """The jobs GitHub creates for one entry under ``jobs:``, as matrix cells.

    The axes' product, less the cells an ``exclude`` entry matches. An ``include``
    entry merges into every cell whose axis values it matches, adding none, and is a
    cell of its own only when it matches none (the matrix rules in GitHub's workflow
    syntax reference). A job with no matrix is one empty cell.
    """
    matrix = (job.get("strategy") or {}).get("matrix")
    if not matrix:
        return [{}]
    assert isinstance(matrix, dict), f"a matrix this test cannot expand: {matrix!r}"
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    for name, values in axes.items():
        assert isinstance(values, list), f"axis {name} is not a list: {values!r}"
    cells = (
        [dict(zip(axes, combo)) for combo in itertools.product(*axes.values())]
        if axes
        else []
    )
    for excluded in matrix.get("exclude") or []:
        cells = [
            c for c in cells if not all(c.get(k) == v for k, v in excluded.items())
        ]
    added = []
    for included in matrix.get("include") or []:
        matching = [
            cell
            for cell in cells
            if all(cell[k] == v for k, v in included.items() if k in axes)
        ]
        for cell in matching:
            cell.update(included)
        if not matching:
            added.append(dict(included))
    return cells + added


def _legs(job: dict[str, Any]) -> int:
    """How many jobs GitHub creates for one entry under ``jobs:``."""
    return len(_cells(job))


def _push_only(job: dict[str, Any]) -> bool:
    return "github.event_name == 'push'" in str(job.get("if", ""))


def _comment_text(path: Path) -> str:
    """The file's comment lines, unwrapped into one string."""
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            lines.append(stripped.lstrip("#").strip())
    return " ".join(lines)


def _one(pattern: str, text: str) -> re.Match:
    found = list(re.finditer(pattern, text))
    assert len(found) == 1, (
        f"expected exactly one comment matching {pattern!r} in {UNIFIED_CI.name}, "
        f"found {len(found)}"
    )
    return found[0]


JOBS = _jobs(UNIFIED_CI)
LEGS = {name: _legs(job) for name, job in JOBS.items()}
#: The legs of the whole unit-test family, which the old single job counted by itself.
#: Each leg publishes one `PyTest - ...` check run from inside the job
#: (mikepenz/action-junit-report), which is not a job of its own, so this is also the
#: number of those check runs.
UNIT_TEST_LEGS = sum(LEGS[name] for name in UNIT_TEST_JOB_IDS)
#: LEGS as the workflow's comments list it: the three unit-test jobs under one name.
COMMENT_LEGS = {
    **{name: n for name, n in LEGS.items() if name not in UNIT_TEST_JOB_IDS},
    "unit-test": UNIT_TEST_LEGS,
}
ON_PUSH = sum(LEGS.values())
ON_PULL_REQUEST = sum(n for name, n in LEGS.items() if not _push_only(JOBS[name]))
COMMENTS = _comment_text(UNIFIED_CI)


class TestTheExpansion:
    """Positive controls: the counter gives the counts these jobs plainly have."""

    def test_a_job_without_a_matrix_is_one_job(self):
        assert LEGS["lint"] == 1

    def test_an_axis_product_less_its_excludes(self):
        # 25 OS and Python combinations, each split into 8 shards (tests/unit/test_unit_test_shards.py
        # holds the shard axis itself to one list of eight), cut into three jobs by OS:
        # 2 Linux and 2 macOS images and 1 Windows image, each on 5 Python versions.
        assert LEGS["unit-test-linux"] == 2 * 5 * 8
        assert LEGS["unit-test-macos"] == 2 * 5 * 8
        assert LEGS["unit-test-windows"] == 1 * 5 * 8
        assert UNIT_TEST_LEGS == 25 * 8

    def test_no_matrix_is_past_githubs_limit_of_256_jobs(self):
        """GitHub rejects the workflow, not just the leg, past 256 jobs from one matrix.

        The limit applies to each matrix, and the unit-test matrix is three of them. As
        one job it was the closest, at 200 legs; its largest part is now 80, and the
        family as a whole is still 200.
        """
        too_big = {name: legs for name, legs in LEGS.items() if legs > 256}
        assert not too_big, too_big
        assert max(LEGS[name] for name in UNIT_TEST_JOB_IDS) <= 256

    def test_an_include_that_merges_adds_no_cell(self):
        job = {
            "strategy": {
                "matrix": {
                    "os": ["a", "b"],
                    "include": [{"os": "a", "extra": 1}, {"os": "c"}],
                }
            }
        }
        assert _legs(job) == 3

    def test_only_warm_image_layers_waits_for_a_push(self):
        assert [name for name, job in JOBS.items() if _push_only(job)] == [
            "warm-image-layers"
        ]


class TestTheCommentsMatchTheWorkflow:
    def test_the_per_job_list_names_every_job_with_its_legs(self):
        match = _one(
            r"Where (\d+) comes from, per job, on a push to main: (.+?)\.", COMMENTS
        )
        listed = {
            name: int(count)
            for name, count in re.findall(r"([a-z][a-z0-9-]*) (\d+)", match.group(2))
        }

        # The comment names the three unit-test jobs as the one family they split.
        assert listed == COMMENT_LEGS
        assert int(match.group(1)) == ON_PUSH

    def test_the_cost_note_prices_both_runs_of_a_queued_merge(self):
        match = _one(
            r"this workflow expands to (\d+) jobs on a push to main and (\d+) on a "
            r"pull request or a merge-queue run, where warm-image-layers does not run, "
            r"and ash-iac-drift\.yml to (\d+), so a queued merge that also pushes to "
            r"main is ~(\d+) runner jobs instead of ~(\d+)\.",
            COMMENTS,
        )
        on_push, on_queue, iac, both, queue_only = map(int, match.groups())
        iac_jobs = len(_jobs(IAC_DRIFT))

        assert (on_push, on_queue, iac) == (ON_PUSH, ON_PULL_REQUEST, iac_jobs)
        assert both == ON_PUSH + ON_PULL_REQUEST + 2 * iac_jobs
        assert queue_only == ON_PULL_REQUEST + iac_jobs

    def test_the_check_run_note_adds_the_junit_runs_to_the_jobs(self):
        match = _one(
            r"(\d+) is this workflow's own contribution to a pull request: the (\d+) "
            r"jobs that run there, plus the (\d+) `PyTest - \.\.\.` check runs",
            COMMENTS,
        )
        check_runs, jobs, junit = map(int, match.groups())

        assert (jobs, junit) == (ON_PULL_REQUEST, UNIT_TEST_LEGS)
        assert check_runs == jobs + junit
        assert re.search(
            rf"this workflow contributes {check_runs} check runs to a pull request",
            COMMENTS,
        )

    def test_the_install_legs_outside_bundle_are_counted_right(self):
        """homebrew and the three container runtimes are their own legs; the
        comment on the method axis counts them, and it said 8 after the
        ubuntu-24.04-arm homebrew leg was excluded and there were 7."""
        match = _one(r"they are (\d+) legs in total \(([^)]*)\)", COMMENTS)
        own_legs = [
            cell
            for cell in _cells(JOBS["install-validation"])
            if cell["method"] != "bundle"
        ]
        per_method = {
            method: int(count)
            for method, count in re.findall(r"([a-z]+) (\d+)", match.group(2))
        }

        assert int(match.group(1)) == len(own_legs)
        # The figures in the parentheses too, not only their total.
        assert per_method == dict(Counter(cell["method"] for cell in own_legs))

    def test_no_comment_still_states_a_superseded_total(self):
        """The figures this file replaced, so a merge that brings one back is seen."""
        for stale in ("expands to 92 jobs", "contributes 117 check", "117 is this"):
            assert stale not in COMMENTS
