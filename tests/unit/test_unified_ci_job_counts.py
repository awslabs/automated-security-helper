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
merge-queue figures leave out the jobs whose ``if`` runs them only on a push.

The pull-request figures are smaller still. Several matrices carry an ``exclude``
overlay whose entries are ``${{ github.event_name == 'pull_request' && '<value>' || ''
}}``: on a pull request the entry is the value and drops the combinations it matches, on
every other event it is the empty string and matches no combination (the note on
ensure-cache in the workflow). ``_cells`` resolves that overlay for the event it is asked about, so the push
and merge-queue counts read the static axes as before and the pull-request counts read
the cover that actually runs there.

What it does not cover
----------------------
These are derived counts. GitHub's own job census for a run is the measurement, and
the comments say which link of the chain was measured. A job whose ``if`` depends on
something other than the event, such as required-checks' ``always()`` or a
``needs`` output, is counted as running. Whether GitHub evaluates the overlay the way
this file does is a property of the hosted run, not of this file; if it did not, the
string would match no combination and the full matrix would run, so the failure
direction is a slower pull request rather than a missing leg.
"""

from __future__ import annotations

import itertools
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.utils.ci_tiers import (
    E2E_TEST_JOB_IDS,
    INTEGRATION_TEST_JOB_IDS,
    UNIT_TEST_JOB_IDS,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
UNIFIED_CI = WORKFLOWS / "ash-unified-ci.yml"
IAC_DRIFT = WORKFLOWS / "ash-iac-drift.yml"

RUN_UNIT_TESTS_USES = "./.github/actions/run-unit-tests"


def _jobs(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]


#: The one shape of event-conditioned matrix entry this workflow uses: the value on a
#: pull request, the empty string (matching no combination) on every other event.
PULL_REQUEST_OVERLAY = re.compile(
    r"^\$\{\{ github\.event_name == 'pull_request' && '([^']*)' \|\| '' \}\}$"
)


def _resolve(value: Any, event: str) -> Any:
    """The value a matrix entry has under ``event``; None when the entry is void.

    A plain value is itself on every event. The overlay expression is its quoted value
    on a pull request and void everywhere else, because GitHub evaluates it to '' there
    and no combination has an empty axis value.
    """
    if isinstance(value, str):
        match = PULL_REQUEST_OVERLAY.match(value)
        if match:
            return match.group(1) if event == "pull_request" else None
    return value


def _cells(job: dict[str, Any], event: str = "push") -> list[dict[str, Any]]:
    """The jobs GitHub creates for one entry under ``jobs:``, as matrix cells.

    The axes' product, less the cells an ``exclude`` entry matches. An ``include``
    entry merges into every cell whose axis values it matches, adding none, and is a
    cell of its own only when it matches none (the matrix rules in GitHub's workflow
    syntax reference). A job with no matrix is one empty cell. Exclude entries are
    resolved for ``event`` first (see ``_resolve``); an entry with a void value matches
    nothing, which is what the empty string does on GitHub.
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
        resolved = {k: _resolve(v, event) for k, v in excluded.items()}
        if any(v is None for v in resolved.values()):
            continue
        cells = [
            c for c in cells if not all(c.get(k) == v for k, v in resolved.items())
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


def _legs(job: dict[str, Any], event: str = "push") -> int:
    """How many jobs GitHub creates for one entry under ``jobs:`` on ``event``."""
    return len(_cells(job, event))


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
UNIT_TEST_LEGS = sum(LEGS[name] for name in UNIT_TEST_JOB_IDS)
#: Every job that calls run-unit-tests, whatever its tier. Each of their legs publishes
#: one `PyTest - ...` check run from inside the job (mikepenz/action-junit-report), which
#: is not a job of its own, so the legs of these jobs are also the number of those check
#: runs. Found from the steps, so a tier job added later is counted without an edit here.
PYTEST_JOB_IDS = [
    name
    for name, job in JOBS.items()
    if any(step.get("uses") == RUN_UNIT_TESTS_USES for step in job.get("steps") or [])
]
PYTEST_CHECK_RUNS = sum(LEGS[name] for name in PYTEST_JOB_IDS)
#: LEGS as the workflow's comments list it: the three unit-test jobs under one name.
COMMENT_LEGS = {
    **{name: n for name, n in LEGS.items() if name not in UNIT_TEST_JOB_IDS},
    "unit-test": UNIT_TEST_LEGS,
}
ON_PUSH = sum(LEGS.values())
#: A merge_group run: the static matrices less the push-only jobs.
ON_MERGE_QUEUE = sum(n for name, n in LEGS.items() if not _push_only(JOBS[name]))
#: A pull_request run: the overlay resolved, the push-only jobs left out.
PR_LEGS = {
    name: _legs(job, "pull_request")
    for name, job in JOBS.items()
    if not _push_only(job)
}
PR_COMMENT_LEGS = {
    **{name: n for name, n in PR_LEGS.items() if name not in UNIT_TEST_JOB_IDS},
    "unit-test": sum(PR_LEGS[name] for name in UNIT_TEST_JOB_IDS),
}
ON_PULL_REQUEST = sum(PR_LEGS.values())
PR_PYTEST_CHECK_RUNS = sum(PR_LEGS[name] for name in PYTEST_JOB_IDS)
COMMENTS = _comment_text(UNIFIED_CI)


class TestTheExpansion:
    """Positive controls: the counter gives the counts these jobs plainly have."""

    def test_a_job_without_a_matrix_is_one_job(self):
        assert LEGS["lint"] == 1

    def test_an_axis_product_less_its_excludes(self):
        # 25 OS and Python combinations, cut into three jobs by OS: 2 Linux and 2 macOS
        # images and 1 Windows image, each on 5 Python versions. The unit and the
        # integration tier split each combination into 4 shards
        # (tests/unit/test_unit_test_shards.py holds that axis itself to one list of
        # four); the e2e tier runs once per image, on one Python version.
        assert LEGS["unit-test-linux"] == 2 * 5 * 4
        assert LEGS["unit-test-macos"] == 2 * 5 * 4
        assert LEGS["unit-test-windows"] == 1 * 5 * 4
        assert UNIT_TEST_LEGS == 100
        assert LEGS["integration-test-linux"] == 2 * 5 * 4
        assert LEGS["integration-test-macos"] == 2 * 5 * 4
        assert LEGS["integration-test-windows"] == 1 * 5 * 4
        assert sum(LEGS[name] for name in INTEGRATION_TEST_JOB_IDS) == 25 * 4
        assert [LEGS[name] for name in E2E_TEST_JOB_IDS] == [2, 2, 1]

    def test_the_jobs_that_publish_a_pytest_check_run_are_the_three_tiers(self):
        """The check-run note counts one run per leg of every job that calls the action."""
        assert sorted(PYTEST_JOB_IDS) == sorted(
            [*UNIT_TEST_JOB_IDS, *INTEGRATION_TEST_JOB_IDS, *E2E_TEST_JOB_IDS]
        ), PYTEST_JOB_IDS
        assert PYTEST_CHECK_RUNS == 100 + 100 + 5

    def test_no_matrix_is_past_githubs_limit_of_256_jobs(self):
        """GitHub rejects the workflow, not just the leg, past 256 jobs from one matrix.

        The limit applies to each matrix. The unit-test matrix was the closest, at 200
        legs as one job; the tiers are nine matrices now and the largest is 40.
        """
        too_big = {name: legs for name, legs in LEGS.items() if legs > 256}
        assert not too_big, too_big
        assert max(LEGS[name] for name in PYTEST_JOB_IDS) <= 256

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


#: What a pull request keeps of each pool: the arm64 Linux image, the pinned macOS
#: image, the one Windows image, and the lowest, the coverage-gated and the highest
#: Python. The saturated hosted labels (ubuntu-latest, macos-latest) and Python 3.11 and
#: 3.13 run on the merge-queue entry and on the push to main instead. When GitHub retires
#: macos-15, the workflow's five entries and this set move to macos-latest together.
PR_COVER_IMAGES = {"ubuntu-24.04-arm", "macos-15", "windows-latest"}
#: The pull-request image unit-coverage cannot gate: its axis names macos-latest and no
#: pinned macOS image, so a pull request runs no macOS coverage gate (the note on
#: ensure-cache in the workflow; the merge-queue entry and the push run it).
PR_IMAGES_WITHOUT_A_COVERAGE_GATE = {"macos-15"}
PR_COVER_PYTHONS = {"3.10", "3.12", "3.14"}
TIER_JOB_IDS = [*UNIT_TEST_JOB_IDS, *INTEGRATION_TEST_JOB_IDS, *E2E_TEST_JOB_IDS]


class TestThePullRequestCover:
    """The overlay thins a pull request to one leg per pool and leaves every other event whole."""

    def test_the_overlay_resolves_for_a_pull_request_and_is_void_elsewhere(self):
        """Positive control on `_resolve`: the one shape the workflow uses."""
        expr = "${{ github.event_name == 'pull_request' && 'ubuntu-latest' || '' }}"
        assert _resolve(expr, "pull_request") == "ubuntu-latest"
        assert _resolve(expr, "push") is None
        assert _resolve(expr, "merge_group") is None
        assert _resolve("ubuntu-latest", "pull_request") == "ubuntu-latest"
        assert _resolve("${{ matrix.os }}", "pull_request") == "${{ matrix.os }}"

    def test_the_overlay_drops_cells_only_on_a_pull_request(self):
        """Positive control on `_cells`: an event-conditioned exclude thins one event."""
        job = {
            "strategy": {
                "matrix": {
                    "os": ["a", "b"],
                    "exclude": [
                        {
                            "os": "${{ github.event_name == 'pull_request' && 'a' || '' }}"
                        }
                    ],
                }
            }
        }
        assert _legs(job, "push") == 2
        assert _legs(job, "merge_group") == 2
        assert _legs(job, "pull_request") == 1
        assert _cells(job, "pull_request") == [{"os": "b"}]

    def test_every_overlay_entry_in_the_workflow_has_the_one_shape(self):
        """An exclude value with an expression is either the overlay or a defect."""
        for name, job in JOBS.items():
            matrix = (job.get("strategy") or {}).get("matrix") or {}
            for entry in matrix.get("exclude") or []:
                for key, value in entry.items():
                    if isinstance(value, str) and "${{" in value:
                        assert PULL_REQUEST_OVERLAY.match(value), (name, key, value)

    def test_the_static_matrices_run_whole_on_a_push_and_in_the_merge_queue(self):
        """The overlay is void off a pull request, so those counts read the static axes."""
        for name, job in JOBS.items():
            assert _legs(job, "merge_group") == LEGS[name], name
            assert _legs(job, "workflow_dispatch") == LEGS[name], name

    @pytest.mark.parametrize("job_id", TIER_JOB_IDS)
    def test_a_tier_job_keeps_one_image_per_pool_on_a_pull_request(self, job_id):
        cells = _cells(JOBS[job_id], "pull_request")
        assert cells, job_id
        images = {c["os"] for c in cells}
        assert images <= PR_COVER_IMAGES, (job_id, images)
        assert len(images) == 1, (job_id, images)
        pythons = {str(c["python-version"]) for c in cells if "python-version" in c}
        assert pythons in ({*PR_COVER_PYTHONS}, set()), (job_id, pythons)
        # The shard axis is untouched: every shard of a kept combination still runs.
        shards = {c["shard"] for c in cells if "shard" in c}
        assert shards == {
            str(s) for s in JOBS[job_id]["strategy"]["matrix"].get("shard", [])
        }

    def test_the_pull_request_tiers_add_up(self):
        assert sum(PR_LEGS[n] for n in UNIT_TEST_JOB_IDS) == 3 * 3 * 4
        assert sum(PR_LEGS[n] for n in INTEGRATION_TEST_JOB_IDS) == 3 * 3 * 4
        assert [PR_LEGS[n] for n in E2E_TEST_JOB_IDS] == [1, 1, 1]
        assert PR_PYTEST_CHECK_RUNS == 36 + 36 + 3

    def test_ensure_cache_runs_on_the_two_labels_with_headroom_on_a_pull_request(self):
        """The fan-out waits for this job, so on a pull request it must not touch a saturated label."""
        images = {c["os"] for c in _cells(JOBS["ensure-cache"], "pull_request")}
        assert images == {"ubuntu-24.04-arm", "windows-latest"}
        # Every pull-request leg of a tier still runs on an image the job covers, or on
        # macos-15, which reads main's cache instead (the note on ensure-cache).
        tier_images = {
            c["os"] for j in TIER_JOB_IDS for c in _cells(JOBS[j], "pull_request")
        }
        assert tier_images - images == {"macos-15"}, tier_images

    def test_unit_coverage_gates_the_pull_request_images_its_axis_names(self):
        """The gate runs where it has shards to combine; macos-15 is the one image it lacks.

        A unit-coverage leg on an image the unit tier did not run there would find no
        artifacts and fail; a unit-tier image the gate's axis does not name goes ungated
        on a pull request, which is the recorded cost of the macos-15 cover.
        """
        gated = {c["os"] for c in _cells(JOBS["unit-coverage"], "pull_request")}
        tested = {
            c["os"] for j in UNIT_TEST_JOB_IDS for c in _cells(JOBS[j], "pull_request")
        }
        assert gated <= tested, (gated, tested)
        assert tested - gated == PR_IMAGES_WITHOUT_A_COVERAGE_GATE, (gated, tested)
        axis = set(JOBS["unit-coverage"]["strategy"]["matrix"]["os"])
        assert not (PR_IMAGES_WITHOUT_A_COVERAGE_GATE & axis), (
            "the gate's axis names the image, so the gate could run there"
        )
        # 3.12 stays in every pool's cover because this job combines its data.
        for job_id in UNIT_TEST_JOB_IDS:
            pythons = {
                str(c["python-version"]) for c in _cells(JOBS[job_id], "pull_request")
            }
            assert "3.12" in pythons, job_id

    def test_install_validation_keeps_its_container_legs_on_a_pull_request(self):
        cells = _cells(JOBS["install-validation"], "pull_request")
        by_method = Counter(c["method"] for c in cells)
        full = Counter(c["method"] for c in _cells(JOBS["install-validation"], "push"))
        # The x86-only container runtimes are not thinned.
        for method in ("podman", "finch", "nerdctl"):
            assert by_method[method] == full[method], (method, by_method, full)
        # The bundle keeps one leg per pool on the three cover Pythons.
        bundle = [c for c in cells if c["method"] == "bundle"]
        assert {c["os"] for c in bundle} == PR_COVER_IMAGES
        assert {str(c["python-version"]) for c in bundle} == PR_COVER_PYTHONS
        assert len(bundle) == 9
        # Homebrew on macOS still runs here on macos-15 (and in homebrew-macos).
        assert [c["os"] for c in cells if c["method"] == "homebrew"] == ["macos-15"]
        assert PR_LEGS["install-validation"] == 14

    def test_the_pull_request_total_is_smaller_than_the_merge_queue_total(self):
        assert ON_PULL_REQUEST < ON_MERGE_QUEUE < ON_PUSH
        assert ON_PUSH - ON_MERGE_QUEUE == LEGS["warm-image-layers"]


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

    def test_the_per_job_list_for_a_pull_request_names_every_job_that_runs_there(self):
        match = _one(
            r"Where (\d+) comes from, per job, on a pull request \(the pull-request "
            r"cover, the note on ensure-cache\): (.+?)\. warm-image-layers is push-only",
            COMMENTS,
        )
        listed = {
            name: int(count)
            for name, count in re.findall(r"([a-z][a-z0-9-]*) (\d+)", match.group(2))
        }

        assert listed == PR_COMMENT_LEGS
        assert int(match.group(1)) == ON_PULL_REQUEST

    def test_the_cost_note_prices_both_runs_of_a_queued_merge(self):
        match = _one(
            r"this workflow expands to (\d+) jobs on a push to main, (\d+) on a "
            r"merge-queue run, where warm-image-layers does not run, and (\d+) on a "
            r"pull request, where the matrices run the pull-request cover \(the note on "
            r"ensure-cache\), and ash-iac-drift\.yml to (\d+), so a queued merge that "
            r"also pushes to main is ~(\d+) runner jobs instead of ~(\d+)\.",
            COMMENTS,
        )
        on_push, on_queue, on_pr, iac, both, queue_only = map(int, match.groups())
        iac_jobs = len(_jobs(IAC_DRIFT))

        assert (on_push, on_queue, on_pr, iac) == (
            ON_PUSH,
            ON_MERGE_QUEUE,
            ON_PULL_REQUEST,
            iac_jobs,
        )
        assert both == ON_PUSH + ON_MERGE_QUEUE + 2 * iac_jobs
        assert queue_only == ON_MERGE_QUEUE + iac_jobs

    def test_the_check_run_note_adds_the_junit_runs_to_the_jobs(self):
        match = _one(
            r"(\d+) is this workflow's own contribution to a pull request: the (\d+) "
            r"jobs that run there, plus the (\d+) `PyTest - \.\.\.` check runs",
            COMMENTS,
        )
        check_runs, jobs, junit = map(int, match.groups())

        assert (jobs, junit) == (ON_PULL_REQUEST, PR_PYTEST_CHECK_RUNS)
        assert check_runs == jobs + junit
        assert re.search(
            rf"this workflow contributes {check_runs} check runs to a pull request "
            rf"\({ON_MERGE_QUEUE + PYTEST_CHECK_RUNS} to a merge-queue run",
            COMMENTS,
        )

    def test_the_check_run_note_prices_the_merge_queue_run_too(self):
        match = _one(
            r"A merge-queue run, which runs the full matrices, is (\d+): the (\d+) jobs "
            r"that run there plus (\d+) check runs",
            COMMENTS,
        )
        check_runs, jobs, junit = map(int, match.groups())
        assert (jobs, junit) == (ON_MERGE_QUEUE, PYTEST_CHECK_RUNS)
        assert check_runs == jobs + junit
        assert re.search(
            rf"the {check_runs} above is the current merge-queue figure and "
            rf"{ON_PULL_REQUEST + PR_PYTEST_CHECK_RUNS} the pull-request one",
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
        for stale in (
            "expands to 92 jobs",
            "contributes 117 check",
            "117 is this",
            "expands to 280 jobs",
            "contributes 478 check",
            "478 is this",
            "expands to 286 jobs",
            "contributes 484 check",
            "484 is this",
            "expands to 316 jobs",
            "contributes 544 check",
            "544 is this",
            # Before the pull-request cover, a pull request ran the merge-queue shape.
            "214 on a pull request",
            "contributes 344 check",
            "344 is this",
            # Before the unit tier was cut into four shards.
            "expands to 216 jobs",
            "contributes 158 check",
            "158 is this",
            # Before the cover's macOS image moved to macOS 14 (unit-coverage -1).
            "137 on a pull request",
            "contributes 212 check",
            "212 is this",
        ):
            assert stale not in COMMENTS


SETUP_ASH = "./.github/actions/setup-ash"
ENSURE_CACHE = "ensure-cache"
SETUP_ASH_ACTION = REPO_ROOT / ".github" / "actions" / "setup-ash" / "action.yml"
RUN_UNIT_TESTS_ACTION = (
    REPO_ROOT / ".github" / "actions" / "run-unit-tests" / "action.yml"
)
#: Jobs that call setup-ash and do not wait for ensure-cache, each with the reason. The
#: test below fails when an entry is no longer true, so the list cannot become stale.
NOT_WAITING = {
    "warm-image-layers": (
        "push-only, off the critical path of its own cache, and its image layer cache "
        "is a different cache with its own one-writer concurrency group"
    ),
}


def _setup_ash_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        step
        for step in job.get("steps") or []
        if str(step.get("uses", "")).startswith(SETUP_ASH)
    ]


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def _runner_images(job: dict[str, Any]) -> set[str]:
    """The runner images a job runs on: its os axis, or the literal runs-on."""
    runs_on = str(job["runs-on"])
    if "matrix.os" in runs_on:
        return {entry["os"] for entry in _cells(job)}
    return {runs_on}


SETUP_ASH_CALLERS = [
    name for name, job in JOBS.items() if name != ENSURE_CACHE and _setup_ash_steps(job)
]


class TestEnsureCache:
    """The one job that writes the uv cache, and the jobs that only read it.

    The legs are derived from the callers, not typed twice: the key setup-uv builds is the
    runner image plus a hash of the dependency files, so there is one leg for each distinct
    image any setup-ash caller runs on.
    """

    def test_the_callers_are_found(self):
        # Positive control: a scan that found none would pass every test below.
        assert len(SETUP_ASH_CALLERS) >= 10, SETUP_ASH_CALLERS

    def test_it_has_one_leg_per_runner_image_the_callers_use(self):
        images = set().union(*(_runner_images(JOBS[n]) for n in SETUP_ASH_CALLERS))
        job = JOBS[ENSURE_CACHE]
        matrix = job["strategy"]["matrix"]
        axes = [k for k in matrix if k not in ("include", "exclude")]
        assert axes == ["os"], "a second axis would write a key twice"
        assert "include" not in matrix, (
            "an include would add a leg the callers do not use"
        )
        assert sorted(matrix["os"]) == sorted(images)
        assert LEGS[ENSURE_CACHE] == len(images)
        assert job["strategy"]["max-parallel"] == len(images)

    def test_every_caller_waits_for_it_except_the_named_ones(self):
        for name in SETUP_ASH_CALLERS:
            waits = ENSURE_CACHE in _needs(JOBS[name])
            assert waits == (name not in NOT_WAITING), (
                f"{name}: waits={waits}; NOT_WAITING names {sorted(NOT_WAITING)}"
            )
        assert set(NOT_WAITING) <= set(SETUP_ASH_CALLERS), "a stale NOT_WAITING entry"

    def test_it_runs_on_every_event_and_reads_only_the_repository(self):
        job = JOBS[ENSURE_CACHE]
        assert "if" not in job, "a skipped ensure-cache would skip its dependents"
        assert "needs" not in job
        assert "continue-on-error" not in job
        assert job["permissions"] == {"contents": "read"}
        assert job["strategy"]["fail-fast"] is False
        assert job["timeout-minutes"] == 15

    def test_the_gate_waits_for_it(self):
        assert ENSURE_CACHE in _needs(JOBS["required-checks"])

    def test_only_it_asks_setup_ash_to_save(self):
        savers = {
            name: step["with"]["save-cache"]
            for name, job in JOBS.items()
            for step in _setup_ash_steps(job)
            if "save-cache" in (step.get("with") or {})
        }
        assert savers == {ENSURE_CACHE: "true"}

    def test_setup_ash_restores_only_unless_asked(self):
        action = yaml.safe_load(SETUP_ASH_ACTION.read_text(encoding="utf-8"))
        assert action["inputs"]["save-cache"]["default"] == "false"
        uv = [s for s in action["runs"]["steps"] if s.get("id") == "setup-uv"]
        assert len(uv) == 1
        assert uv[0]["with"]["enable-cache"] is True
        assert uv[0]["with"]["save-cache"] == "${{ inputs.save-cache }}"

    def test_it_syncs_the_unit_test_extras_and_leaves_ash_out(self):
        unit = yaml.safe_load(RUN_UNIT_TESTS_ACTION.read_text(encoding="utf-8"))
        unit_syncs = [
            str(s["run"])
            for s in unit["runs"]["steps"]
            if str(s.get("run", "")).strip().startswith("uv sync")
        ]
        assert len(unit_syncs) == 1, unit_syncs
        ensure_syncs = [
            str(s["run"])
            for s in JOBS[ENSURE_CACHE]["steps"]
            if "uv sync" in str(s.get("run", ""))
        ]
        assert len(ensure_syncs) == 1, ensure_syncs
        ensure_extras = sorted(re.findall(r"--extra (\S+)", ensure_syncs[0]))
        unit_extras = sorted(re.findall(r"--extra (\S+)", unit_syncs[0]))
        assert ensure_extras == unit_extras
        assert unit_extras, "the unit-test sync installs no extras to compare"
        assert "--no-install-project" in ensure_syncs[0]
        assert "--frozen" in ensure_syncs[0]
