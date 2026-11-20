#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The verdict of a workflow's one aggregate gate job, censused against the workflow.

    NEEDS_JSON='${{ toJSON(needs) }}' assert-workflow-gate.py --workflow FILE --gate-job NAME
    assert-workflow-gate.py --workflow FILE --gate-job NAME --self-test

WHY THIS EXISTS
---------------
A workflow with a matrix has no single check name a ruleset can require: every leg's
name is its matrix label, and a label that changes leaves the old name required and
never reported. A gate job that `needs` every other job and fails unless all of them
succeeded is the one stable name. It speaks only for the jobs in its `needs`, so a job
added to the workflow and not to `needs` escapes the gate while the gate stays green.

The census is the workflow's own `jobs:` mapping read off disk, with the dependency-free
scanner in assert-required-checks-census.py (cross-checked against PyYAML by
tests/unit/test_required_checks_census.py), the pattern ash-e2e.yml's "e2e: gate" uses.
That script's own command line is not reused: its exemption list names a job of
ash-unified-ci.yml and reports that entry stale for any other workflow.

THE VERDICT
-----------
Exit 0 only when every job but the gate is in `needs` and every `needs` entry is a job
of the workflow whose result is `success`. `skipped` is a failure: a job that never ran
must not read as a pass, and every job in the workflows this gates runs on every run.
Exit 1 with one `::error::` line per problem otherwise; exit 2 when the inputs cannot be
read (no NEEDS_JSON, an empty census, a gate job the workflow does not have).

--self-test runs the verdict over the real workflow with planted `needs` and requires
each wrong one rejected: a failed job, a skipped one, a cancelled one, a job left out
of `needs`, and a `needs` entry naming no job. It also requires the all-success set to
pass, so a verdict that rejects everything cannot pass its own test.

Standard library only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Dict, List

CENSUS_SCRIPT = Path(__file__).resolve().parent / "assert-required-checks-census.py"


class InputError(Exception):
    """The inputs cannot be judged; the message says why."""


def _census_module():
    spec = importlib.util.spec_from_file_location(
        "ash_required_checks_census", CENSUS_SCRIPT
    )
    if spec is None or spec.loader is None:
        raise InputError(f"cannot load {CENSUS_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gated_jobs(workflow_text: str, gate_job: str) -> List[str]:
    names = _census_module().workflow_job_names(workflow_text)
    if not names:
        raise InputError(
            "the workflow's job census is empty, and an empty census passes every check "
            "vacuously; the scanner or the path is wrong"
        )
    if gate_job not in names:
        raise InputError(f"the workflow has no job {gate_job!r}; its jobs are {names}")
    jobs = [name for name in names if name != gate_job]
    if not jobs:
        raise InputError(f"{gate_job} is the workflow's only job, so it gates nothing")
    return jobs


def problems(jobs: List[str], needs: Dict[str, dict]) -> List[str]:
    found: List[str] = []
    for name in sorted(set(jobs) - set(needs)):
        found.append(
            f"job {name} is not in the gate's needs, so the gate would pass without it"
        )
    for name in sorted(set(needs) - set(jobs)):
        found.append(f"the gate needs {name}, which is not a job of this workflow")
    for name in sorted(set(needs) & set(jobs)):
        result = (needs[name] or {}).get("result")
        if result != "success":
            found.append(f"{name} is {result}")
    return found


def load_needs(raw: str | None) -> Dict[str, dict]:
    if raw is None or not raw.strip():
        raise InputError(
            "NEEDS_JSON is unset or empty; pass ${{ toJSON(needs) }}, or this would "
            "judge nothing"
        )
    try:
        needs = json.loads(raw)
    except json.JSONDecodeError as err:
        raise InputError(f"NEEDS_JSON is not JSON: {err}") from err
    if not isinstance(needs, dict):
        raise InputError(f"NEEDS_JSON is a {type(needs).__name__}, not an object")
    return needs


def self_test(jobs: List[str]) -> List[str]:
    """The failures of the self-test; empty means every plant was judged correctly."""
    ok = {name: {"result": "success"} for name in jobs}
    failures: List[str] = []
    if problems(jobs, ok):
        failures.append(f"the all-success needs were rejected: {problems(jobs, ok)}")
    first = jobs[0]
    plants = {}
    for result in ("failure", "skipped", "cancelled"):
        plants[f"{first} {result}"] = (
            {**ok, first: {"result": result}},
            f"{first} is {result}",
        )
    plants[f"{first} left out of needs"] = (
        {k: v for k, v in ok.items() if k != first},
        f"job {first} is not in the gate's needs",
    )
    plants["a needs entry naming no job"] = (
        {**ok, "no-such-job": {"result": "success"}},
        "the gate needs no-such-job, which is not a job of this workflow",
    )
    for label, (needs, expected) in plants.items():
        got = problems(jobs, needs)
        if len(got) != 1 or expected not in got[0]:
            failures.append(f"{label}: expected exactly [{expected}...], got {got}")
        else:
            print(f"OK      rejected: {label}")
    return failures


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--workflow", required=True, type=Path)
    parser.add_argument(
        "--gate-job", required=True, help="the gate's own key, as ${{ github.job }}"
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    try:
        jobs = gated_jobs(args.workflow.read_text(encoding="utf-8"), args.gate_job)
        if args.self_test:
            failures = self_test(jobs)
            for failure in failures:
                print(f"::error::gate self-test: {failure}")
            if not failures:
                print(
                    f"the gate verdict rejects every planted wrong needs set over {len(jobs)} job(s)"
                )
            return 1 if failures else 0
        needs = load_needs(os.environ.get("NEEDS_JSON"))
    except (InputError, OSError) as err:
        print(f"::error::{args.gate_job}: {err}")
        return 2
    found = problems(jobs, needs)
    for name in sorted(needs):
        print(f"{(needs[name] or {}).get('result', '?'):<10} {name}")
    for problem in found:
        print(f"::error::{problem}")
    if found:
        return 1
    print(f"{args.gate_job}: all {len(jobs)} job(s) of {args.workflow} succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
