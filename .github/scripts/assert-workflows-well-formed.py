#!/usr/bin/env python3
"""Reject a workflow that parses as YAML but that GitHub Actions will not run.

WHY THIS EXISTS

A merge that added four packaging jobs to ash-package.yml resolved its conflicts by
keeping both sides, and the conflict boundaries fell inside job bodies. Two jobs
came out of it with `steps:` and nothing under it, and two others gained a step
that belonged to the job above them.

Nothing caught it. `yaml.safe_load` reads `steps:` with an empty value as None and
returns a complete-looking document, so the file parsed clean. A listing of job
names was also complete -- the names were all there, only the bodies were gone. It
surfaced only when `gh workflow run` returned

    HTTP 422: failed to parse workflow: (Line: 669, Col: 11): Unexpected value ''

which is GitHub's own parser refusing what Python's had accepted. By then the file
was already pushed.

So the lesson this encodes is narrow and worth stating: a YAML parser is not an
Actions validator, and a census of job NAMES is not a census of job BODIES. The
checks below are the ones that would have failed on that file.

WHAT IT CHECKS, AND WHY EACH ONE

  empty-steps          `steps:` present with nothing under it. This is the exact
                       422 above. It is the single most likely product of a bad
                       merge, because `steps:` is the last line of a job header
                       and the first line of its body is where a conflict marker
                       lands.
  no-steps-no-uses     a job with neither `steps:` nor `uses:`. A job must either
                       run steps or call a reusable workflow; one with neither is
                       a job header whose body was lost entirely.
  empty-job            a job key whose whole value is empty.
  no-jobs              a workflow with no `jobs:` at all.
  missing-runs-on      a steps-bearing job with no `runs-on`. Actions rejects it,
                       and a merge that drops one line drops this one as easily as
                       any other.
  empty-step           a step that is neither `run:` nor `uses:`. Distinct from
                       empty-steps: the list exists and has an entry that does
                       nothing, which is what an interleaved merge produces when
                       it keeps a step's `name:` and loses the rest of it.

WHAT IT DELIBERATELY DOES NOT CHECK

It is not a schema validator and does not try to be. Expression syntax, input
types, permission scopes and action-input names are all out of scope: the only
authority on those is Actions itself, and a partial reimplementation would give
false confidence in exactly the direction this script exists to remove. Treat a
pass as "no job body is missing", not as "this workflow is valid".

FAILURE MODE OF THIS SCRIPT ITSELF

It finds nothing if it is pointed at the wrong tree, which is not hypothetical:
the sibling gate assert-actions-pinned.mjs resolves its search root from the
current working directory, and running it from outside the repository read a
DIFFERENT checkout and reported a stale count that happened to look plausible. So
this script resolves paths relative to its own location rather than the cwd, prints
the absolute directory it scanned and the file count, and exits non-zero if it
found no workflows at all. A gate that scanned nothing must fail rather than pass.

Usage: assert-workflows-well-formed.py [--self-test]
"""
from __future__ import annotations

import pathlib
import sys

import yaml

# Relative to this file, not to the cwd. See "failure mode of this script itself".
WORKFLOW_DIR = pathlib.Path(__file__).resolve().parent.parent / "workflows"


def check(name: str, doc: object) -> list[str]:
    """Return a list of findings for one parsed workflow document."""
    bad: list[str] = []
    if not isinstance(doc, dict):
        return [f"{name}: not a mapping at the top level"]

    jobs = doc.get("jobs")
    if not jobs or not isinstance(jobs, dict):
        return [f"{name}: no-jobs -- a workflow with no jobs runs nothing"]

    for job_name, body in jobs.items():
        where = f"{name}: job {job_name}"
        if body is None or body == {}:
            bad.append(f"{where}: empty-job -- the job key has no value")
            continue
        if not isinstance(body, dict):
            bad.append(f"{where}: not a mapping")
            continue

        has_steps_key = "steps" in body
        steps = body.get("steps")

        if has_steps_key and not steps:
            bad.append(
                f"{where}: empty-steps -- `steps:` is present with nothing under it. "
                "yaml reads this as None and accepts it; Actions rejects it with "
                "\"Unexpected value ''\""
            )
            continue
        if not has_steps_key and "uses" not in body:
            bad.append(
                f"{where}: no-steps-no-uses -- a job must run steps or call a "
                "reusable workflow"
            )
            continue
        if not has_steps_key:
            continue  # a reusable-workflow call; runs-on and steps do not apply

        if "runs-on" not in body:
            bad.append(f"{where}: missing-runs-on")
        for i, step in enumerate(steps):
            if not isinstance(step, dict) or not ({"run", "uses"} & set(step)):
                label = (step or {}).get("name", f"index {i}") if isinstance(step, dict) else f"index {i}"
                bad.append(f"{where}: empty-step -- step {label} has neither run: nor uses:")
    return bad


# One fixture per finding, so a rule that stopped matching is reported rather than
# hidden by another rule firing on the same document.
SELF_TEST = {
    "empty-steps": "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n",
    "no-steps-no-uses": "jobs:\n  a:\n    runs-on: ubuntu-latest\n",
    "empty-job": "jobs:\n  a:\n",
    "no-jobs": "name: x\n",
    "missing-runs-on": "jobs:\n  a:\n    steps:\n      - run: true\n",
    "empty-step": "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - name: nothing\n",
}
GOOD = (
    "jobs:\n"
    "  a:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@v9\n"
    "      - run: echo hi\n"
    "  b:\n"
    "    uses: ./.github/workflows/other.yml\n"
)


def self_test() -> int:
    failures = 0
    for expected, text in SELF_TEST.items():
        found = check("fixture", yaml.safe_load(text))
        hit = any(expected in f for f in found)
        print(f"  self-test {expected:18s} {'rejected' if hit else 'NOT REJECTED'}")
        if not hit:
            failures += 1
    clean = check("fixture", yaml.safe_load(GOOD))
    print(f"  self-test {'well-formed':18s} "
          f"{'accepted' if not clean else 'WRONGLY REJECTED: ' + str(clean)}")
    if clean:
        failures += 1
    if failures:
        print(f"self-test FAILED: {failures} rule(s) do not work", file=sys.stderr)
        return 1
    print("self-test OK: every rule fires on its own fixture, and a good workflow passes")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()

    print(f"scanning {WORKFLOW_DIR}")
    paths = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
    if not paths:
        print(f"FAIL: no workflows found under {WORKFLOW_DIR}. A gate that scanned "
              "nothing must fail rather than pass.", file=sys.stderr)
        return 2

    findings: list[str] = []
    for path in paths:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            findings.append(f"{path.name}: does not parse as YAML: {exc}")
            continue
        findings.extend(check(path.name, doc))

    jobs = sum(
        len((yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("jobs") or {})
        for p in paths
    )
    if findings:
        print(f"\nworkflow structure FAILED: {len(findings)} finding(s) across "
              f"{len(paths)} file(s)", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"workflow structure OK: {len(paths)} workflow(s), {jobs} job(s), "
          "every job has a body")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
