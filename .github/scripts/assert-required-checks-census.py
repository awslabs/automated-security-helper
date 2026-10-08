#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Asserts the required-checks gate depends on every job in its own workflow.

WHY THIS EXISTS
---------------
``required-checks`` in ``.github/workflows/ash-unified-ci.yml`` is the one check
name a ruleset can require, because it is the one name that does not move with a
matrix. It reports the verdict its ``needs`` already computed, so the share of
the workflow it speaks for is exactly its ``needs`` list -- and a job added to
the workflow but not to that list escapes the gate silently while the gate keeps
reporting success.

The gate used to guard that with a literal: ``EXPECTED_UPSTREAM_JOBS: "8"``
compared against ``len(needs)``. Both sides of that comparison lived inside the
gate job, so it could only catch the harmless direction. Adding a tenth job
without adding it to ``needs`` leaves ``len(needs)`` at 8 and the literal at 8,
and the check passes over shrunk coverage; updating ``needs`` and forgetting the
literal is the direction it caught, and that one fails loudly on its own the
moment anyone reads the gate's output. The literal was never wrong on this tree
-- 9 jobs, 8 in ``needs``, the 9th being the gate itself, so coverage was
complete -- which is why the hole stayed latent rather than showing up as a
missed regression.

The census has to come from outside the report, which is the same reason
``.github/scripts/assert-coverage-completeness.mjs`` takes its file list from
``git ls-files`` rather than from the coverage report it is checking. Here the
census is the workflow's own ``jobs:`` mapping, read off disk.

WHY THE JOB LIST IS SCANNED RATHER THAN PARSED WITH PyYAML
----------------------------------------------------------
The gate runs on a bare ``ubuntu-latest`` with the repository checked out and
nothing installed. Reaching the network to ``pip install pyyaml`` would put a
registry round trip inside the one job whose job is to be trustworthy, and this
repository has already lost a leg exactly that way -- see the comment on the
"Code coverage summary" step in ``.github/actions/run-unit-tests/action.yml``,
where a Docker-based action's image pull failed DNS resolution and the leg
reported failure having run zero tests.

So the scanner below is dependency-free, and its correctness is not taken on
trust: ``tests/unit/test_required_checks_census.py`` asserts it returns exactly
the job keys ``yaml.safe_load`` finds in every workflow in this repository.
PyYAML is a test dependency, so the second instrument runs where it is already
available and the gate stays self-contained.

The scanner understands block scalars (``run: |``) because this workflow is full
of them and one contains a heredoc; without that, a line inside a shell script
could be mistaken for a job key.

JOBS THAT MAY DELIBERATELY GO UNGATED
-------------------------------------
``_UNGATED`` below is the named, reasoned exemption list, and today it holds one entry, the image layer-cache warm-up.
The mechanism exists rather than being omitted because there is a legitimate
case for it -- an advisory job carrying ``continue-on-error``, whose failure is
information rather than a verdict -- and the alternative when that case arrives
is to weaken the census instead. An exemption is checked for staleness on every
run: an entry naming a job the workflow no longer has, or one that has since
been added to ``needs``, is a false statement in the tree and fails.

An exemption is NOT a place to record "this job is slow" or "this job is flaky".
It records that the job's verdict is deliberately not part of the merge gate.

USAGE
-----
    python3 .github/scripts/assert-required-checks-census.py \
      --workflow .github/workflows/ash-unified-ci.yml \
      --gate-job required-checks

``NEEDS_JSON`` must hold ``toJSON(needs)`` from the gate job. Passing it through
the environment rather than argv keeps a multi-kilobyte JSON blob out of the
command line and out of the process table.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# A job in the gate's workflow that is deliberately NOT part of the merge gate,
# mapped to the reason it is not.
#
# State what makes the job's verdict advisory rather than required. "It is slow"
# and "it is flaky" are not reasons -- a flaky required check is a flake to fix,
# and a slow one is a budget to argue about.
#
# This is also where a job carrying a job-level `if:` that can be false belongs.
# Every gated job runs on every run -- scan-validation's `if: ${{ !cancelled() }}`
# is false only when the run itself is cancelled -- and the result check below refuses
# 'skipped' precisely so a job that never ran cannot read as a pass. A
# conditional job in `needs` would therefore take the gate red whenever its
# condition was false, so it has to be named here instead -- and naming it is
# the point, because "this job sometimes does not run" is a claim worth writing
# down rather than inferring from a count.
_UNGATED: dict[str, str] = {
    "warm-image-layers": (
        "a layer-cache warm-up that runs only on pushes to main. Its result is how "
        "fast the scan legs build, never whether they pass: scan-validation runs "
        "under `!cancelled()` whether it succeeded, failed, was skipped or was "
        "cancelled by its concurrency group, and scan-validation itself is gated."
    ),
}

# A mapping key, optionally preceded by one or more sequence dashes. The dashes have to
# be part of the pattern: a step is written `- run: |`, so without them the `run` key is
# invisible and the block scalar it opens is never noticed -- which is how a shell
# script's own indented lines come to be read as structure.
_KEY = re.compile(r"^( *)((?:-  *)*)([A-Za-z0-9_][A-Za-z0-9_.-]*):(.*)$")

# Block scalar indicators only: `|`, `>`, and either of those with a chomping
# indicator and/or an explicit indentation digit (`|-`, `>+`, `|2`, `|2-`).
# Deliberately anchored to a leading `|` or `>` -- an earlier draft also matched a
# bare number so that `timeout-minutes: 5` would have been read as opening a
# block scalar, and everything indented under the job after it would have been
# skipped.
_BLOCK_SCALAR = re.compile(r"^[|>][0-9+-]*$")


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def workflow_job_names(text: str) -> list[str]:
    """The top-level keys of the workflow's ``jobs:`` mapping, in file order.

    Deliberately not a general YAML parser. It walks lines, skips blanks and
    comments, skips the bodies of block scalars so a shell script cannot be
    mistaken for structure, and collects the keys at the one indentation level
    that ``jobs:`` opens. Cross-checked against ``yaml.safe_load`` by
    ``tests/unit/test_required_checks_census.py``.
    """
    jobs_indent: int | None = None
    key_indent: int | None = None
    block_owner_indent: int | None = None
    names: list[str] = []

    for raw in text.splitlines():
        stripped = raw.strip()

        if block_owner_indent is not None:
            # A block scalar's body is every following line indented deeper than
            # the key that opened it. Blank lines belong to the body too.
            if stripped == "" or _indent_of(raw) > block_owner_indent:
                continue
            block_owner_indent = None

        if stripped == "" or stripped.startswith("#"):
            continue

        match = _KEY.match(raw)
        if not match:
            # A sequence item that is not a mapping key (`- lint`, `- { os: x }`)
            # or a continuation line. Neither can be a job key.
            continue

        leading, dashes, name, value = match.groups()
        # A sequence dash occupies the column the key would otherwise start at, so
        # the key's real indentation includes it. Without this, `- run: |` reports
        # indent 6 rather than 8 and its body is measured against the wrong column
        # -- which is how the shell script inside a step comes to be read as
        # structure. Caught by a fixture in the test file, not by inspection.
        indent = len(leading) + len(dashes)

        if jobs_indent is None:
            if name == "jobs" and indent == 0 and not dashes:
                jobs_indent = indent
            continue

        # A mapping key back at or above `jobs:`'s own indentation ends the
        # mapping. There is nothing after `jobs:` in this workflow today, and a
        # future top-level key must not be read as a job.
        if indent <= jobs_indent:
            break

        if _is_block(value.strip()):
            block_owner_indent = indent

        # A job is a mapping entry, never a sequence item.
        if dashes:
            continue

        if key_indent is None:
            key_indent = indent

        if indent == key_indent:
            names.append(name)

    return names


def _is_block(value: str) -> bool:
    return value != "" and bool(_BLOCK_SCALAR.match(value))


def _load_needs(raw: str | None) -> dict[str, dict]:
    if raw is None or raw.strip() == "":
        # "No needs context" must not read like "every dependency succeeded".
        raise ValueError(
            "NEEDS_JSON is unset or empty. The gate step must pass "
            "${{ toJSON(needs) }} through it; without that this check would "
            "compare the workflow's job census against nothing and could only "
            "fail or pass for the wrong reason."
        )
    try:
        needs = json.loads(raw)
    except json.JSONDecodeError as err:
        raise ValueError(f"NEEDS_JSON is not valid JSON: {err}") from err
    if not isinstance(needs, dict):
        raise ValueError(f"NEEDS_JSON is {type(needs).__name__}, expected an object")
    return needs


def check(workflow_text: str, gate_job: str, needs: dict[str, dict]) -> list[str]:
    """Returns the list of problems; empty means the gate covers the workflow."""
    problems: list[str] = []

    job_names = workflow_job_names(workflow_text)
    if not job_names:
        # An empty census satisfies every comparison below without examining
        # anything, which is the failure shape this whole file exists to remove.
        raise ValueError(
            "no jobs were found in the workflow. The census is empty, and an "
            "empty census passes every check here vacuously. The scanner has "
            "gone stale against the file's structure."
        )

    if gate_job not in job_names:
        raise ValueError(
            f"the gate job {gate_job!r} is not among the workflow's jobs "
            f"({', '.join(job_names)}). It is passed as ${{{{ github.job }}}}, so "
            "either the scanner is wrong or this script is being run against a "
            "different workflow than the one it is gating."
        )

    census = [name for name in job_names if name != gate_job]
    if not census:
        raise ValueError(
            f"{gate_job} is the only job in the workflow, so there is nothing to "
            "gate and this check cannot mean anything."
        )

    should_be_gated = [name for name in census if name not in _UNGATED]

    missing = sorted(set(should_be_gated) - set(needs))
    if missing:
        problems.append(
            f"these job(s) exist in the workflow but are not in {gate_job}'s "
            f"`needs`, so the gate reports success without them: {missing}. Add "
            "them to `needs`, or -- if a job's verdict is deliberately advisory "
            "-- add it to _UNGATED in this script with the reason."
        )

    unexpected = sorted(set(needs) - set(should_be_gated))
    if unexpected:
        problems.append(
            f"{gate_job} depends on {unexpected}, which the workflow's job census "
            "does not expect. A job named in _UNGATED must not also be in "
            "`needs`, and a `needs` entry naming no job at all means the scanner "
            "disagrees with the file."
        )

    for job, reason in sorted(_UNGATED.items()):
        if job not in job_names:
            problems.append(
                f"_UNGATED excuses {job!r} ({reason}) but the workflow has no such "
                "job. Remove the entry."
            )
        if job in needs:
            problems.append(
                f"_UNGATED excuses {job!r} ({reason}) but it is in {gate_job}'s "
                "`needs`, so it IS gated. The excuse is a false statement; remove "
                "the entry."
            )

    # Every gated job runs on every run -- the one job-level `if` among them,
    # scan-validation's `!cancelled()`, is false only for a cancelled run -- so a
    # result of anything other than success means something went
    # wrong, 'skipped' included. Tolerating 'skipped' would let a job that never
    # ran read as a pass.
    for name, data in sorted(needs.items()):
        result = (data or {}).get("result")
        if result != "success":
            problems.append(f"{name}: {result}")

    return problems


def main(argv: list[str], env: dict[str, str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", required=True)
    parser.add_argument(
        "--gate-job",
        required=True,
        help="the gate job's own key, passed as ${{ github.job }} so it is read "
        "from the run rather than restated",
    )
    opts = parser.parse_args(argv)

    text = Path(opts.workflow).read_text(encoding="utf-8")
    needs = _load_needs(env.get("NEEDS_JSON"))

    for name, data in sorted(needs.items()):
        print(f"{(data or {}).get('result', '?'):<10} {name}")

    problems = check(text, opts.gate_job, needs)
    if problems:
        for problem in problems:
            print(f"::error::{problem}")
        return 1

    census = [n for n in workflow_job_names(text) if n != opts.gate_job]
    print(
        f"{opts.gate_job} gates {len(needs)} of {len(census)} job(s) in "
        f"{opts.workflow}, {len(_UNGATED)} deliberately ungated, and all "
        f"{len(needs)} succeeded"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:], dict(__import__("os").environ)))
    except (ValueError, OSError) as err:
        print(f"::error::required-checks census: {err}")
        sys.exit(2)
