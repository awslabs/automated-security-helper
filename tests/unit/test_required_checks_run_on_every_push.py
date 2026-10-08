# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The v4-capabilities required checks must report on every push.

Why this file exists
--------------------
The v4-capabilities ruleset requires the check names in ``REQUIRED_CHECKS`` by their
exact text. A required check that never reports does not fail the rule, it leaves it
unsatisfied, and nothing says why. Three things make a check not report on a push:

1. A ``paths`` (or ``paths-ignore``) filter on the workflow's ``push`` or
   ``pull_request`` trigger, so a change outside the list starts no run at all. The
   four workflows below had one; they now run on every push, and
   ``test_the_workflow_has_no_paths_filter`` keeps it that way.
2. A job-level ``if:`` that evaluates false, or one on a job the required job
   ``needs`` (a skipped dependency skips the dependant). A skipped check does not
   satisfy the rule either. The two gates carry ``if: always()``, which never skips,
   and nothing else may carry one.
3. A concurrency group two pushes to one branch share. With ``cancel-in-progress``
   the second push cancels the first push's checks, so that commit carries
   ``cancelled``; without it GitHub still keeps only one pending run per group and
   evicts the older one before it starts. ``test_two_pushes_never_share_a_concurrency_group``
   evaluates every workflow- and job-level group for two pushes and requires them to
   differ.
4. A renamed job, or a matrix on it. The ruleset matches the check name verbatim, and
   GitHub appends the matrix values to a job name that does not reference them, so
   either change leaves the old name with nothing reporting under it.

Every check here reads the workflows with ``yaml.safe_load``, and each has a planted
negative showing it fails on the defect it names.

What it does not cover
----------------------
The ruleset itself lives in the repository settings, not in the tree, so this cannot
prove the ruleset lists these names; it proves that each name exists and reports.
Branch filters are left as the workflows declare them: ash-e2e.yml runs on pushes to
v4-capabilities and v4/** only.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# Workflow file -> the check names the ruleset requires from it. A job with no
# `name:` reports under its job id.
REQUIRED_CHECKS: dict[str, tuple[str, ...]] = {
    "ash-e2e.yml": ("e2e: gate",),
    "ash-native-packages.yml": ("native-packages: gate",),
    "ash-vscode-extension.yml": (
        "coverage verdicts agree with ASH",
        "snapshots: structural, Snapshot-Update trailers, orphans",
        "integration tests in a real VS Code",
        "build and inspect the .vsix",
        "snapshots: pixels in a pinned VS Code",
        "e2e: .vsix install, real ashx scans, upgrade, uninstall",
    ),
    "ash-jetbrains-ci.yml": (
        "editors: jetbrains plugin verifier (gradle:jdk21)",
        "editors: jetbrains snapshot trailers",
        "editors: jetbrains visual snapshots (IntelliJ IDEA 2025.2.5, Xvfb)",
        "editors: jetbrains e2e with a real ashx (gradle:jdk21)",
        "editors: jetbrains (gradle:jdk21)",
    ),
    "ash-kubernetes-operator.yml": ("e2e-kind", "crd-drift", "lint-and-unit"),
}

# The only job-level condition allowed on a required job or anything it needs: it
# never skips, which is what lets a gate report on a red dependency.
ALWAYS = "always()"

FILTER_KEYS = ("paths", "paths-ignore")
FILTERED_EVENTS = ("push", "pull_request")


def _load(text: str) -> dict[str, Any]:
    data = yaml.safe_load(text)
    assert isinstance(data, dict), "the workflow is not a YAML mapping"
    return data


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    # YAML 1.1 reads the bare key `on` as the boolean True.
    on = workflow.get("on", workflow.get(True))
    assert isinstance(on, dict), f"`on:` is not a mapping of events: {on!r}"
    return on


def filter_problems(text: str) -> list[str]:
    """Why this workflow would skip a push or pull_request; empty when it cannot."""
    on = _triggers(_load(text))
    problems = []
    if "push" not in on:
        problems.append("the workflow does not trigger on push")
    for event in FILTERED_EVENTS:
        body = on.get(event)
        if not isinstance(body, dict):
            continue
        for key in FILTER_KEYS:
            if key in body:
                problems.append(f"on.{event} has a `{key}` filter")
    return problems


def _check_name(job_id: str, job: dict[str, Any]) -> str:
    return str(job.get("name", job_id))


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def required_job_problems(text: str, required: tuple[str, ...]) -> list[str]:
    """Why a required check name would not report on a push; empty when every one does."""
    jobs = _load(text).get("jobs") or {}
    by_name: dict[str, list[str]] = {}
    for job_id, job in jobs.items():
        by_name.setdefault(_check_name(job_id, job), []).append(job_id)
    problems = []
    for name in required:
        ids = by_name.get(name, [])
        if len(ids) != 1:
            problems.append(
                f"{len(ids)} jobs report as {name!r}; the ruleset needs exactly one"
            )
            continue
        job = jobs[ids[0]]
        if (job.get("strategy") or {}).get("matrix"):
            problems.append(
                f"{name!r} has a matrix, so its checks report under other names"
            )
        if "${{" in name:
            problems.append(f"{name!r} is an expression, not a fixed check name")
        # The job and everything it needs, transitively: a skipped dependency skips it.
        pending, seen = [ids[0]], set()
        while pending:
            job_id = pending.pop()
            if job_id in seen:
                continue
            seen.add(job_id)
            if job_id not in jobs:
                problems.append(f"{name!r} needs {job_id!r}, which is not a job")
                continue
            condition = jobs[job_id].get("if")
            if condition is not None and str(condition).strip() != ALWAYS:
                where = "it" if job_id == ids[0] else f"its dependency {job_id!r}"
                problems.append(
                    f"{name!r} can be skipped: {where} has `if: {condition}`"
                )
            pending.extend(_needs(jobs[job_id]))
    return problems


# The expression forms concurrency groups here use. Anything else is refused rather
# than guessed at, so a new form fails this test instead of passing it unevaluated.
_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}")
_TOKEN = re.compile(r"\s*(github\.[a-z_]+|'[^']*'|==|!=|&&|\|\||\(|\))")


def _equal(left: object, right: object) -> bool:
    """GitHub's ==: two strings compare ignoring case."""
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    return left == right


def _evaluate(expression: str, context: dict[str, str]) -> str:
    """One `${{ }}` body: github.<x> lookups, '...' literals, ==, !=, && and ||,
    with GitHub's short-circuit semantics (an operator returns an operand)."""
    tokens, position = [], 0
    while position < len(expression.rstrip()):
        match = _TOKEN.match(expression, position)
        if match is None:
            raise ValueError(f"unreadable concurrency expression: {expression!r}")
        tokens.append(match.group(1))
        position = match.end()

    def operand(index: int) -> tuple[object, int]:
        token = tokens[index]
        if token == "(":
            value, index = disjunction(index + 1)
            if tokens[index] != ")":
                raise ValueError(f"unbalanced concurrency expression: {expression!r}")
            return value, index + 1
        if token.startswith("'"):
            return token[1:-1], index + 1
        if token.startswith("github."):
            name = token.removeprefix("github.")
            if name not in context:
                raise ValueError(f"no value for {token} in {expression!r}")
            return context[name], index + 1
        raise ValueError(f"unreadable concurrency expression: {expression!r}")

    def comparison(index: int) -> tuple[object, int]:
        left, index = operand(index)
        while index < len(tokens) and tokens[index] in ("==", "!="):
            op = tokens[index]
            right, index = operand(index + 1)
            same = _equal(left, right)
            left = same if op == "==" else not same
        return left, index

    def conjunction(index: int) -> tuple[object, int]:
        left, index = comparison(index)
        while index < len(tokens) and tokens[index] == "&&":
            right, index = comparison(index + 1)
            left = left and right
        return left, index

    def disjunction(index: int) -> tuple[object, int]:
        left, index = conjunction(index)
        while index < len(tokens) and tokens[index] == "||":
            right, index = conjunction(index + 1)
            left = left or right
        return left, index

    value, end = disjunction(0)
    if end != len(tokens):
        raise ValueError(f"unreadable concurrency expression: {expression!r}")
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _render(template: str, context: dict[str, str]) -> str:
    return _EXPRESSION.sub(lambda m: _evaluate(m.group(1), context), template)


def _push(sha: str) -> dict[str, str]:
    return {
        "event_name": "push",
        "ref": "refs/heads/v4-capabilities",
        "sha": sha,
        "workflow": "a workflow",
        "head_ref": "",
        "run_id": "1",
    }


def concurrency_problems(text: str) -> list[str]:
    """Concurrency that can cost a push its verdict; empty when there is none.

    Two pushes to one branch must land in different groups, and a push run must not
    be cancellable: the same commit pushed to two branches shares a sha-keyed group,
    and with cancel-in-progress the second push would cancel the first's checks."""
    workflow = _load(text)
    scopes = [("the workflow", workflow.get("concurrency"))] + [
        (f"job {job_id!r}", job.get("concurrency"))
        for job_id, job in (workflow.get("jobs") or {}).items()
    ]
    problems = []
    for where, concurrency in scopes:
        if concurrency is None:
            continue
        group = (
            concurrency.get("group") if isinstance(concurrency, dict) else concurrency
        )
        try:
            first = _render(str(group), _push("a" * 40))
            second = _render(str(group), _push("b" * 40))
        except ValueError as error:
            problems.append(f"{where}: {error}")
            continue
        if first == second:
            problems.append(
                f"{where}: two pushes to one branch share concurrency group {first!r}"
            )
        cancel = (
            concurrency.get("cancel-in-progress", False)
            if isinstance(concurrency, dict)
            else False
        )
        if isinstance(cancel, bool):
            rendered = "true" if cancel else "false"
        else:
            try:
                rendered = _render(str(cancel), _push("a" * 40))
            except ValueError as error:
                problems.append(f"{where}: {error}")
                continue
        if rendered != "false":
            problems.append(
                f"{where}: cancel-in-progress is {rendered!r} on push, so a push run "
                "can be cancelled"
            )
    return problems


def _text(workflow: str) -> str:
    return (WORKFLOWS / workflow).read_text(encoding="utf-8")


def test_the_census_names_every_required_check() -> None:
    # The ruleset's list, counted, so a name dropped from REQUIRED_CHECKS is seen.
    names = [name for names in REQUIRED_CHECKS.values() for name in names]
    assert len(names) == len(set(names)) == 16


@pytest.mark.parametrize("workflow", sorted(REQUIRED_CHECKS))
def test_the_workflow_has_no_paths_filter(workflow: str) -> None:
    assert filter_problems(_text(workflow)) == []


@pytest.mark.parametrize("workflow", sorted(REQUIRED_CHECKS))
def test_every_required_check_exists_and_cannot_be_skipped(workflow: str) -> None:
    assert required_job_problems(_text(workflow), REQUIRED_CHECKS[workflow]) == []


def _after_event(text: str, event: str, inserted: str) -> str:
    """The workflow with `inserted` placed directly under its `  <event>:` line."""
    planted, count = re.subn(
        rf"^(  {event}:[^\n]*\n)",
        rf"\g<1>{inserted}",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    assert count == 1, f"no `  {event}:` line to plant under"
    return planted


@pytest.mark.parametrize("workflow", sorted(REQUIRED_CHECKS))
@pytest.mark.parametrize("key", FILTER_KEYS)
def test_a_paths_filter_planted_on_push_is_refused(workflow: str, key: str) -> None:
    planted = _after_event(_text(workflow), "push", f'    {key}:\n      - "docs/**"\n')
    assert f"on.push has a `{key}` filter" in filter_problems(planted)


def test_a_paths_filter_planted_on_pull_request_is_refused() -> None:
    text = _text("ash-vscode-extension.yml")
    planted = _after_event(text, "pull_request", '    paths:\n      - "docs/**"\n')
    assert filter_problems(planted) == ["on.pull_request has a `paths` filter"]


def test_a_workflow_without_a_push_trigger_is_refused() -> None:
    text = "on:\n  pull_request:\n  workflow_dispatch:\njobs: {}\n"
    assert filter_problems(text) == ["the workflow does not trigger on push"]


def test_a_renamed_required_job_is_refused() -> None:
    text = _text("ash-jetbrains-ci.yml")
    planted = text.replace(
        'name: "editors: jetbrains snapshot trailers"',
        'name: "editors: jetbrains snapshot trailer check"',
    )
    assert planted != text, "the job name to rename is not in the workflow"
    assert required_job_problems(planted, REQUIRED_CHECKS["ash-jetbrains-ci.yml"]) == [
        (
            "0 jobs report as 'editors: jetbrains snapshot trailers'; "
            "the ruleset needs exactly one"
        )
    ]


def test_a_renamed_unnamed_job_is_refused() -> None:
    text = _text("ash-kubernetes-operator.yml")
    planted = re.sub(
        r"^  crd-drift:", "  crd-check:", text, count=1, flags=re.MULTILINE
    )
    assert planted != text
    problems = required_job_problems(
        planted, REQUIRED_CHECKS["ash-kubernetes-operator.yml"]
    )
    assert problems == ["0 jobs report as 'crd-drift'; the ruleset needs exactly one"]


def _plant_job_condition(text: str, job_id: str, condition: str) -> str:
    planted, count = re.subn(
        rf"^(  {re.escape(job_id)}:\n)",
        rf"\g<1>    if: {condition}\n",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    assert count == 1, f"no job {job_id!r} to plant under"
    return planted


def test_a_job_level_if_on_a_required_job_is_refused() -> None:
    text = _text("ash-kubernetes-operator.yml")
    planted = _plant_job_condition(text, "e2e-kind", "github.event_name != 'push'")
    assert required_job_problems(
        planted, REQUIRED_CHECKS["ash-kubernetes-operator.yml"]
    ) == ["'e2e-kind' can be skipped: it has `if: github.event_name != 'push'`"]


def test_a_job_level_if_on_a_dependency_is_refused() -> None:
    # integration-real needs package; a skipped package skips the required e2e job.
    text = _text("ash-vscode-extension.yml")
    planted = _plant_job_condition(text, "package", "github.ref == 'refs/heads/main'")
    problems = required_job_problems(
        planted, REQUIRED_CHECKS["ash-vscode-extension.yml"]
    )
    assert (
        "'e2e: .vsix install, real ashx scans, upgrade, uninstall' can be skipped: "
        "its dependency 'package' has `if: github.ref == 'refs/heads/main'`"
    ) in problems


def test_a_gate_condition_other_than_always_is_refused() -> None:
    text = _text("ash-native-packages.yml")
    planted = text.replace("    if: always()\n", "    if: success()\n", 1)
    assert planted != text
    assert required_job_problems(
        planted, REQUIRED_CHECKS["ash-native-packages.yml"]
    ) == ["'native-packages: gate' can be skipped: it has `if: success()`"]


def test_a_matrix_on_a_required_job_is_refused() -> None:
    text = _text("ash-kubernetes-operator.yml")
    planted, count = re.subn(
        r"^(  lint-and-unit:\n)",
        r"\g<1>    strategy:\n      matrix:\n        python: ['3.12', '3.13']\n",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    assert count == 1
    assert required_job_problems(
        planted, REQUIRED_CHECKS["ash-kubernetes-operator.yml"]
    ) == ["'lint-and-unit' has a matrix, so its checks report under other names"]


@pytest.mark.parametrize("workflow", sorted(REQUIRED_CHECKS))
def test_two_pushes_never_share_a_concurrency_group(workflow: str) -> None:
    assert concurrency_problems(_text(workflow)) == []


def test_the_expression_reader_follows_github_semantics() -> None:
    group = (
        "${{ github.workflow }}-"
        "${{ github.event_name == 'push' && github.sha || github.ref }}"
    )
    assert _render(group, _push("abc")) == "a workflow-abc"
    pull = {**_push("abc"), "event_name": "pull_request", "ref": "refs/pull/1/merge"}
    assert _render(group, pull) == "a workflow-refs/pull/1/merge"
    assert _render("${{ github.event_name == 'pull_request' }}", pull) == "true"
    # GitHub compares strings ignoring case.
    assert _render("${{ github.event_name == 'PUSH' }}", _push("abc")) == "true"
    assert _render("${{ github.event_name != 'Push' }}", _push("abc")) == "false"
    assert (
        _render("x-${{ github.event_name == 'push' && github.sha || '' }}", pull)
        == "x-"
    )


CANCELLABLE_ON_PUSH = (
    "the workflow: cancel-in-progress is 'true' on push, so a push run can be cancelled"
)

BASE_KEYING = (
    "concurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n"
    "  cancel-in-progress: true\n"
)


@pytest.mark.parametrize("workflow", sorted(REQUIRED_CHECKS))
def test_ref_keyed_workflow_concurrency_is_refused(workflow: str) -> None:
    text = _text(workflow)
    planted, count = re.subn(
        r"^concurrency:\n(?:[ #].*\n|\n)*?(?=\S)",
        BASE_KEYING + "\n",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    assert count == 1, f"{workflow} has no workflow-level concurrency to replace"
    assert concurrency_problems(planted) == [
        (
            "the workflow: two pushes to one branch share concurrency group "
            "'a workflow-refs/heads/v4-capabilities'"
        ),
        CANCELLABLE_ON_PUSH,
    ]


@pytest.mark.parametrize("workflow", sorted(REQUIRED_CHECKS))
@pytest.mark.parametrize(
    "cancel", ["true", "${{ github.event_name != 'pull_request' }}"]
)
def test_a_cancellable_push_run_is_refused(workflow: str, cancel: str) -> None:
    text = _text(workflow)
    planted, count = re.subn(
        r"^  cancel-in-progress: .*$",
        f"  cancel-in-progress: {cancel}",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    assert count == 1, f"{workflow} has no workflow-level cancel-in-progress"
    assert concurrency_problems(planted) == [CANCELLABLE_ON_PUSH]


def test_ref_keyed_job_concurrency_is_refused() -> None:
    text = _text("ash-kubernetes-operator.yml")
    planted, count = re.subn(
        r"^(  e2e-kind:\n)",
        r"\g<1>    concurrency:\n      group: kind-${{ github.ref }}\n",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    assert count == 1
    assert concurrency_problems(planted) == [
        (
            "job 'e2e-kind': two pushes to one branch share concurrency group "
            "'kind-refs/heads/v4-capabilities'"
        )
    ]


def test_a_fixed_string_group_is_refused() -> None:
    text = "on:\n  push:\nconcurrency: deploy\njobs: {}\n"
    assert concurrency_problems(text) == [
        "the workflow: two pushes to one branch share concurrency group 'deploy'"
    ]


def test_an_unreadable_group_expression_is_refused() -> None:
    text = (
        "on:\n  push:\nconcurrency:\n"
        "  group: ${{ format('{0}', github.sha) }}\njobs: {}\n"
    )
    problems = concurrency_problems(text)
    assert len(problems) == 1 and "unreadable concurrency expression" in problems[0]
