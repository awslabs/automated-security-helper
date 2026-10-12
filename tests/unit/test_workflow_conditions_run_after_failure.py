# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A job or step meant to run after a failure says so with a status function.

Why this file exists
--------------------
GitHub Actions adds an implicit ``success() &&`` to every job-level and step-level
``if:`` that calls none of ``success()``, ``failure()``, ``always()`` or
``cancelled()``. So ``if: needs.ash.result == 'failure'`` can never be true: after a
failed ``ash`` job ``success()`` is false and the job is skipped. ash-repo-scan.yml's
SARIF job read ``(needs.ash.result == 'success' || needs.ash.result == 'failure') &&
...`` with no status function, and so it was skipped after every failed scan, which is
the case it was written for (a scan that fails on findings has still written its
SARIF). The Actions model in tests/utils/github_actions.py evaluated the expression as
written, without the implicit ``success()``, so the workflow tests passed it.

What this asserts
-----------------
1. Every job-level and step-level ``if:`` in the repository's workflows and composite
   actions (.github/, ash-agent-plugins/.github/, and the GitHub Actions example under
   docs/content/tutorials/CI) that reads a job result, a step outcome or conclusion, or
   ``job.status`` against anything other than ``'success'`` calls a status function.
2. A step that uploads results, SARIF or a test report after a step that runs ASH in
   the same job has an ``if:`` with a status function, so a scan that fails on findings
   still leaves its results. The same holds for the GitHub Actions examples in the docs
   and package READMEs, which users copy, whether a YAML block is a whole workflow or a
   bare list of steps. A scan run with ``--no-fail-on-findings`` cannot fail on
   findings, so an upload after it needs no status function.
3. The model applies the implicit ``success()``: a condition without a status function
   is false after a failure, ``!cancelled() && ...`` is not, and a job's status comes
   from the results of the jobs it needs.
4. Negative controls for both rules, and the scan finds the conditions and uploads it is
   about, so it cannot pass by reading nothing. For the docs, the reader must flag both
   shapes in a synthetic example, and must find at least one real upload; it does not
   count pages, which change with every docs rewrite.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterator

import pytest
import yaml

from tests.utils import github_actions as ga

REPO_ROOT = Path(__file__).resolve().parents[2]

STATUS_CALL = re.compile(r"\b(?:success|always|cancelled|failure)\s*\(", re.IGNORECASE)
RESULT_REF = re.compile(
    r"\bneeds\.[\w-]+\.result\b|\bsteps\.[\w-]+\.(?:outcome|conclusion)\b|\bjob\.status\b"
)
# A comparison that can only hold when something did not succeed.
NOT_SUCCESS = re.compile(
    r"""['"](?:failure|cancelled|skipped)['"]|!=\s*['"]success['"]|['"]success['"]\s*!="""
)
UPLOADS = re.compile(
    r"actions/upload-artifact@|github/codeql-action/upload-sarif@|"
    r"mikepenz/action-junit-report@|mshick/add-pr-comment@"
)
# A step that runs ASH: the `ash` command (directly, or through uv/uvx), Invoke-ASH, or
# this repository's scan action.
RUNS_ASH = re.compile(r"(?<![\w./-])ash(?=\s|$)|\bInvoke-ASH\b|/run-scan-test\b")


def workflow_files() -> list[Path]:
    return [
        *sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")),
        *sorted((REPO_ROOT / ".github" / "actions").glob("*/action.yml")),
        *sorted(
            (REPO_ROOT / "ash-agent-plugins" / ".github" / "workflows").glob("*.yml")
        ),
        *sorted(
            (REPO_ROOT / "docs" / "content" / "tutorials" / "CI").rglob(
                ".github/workflows/*.yml"
            )
        ),
    ]


def _jobs_of(data: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any] | None, list]]:
    """(name, job or None for a composite action, steps)."""
    for job_id, job in (data.get("jobs") or {}).items():
        job = job or {}
        yield job_id, job, list(job.get("steps") or [])
    runs = data.get("runs") or {}
    if runs.get("steps"):
        yield "composite action", None, list(runs["steps"])


def _condition_text(condition: Any) -> str:
    return "" if condition is None else str(condition)


def lacks_status_after_failure(condition: Any) -> bool:
    """Whether an ``if:`` reads a non-success outcome but calls no status function."""
    text = _condition_text(condition)
    return (
        bool(RESULT_REF.search(text))
        and bool(NOT_SUCCESS.search(text))
        and not STATUS_CALL.search(text)
    )


def scan_can_fail(step: dict[str, Any]) -> bool:
    """A step that runs ASH and can fail on findings (no `--no-fail-on-findings`)."""
    run = str(step.get("run") or "")
    runs_ash = RUNS_ASH.search(run) or RUNS_ASH.search(str(step.get("uses") or ""))
    return bool(runs_ash) and "--no-fail-on-findings" not in run


def _uploads_after_scan(steps: list) -> list[dict[str, Any]]:
    """The upload steps that follow a step that runs ASH and can fail."""
    found, armed = [], False
    for step in steps:
        if not isinstance(step, dict):
            continue
        if armed and UPLOADS.search(str(step.get("uses") or "")):
            found.append(step)
        armed = armed or scan_can_fail(step)
    return found


def uploads_after_ash_without_status(steps: list) -> list[str]:
    """Upload steps that follow a step running ASH but would be skipped after it fails."""
    return [
        str(step.get("name") or step.get("uses"))
        for step in _uploads_after_scan(steps)
        if not STATUS_CALL.search(_condition_text(step.get("if")))
    ]


def _scan() -> tuple[int, list[str], list[str], list[str]]:
    conditions, missing_status, uploads, found_uploads = 0, [], [], []
    for path in workflow_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        where = str(path.relative_to(REPO_ROOT))
        for name, job, steps in _jobs_of(data):
            items = ([(f"job {name}", job.get("if"))] if job is not None else []) + [
                (f"{name} / step {s.get('name') or s.get('uses')}", s.get("if"))
                for s in steps
                if isinstance(s, dict)
            ]
            for label, condition in items:
                if condition is not None:
                    conditions += 1
                if lacks_status_after_failure(condition):
                    missing_status.append(f"{where}: {label}: {condition}")
            uploads += [
                f"{where}: {name}: {u}" for u in uploads_after_ash_without_status(steps)
            ]
            found_uploads += [
                f"{where}: {name}: {s.get('name')}" for s in _uploads_after_scan(steps)
            ]
    return conditions, missing_status, uploads, found_uploads


#: The job id given to a snippet that is a list of steps with no `jobs:` around it.
STEP_LIST = "(steps)"


def is_step_list(data: Any) -> bool:
    """A YAML list whose every item is a step: a mapping with `uses` or `run`."""
    return (
        isinstance(data, list)
        and bool(data)
        and all(isinstance(s, dict) and ("uses" in s or "run" in s) for s in data)
    )


def yaml_example_jobs(text: str) -> Iterator[tuple[int, str, list]]:
    """(line, job id, steps) for each GitHub Actions job in a markdown text's YAML blocks.

    A block that is a list of steps with no `jobs:` (a snippet showing the steps to
    add to a job, as on a how-to page) is read as one job named STEP_LIST.
    """
    for block in re.finditer(r"```ya?ml\n(.*?)```", text, re.DOTALL):
        try:
            data = yaml.safe_load(block.group(1))
        except yaml.YAMLError:
            continue
        line = text[: block.start()].count("\n") + 1
        if isinstance(data, dict) and isinstance(data.get("jobs"), dict):
            for job_id, job in data["jobs"].items():
                if isinstance(job, dict):
                    yield line, str(job_id), list(job.get("steps") or [])
        elif is_step_list(data):
            yield line, STEP_LIST, list(data)


def docs_example_jobs() -> Iterator[tuple[str, str, list]]:
    """(file:line, job id, steps) for each GitHub Actions job in a docs YAML example."""
    sources = {
        *(REPO_ROOT / "docs" / "content").rglob("*.md"),
        *(REPO_ROOT / "docs" / "content").rglob("*.template"),
        *(REPO_ROOT / "automated_security_helper").rglob("README.md"),
        REPO_ROOT / "README.md",
    }
    for path in sorted(sources):
        text = path.read_text(encoding="utf-8")
        for line, job_id, steps in yaml_example_jobs(text):
            yield f"{path.relative_to(REPO_ROOT)}:{line}", job_id, steps


#: Docs-shaped examples the reader must find and flag: an upload with no `if:` after an
#: ASH step that can fail, once in a full workflow and once as a bare list of steps.
SYNTHETIC_DOCS_EXAMPLES = """
A workflow:

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - run: ash --mode local
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          path: .ash/ash_output/reports
```

The steps to add to your job:

```yaml
- name: Run ASH
  run: uvx --from automated-security-helper ash --mode local
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: .ash/ash_output/reports/ash.ghas.sarif
```

Not GitHub Actions, so not read:

```yaml
reporters:
  sarif:
    enabled: true
```
"""


def test_a_condition_on_a_failed_outcome_calls_a_status_function():
    conditions, missing_status, _, _ = _scan()
    assert conditions > 50, (
        f"only {conditions} if: conditions found; the scan is broken"
    )
    assert not missing_status, (
        "these if: conditions read a failed or skipped outcome but call no status "
        "function, so GitHub's implicit success() && makes them false exactly when "
        "they are meant to hold:\n" + "\n".join(missing_status)
    )


#: An `if:` at the start of a comment's text, as in a USAGE block, optionally as a list
#: item. Prose that mentions "`if:`" mid-sentence does not match.
_COMMENT_IF = re.compile(r"^\s*#(?P<indent>\s*)(?:-\s+)?if:\s*(?P<value>.*)$")
_COMMENT = re.compile(r"^\s*#(?P<indent>\s*)(?P<text>.*)$")


def comment_conditions(text: str) -> Iterator[tuple[int, str]]:
    """(line, condition) for each `if:` written inside a comment, block scalars joined."""
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        found = _COMMENT_IF.match(line)
        if not found:
            continue
        value = found.group("value").strip()
        if value in ("|", "|-", ">", ">-"):
            parts = []
            for following in lines[number:]:
                more = _COMMENT.match(following)
                if not more or len(more.group("indent")) <= len(found.group("indent")):
                    break
                parts.append(more.group("text").strip())
            value = " ".join(parts)
        yield number, value


def test_a_condition_in_a_usage_comment_calls_a_status_function():
    """Callers copy the USAGE blocks in workflow comments, which no `if:` key holds."""
    found, missing = [], []
    for path in workflow_files():
        where = path.relative_to(REPO_ROOT)
        for line, condition in comment_conditions(path.read_text(encoding="utf-8")):
            found.append(f"{where}:{line}")
            if lacks_status_after_failure(condition):
                missing.append(f"{where}:{line}: {condition}")
    assert any("upload-ash-sarif.yml" in f for f in found), (
        f"the comment reader finds no usage `if:` in upload-ash-sarif.yml: {found}"
    )
    assert not missing, (
        "these usage examples in comments read a failed or skipped outcome but call "
        "no status function, so a caller who copies one gets GitHub's implicit "
        "success() and skips the job after every failed scan:\n" + "\n".join(missing)
    )


def test_the_comment_reader_joins_a_folded_condition():
    text = (
        "#  USAGE\n"
        "#      sarif:\n"
        "#        if: >-\n"
        "#          (needs.ash.result == 'success' || needs.ash.result == 'failure')\n"
        "#          && needs.ash.outputs.artifact-id != ''\n"
        "#        uses: ./x.yml\n"
        "#  Prose about a job whose `if:` is false is not a condition.\n"
        "#    - if: steps.scan.outcome == 'failure'\n"
    )
    conditions = list(comment_conditions(text))
    folded = (
        "(needs.ash.result == 'success' || needs.ash.result == 'failure') "
        "&& needs.ash.outputs.artifact-id != ''"
    )
    assert conditions == [
        (3, folded),
        (8, "steps.scan.outcome == 'failure'"),
    ], conditions
    assert all(lacks_status_after_failure(c) for _, c in conditions)


def test_an_upload_after_the_scan_runs_when_the_scan_fails():
    _, _, uploads, found = _scan()
    assert any(
        "run-ash-security-scan.yml" in f and "Collect ASH output artifact" in f
        for f in found
    ), found
    assert any("run-scan-test/action.yml" in f for f in found), found
    assert not uploads, (
        "these uploads follow a step that runs ASH but would be skipped when the scan "
        "fails on findings:\n" + "\n".join(uploads)
    )


def test_an_upload_after_the_scan_in_a_docs_example_runs_when_the_scan_fails():
    found, missing = [], []
    for where, job_id, steps in docs_example_jobs():
        found += [f"{where} {job_id}" for _ in _uploads_after_scan(steps)]
        missing += [
            f"{where}: job {job_id}: {name}"
            for name in uploads_after_ash_without_status(steps)
        ]
    # The reader is held to SYNTHETIC_DOCS_EXAMPLES below; this only makes sure the
    # real pages gave it something to check, without counting pages.
    assert found, (
        "no docs example uploads results after an ASH step, so this checked nothing: "
        "the examples moved, or the reader no longer reads them"
    )
    assert not missing, (
        "these docs examples upload results after an ASH step that fails on findings, "
        "with no status function, so a copy of the example uploads nothing when it "
        "finds something:\n" + "\n".join(missing)
    )


def test_the_docs_reader_flags_an_upload_with_no_status_function():
    flagged = [
        (job_id, name)
        for _, job_id, steps in yaml_example_jobs(SYNTHETIC_DOCS_EXAMPLES)
        for name in uploads_after_ash_without_status(steps)
    ]
    assert flagged == [("scan", "Upload results"), (STEP_LIST, "Upload SARIF")], flagged


@pytest.mark.parametrize(
    "condition",
    [
        "needs.ash.result == 'failure'",
        "(needs.ash.result == 'success' || needs.ash.result == 'failure') && x",
        "steps.scan.outcome != 'success'",
        "steps.scan.conclusion == 'failure'",
        "job.status == 'cancelled'",
    ],
)
def test_the_checker_flags_a_failed_outcome_without_a_status_function(condition):
    assert lacks_status_after_failure(condition)


@pytest.mark.parametrize(
    "condition",
    [
        "${{ !cancelled() && needs.ash.outputs.artifact-id != '' }}",
        "always() && needs.ash.result == 'failure'",
        "failure() && steps.scan.outcome == 'failure'",
        "steps.pull.outcome == 'success' && github.event_name == 'push'",
        "inputs.install-cfn-nag",
        None,
    ],
)
def test_the_checker_accepts_a_condition_that_can_hold(condition):
    assert not lacks_status_after_failure(condition)


def test_the_upload_checker_flags_an_upload_skipped_after_a_failed_scan():
    steps = [
        {"name": "Run ASH", "run": "ash --mode local"},
        {"name": "Upload", "uses": "actions/upload-artifact@v4"},
        {"name": "SARIF", "uses": "github/codeql-action/upload-sarif@v3", "if": "true"},
        {"name": "Kept", "uses": "actions/upload-artifact@v4", "if": "!cancelled()"},
    ]
    assert uploads_after_ash_without_status(steps) == ["Upload", "SARIF"]
    assert uploads_after_ash_without_status(steps[1:]) == []
    assert (
        uploads_after_ash_without_status(
            [{"run": "bash scripts/x.sh"}, {"uses": "actions/upload-artifact@v4"}]
        )
        == []
    )
    # A scan that cannot fail on findings does not need the upload to outlast it.
    assert (
        uploads_after_ash_without_status(
            [
                {"run": "ash scan --no-fail-on-findings"},
                {"uses": "actions/upload-artifact@v4"},
            ]
        )
        == []
    )


class TestTheModelAppliesTheImplicitSuccess:
    def _holds(self, condition: Any, status: str) -> bool:
        return ga.condition_holds(condition, {"__status__": status, "needs": {}})

    def test_a_condition_without_a_status_function_is_false_after_a_failure(self):
        assert not self._holds("true", "failure")
        assert not self._holds("1 == 1", "failure")
        assert self._holds("1 == 1", "success")

    def test_a_status_function_replaces_the_implicit_success(self):
        assert self._holds("${{ !cancelled() && 1 == 1 }}", "failure")
        assert self._holds("failure()", "failure")
        assert not self._holds("${{ !cancelled() }}", "cancelled")

    @pytest.mark.parametrize(
        ("results", "runs"),
        [
            (["success"], True),
            (["failure"], False),
            (["success", "failure"], False),
            (["skipped"], False),
        ],
    )
    def test_a_jobs_status_comes_from_the_jobs_it_needs(self, results, runs):
        job = {"needs": [f"j{i}" for i in range(len(results))], "if": "1 == 1"}
        context = ga.base_context(event_name="pull_request")
        context["needs"] = {
            f"j{i}": {"result": r, "outputs": {}} for i, r in enumerate(results)
        }
        assert ga.job_runs(job, context) is runs
        always = {**job, "if": "always()"}
        assert ga.job_runs(always, context) is True
