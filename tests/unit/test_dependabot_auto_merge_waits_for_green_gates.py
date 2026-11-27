# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The dependabot auto-merge workflow approves only after every other required gate.

Why this file exists
--------------------
The workflow used to approve at pull-request-open time, for patch and minor bumps
outside the github_actions ecosystem. A grouped actions bump (the "actions group"
PRs) was skipped without a word, and a bump that did qualify was approved before a
single check had run. The policy now is: patch, minor and grouped dependabot bumps
are approved in every ecosystem, a bump with a major upgrade in it never is, and
only once every OTHER required check on the PR's head is complete and successful.
The update types are parsed from the metadata block in dependabot's commit message.

What is pinned
--------------
* The trigger is ``workflow_run`` on exactly the workflows that run on a pull
  request, so the decision is re-armed by each completion and the last one sees the
  full set green. A workflow that gains a ``pull_request`` trigger must be added to
  the list, or its result would never re-arm the decision.
* The shape zizmor hardened stays: no workflow-level grant, no checkout, the mint
  scoped to ``permission-pull-requests`` and run only after an approving decision,
  the PR number and head sha passed through env.
* The decision step is RUN, with a stub ``gh`` that serves canned API answers, so
  the cases below measure the real script: an all-green head approves, one failing
  or pending required check does not, a non-required failure does not hold it, the
  workflow's own check never blocks it, and a fork, a stale head or a human author
  never approves.

Known limits
------------
The stub serves the shape the GraphQL query asks for; nothing here proves GitHub
returns it. The first dependabot PR through the new trigger is the live check, and
the workflow header names that residual.

On a Windows host the script runs under Git for Windows' bash and the host's own jq,
in ``--binary`` mode so that its lines end the way the runner's do (``_install_jq``).
That measures the policy, not the runner: the unit tier's ubuntu legs are the ones
that run the script under an ubuntu image's bash and jq, as the workflow does.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

from tests.utils.github_actions import git_for_windows_bash

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
THIS = "ash-dependabot-auto-merge.yml"

#: Workflows with a pull_request trigger that do not report a gate on the PR head:
#: this workflow, and the tagging workflow, which fires on the closed event.
NOT_GATES = {THIS, "ash-tag-on-merge.yml"}

REPO = "awslabs/automated-security-helper"
SHA = "a" * 40


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(workflow: dict) -> dict:
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    return triggers


WORKFLOW = _load(WORKFLOWS / THIS)
JOB = WORKFLOW["jobs"]["auto-merge"]
STEPS = {step.get("id") or step["name"]: step for step in JOB["steps"]}


# ----------------------------------------------------------------------------
# Structure
# ----------------------------------------------------------------------------


def test_the_trigger_is_workflow_run_completed_only():
    triggers = _triggers(WORKFLOW)
    assert set(triggers) == {"workflow_run"}, (
        "an approval at pull_request time precedes the gates; only a completion "
        f"event may arm the decision, got {sorted(triggers)}"
    )
    assert triggers["workflow_run"]["types"] == ["completed"]


def test_the_listened_workflows_are_exactly_the_pull_request_gates():
    expected = set()
    for path in sorted(WORKFLOWS.glob("*.yml")):
        if path.name in NOT_GATES:
            continue
        workflow = _load(path)
        if "pull_request" in _triggers(workflow):
            expected.add(workflow["name"])
    assert expected, "no pull_request workflow was read; the control is dead"
    listened = set(_triggers(WORKFLOW)["workflow_run"]["workflows"])
    assert listened == expected, (
        f"missing: {sorted(expected - listened)}; "
        f"names no workflow has: {sorted(listened - expected)}"
    )


def test_the_workflow_never_listens_to_itself():
    assert WORKFLOW["name"] not in _triggers(WORKFLOW)["workflow_run"]["workflows"]


def test_least_privilege_shape_is_kept():
    assert WORKFLOW["permissions"] == {}
    assert JOB["permissions"] == {
        "pull-requests": "read",
        "checks": "read",
        "statuses": "read",
    }
    uses = [step.get("uses", "") for step in JOB["steps"]]
    assert not any(u.startswith("actions/checkout") for u in uses), (
        "a checkout would put PR content on a runner that holds a write token"
    )
    assert not any("fetch-metadata" in u for u in uses), (
        "fetch-metadata cannot run on workflow_run and its scope filter is gone"
    )
    assert "pull_request_target" not in _triggers(WORKFLOW)


def test_the_job_is_limited_to_this_repository_and_to_successful_pr_runs():
    condition = JOB["if"]
    assert "github.repository == 'awslabs/automated-security-helper'" in condition
    assert "github.event.workflow_run.event == 'pull_request'" in condition
    assert "github.event.workflow_run.conclusion == 'success'" in condition


def test_the_token_is_minted_scoped_and_only_after_an_approving_decision():
    mint = STEPS["app-token"]
    assert mint["with"]["permission-pull-requests"] == "write"
    assert [k for k in mint["with"] if k.startswith("permission-")] == [
        "permission-pull-requests"
    ]
    assert mint["with"]["repositories"] == "automated-security-helper"
    assert mint["if"] == "steps.decide.outputs.approve == 'true'"
    approve = STEPS["Approve the PR and enable auto-merge"]
    assert approve["if"] == "steps.decide.outputs.approve == 'true'"
    assert approve["env"]["GH_TOKEN"] == "${{ steps.app-token.outputs.token }}"


def test_no_ecosystem_filter_remains():
    text = (WORKFLOWS / THIS).read_text(encoding="utf-8")
    code = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    for stale in ("package-ecosystem", "github_actions", "steps.metadata"):
        assert stale not in code, f"the old scope filter survives: {stale}"


def test_pr_derived_strings_reach_the_script_only_through_env():
    for step in JOB["steps"]:
        script = step.get("run", "")
        assert "${{" not in script, f"{step.get('name')} interpolates into its script"


def test_the_approval_is_bound_to_the_head_the_gates_were_read_on():
    script = STEPS["Approve the PR and enable auto-merge"]["run"]
    assert 'commit_id="$HEAD_SHA"' in script
    assert '--match-head-commit "$HEAD_SHA"' in script


# ----------------------------------------------------------------------------
# Behavior: the decision step, run against a stub gh
# ----------------------------------------------------------------------------


def _decide_script() -> str:
    assert "decide" in STEPS, "the workflow has no decision step"
    return STEPS["decide"]["run"]


STUB_GH = """#!/usr/bin/env bash
case "$*" in
  "api graphql"*) cat "$STUB_DIR/graphql.json" ;;
  "api --paginate repos/"*"/pulls/"*"/commits") cat "$STUB_DIR/commits.json" ;;
  "api repos/"*"/pulls/"*) cat "$STUB_DIR/pull.json" ;;
  *) echo "unexpected gh call: $*" >&2; exit 97 ;;
esac
"""

#: The jq the decision step runs here: the first one on this process's PATH.
#: ``needs_jq`` skips the cases when there is none, and ``_install_jq`` hands the
#: script this one, so the guard and the run read the same jq.
JQ = shutil.which("jq")


def _install_jq(bin_dir: Path) -> None:
    """Put a ``jq`` in ``bin_dir`` that runs ``JQ``, the jq ``needs_jq`` found.

    The script searches the short PATH ``_run`` gives it, not this process's PATH, so
    a jq the guard found anywhere else was out of its reach. On the windows-latest
    runner that was every case that runs the script: the guard found the image's jq,
    and the script stopped at its first jq call with "jq: command not found" (exit
    127), because none of the directories Git for Windows' bash reads
    ``/usr/local/bin:/usr/bin:/bin`` as holds a jq.

    A native Windows jq also ends each line it prints with CRLF unless it is given
    ``--binary``. jq's manual: "Windows users using WSL, MSYS2, or Cygwin, should use
    this option when using a native jq.exe, otherwise jq will turn newlines (LFs)
    into carriage-return-then-newline (CRLF)." The script compares what jq prints
    (``[ "$author" = "dependabot[bot]" ]``), so on Windows the wrapper passes the
    option, and the script reads the lines the ubuntu-latest runner's jq would print.
    """
    assert JQ is not None, "only the cases marked needs_jq run the script"
    binary = " --binary" if os.name == "nt" else ""
    wrapper = bin_dir / "jq"
    wrapper.write_text(
        f'#!/bin/sh\nexec {shlex.quote(Path(JQ).as_posix())}{binary} "$@"\n',
        encoding="utf-8",
        newline="\n",
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)


def _run(
    tmp_path: Path,
    *,
    pull: dict | None = None,
    pages: list[list[dict]] | None = None,
    pull_requests: list | None = None,
    head_sha: str = SHA,
    commits: list[dict] | None = None,
) -> dict[str, str]:
    tmp_path = Path(tempfile.mkdtemp(dir=tmp_path))
    stub_dir = tmp_path / "stub"
    bin_dir = tmp_path / "bin"
    stub_dir.mkdir()
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    # newline="\n": a text write on Windows ends each line with CRLF, and bash keeps
    # a CR as part of the word before it, so under Git for Windows' bash the stub's
    # `case "$*" in` would end in "in\r" and not parse.
    gh.write_text(STUB_GH, encoding="utf-8", newline="\n")
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
    _install_jq(bin_dir)

    base_pull = {
        "user": {"login": "dependabot[bot]"},
        "state": "open",
        "head": {"sha": SHA, "repo": {"full_name": REPO}},
    }
    (stub_dir / "pull.json").write_text(json.dumps(pull or base_pull))
    # gh --paginate prints one JSON array per page; two pages exercise the merge.
    pages_of_commits = [commits if commits is not None else [_commit(["minor"])]]
    if commits is not None and len(commits) > 1:
        pages_of_commits = [commits[:1], commits[1:]]
    (stub_dir / "commits.json").write_text(
        "\n".join(json.dumps(page) for page in pages_of_commits)
    )
    documents = [
        {
            "data": {
                "repository": {
                    "pullRequest": {
                        "commits": {
                            "nodes": [
                                {
                                    "commit": {
                                        "statusCheckRollup": {
                                            "contexts": {"nodes": nodes}
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }
        for nodes in (pages if pages is not None else [[_run_ok("build")]])
    ]
    (stub_dir / "graphql.json").write_text("\n".join(json.dumps(d) for d in documents))

    output = tmp_path / "github_output"
    output.write_text("")
    # The decision step runs under bash. On a Windows runner a bare "bash" is the WSL
    # launcher, which has no distribution installed, so Git for Windows' bash is used,
    # with its paths written the way that bash reads them.
    env = {
        "PATH": f"{bin_dir.as_posix()}:/usr/local/bin:/usr/bin:/bin",
        "HOME": tmp_path.as_posix(),
        "STUB_DIR": stub_dir.as_posix(),
        "GH_TOKEN": "not-a-token",
        "REPO": REPO,
        "HEAD_SHA": head_sha,
        "PULL_REQUESTS": json.dumps(
            [{"number": 1104}] if pull_requests is None else pull_requests
        ),
        "SELF_CHECK": "auto-merge",
        "GITHUB_OUTPUT": output.as_posix(),
    }
    if os.name == "nt":
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
    result = subprocess.run(
        [git_for_windows_bash() or "bash", "-c", _decide_script()],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    values = dict(
        line.split("=", 1) for line in output.read_text().splitlines() if "=" in line
    )
    values["_stdout"] = result.stdout
    return values


def _commit(types: list[str], author: str = "dependabot[bot]") -> dict:
    """A commit as the API lists it, with the metadata block dependabot writes.

    ``types`` are the bare semver words (``minor``) or ``""`` for the empty type of
    an update dependabot computed no level for.
    """
    block = "".join(
        f"- dependency-name: dep{i}\n  dependency-type: direct:production\n"
        f"  update-type: {'version-update:semver-' + t if t else ''}\n"
        for i, t in enumerate(types)
    )
    message = (
        "ci: bump the actions group\n\nBumps the group.\n\n---\n"
        f"updated-dependencies:\n{block}...\n\nSigned-off-by: dependabot[bot]"
    )
    return {"author": {"login": author}, "commit": {"message": message}}


def _run_ok(name: str, required: bool = True) -> dict:
    return {
        "__typename": "CheckRun",
        "name": name,
        "status": "COMPLETED",
        "conclusion": "SUCCESS",
        "isRequired": required,
    }


def _check(name: str, status: str, conclusion: str | None, required: bool = True):
    return {
        "__typename": "CheckRun",
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "isRequired": required,
    }


needs_jq = pytest.mark.skipif(JQ is None, reason="jq is required")


@needs_jq
def test_an_all_green_head_approves_and_names_the_pr(tmp_path):
    out = _run(
        tmp_path,
        pages=[[_run_ok("build"), _run_ok("test"), _run_ok("lint", required=False)]],
    )
    assert out["approve"] == "true"
    assert out["pr"] == "1104"


@needs_jq
def test_an_actions_group_bump_is_no_longer_skipped(tmp_path):
    """The shape of PR 1104: a grouped github_actions bump with four updates."""
    pull = {
        "title": "ci: bump the actions group across 1 directory with 4 updates",
        "user": {"login": "dependabot[bot]"},
        "state": "open",
        "head": {
            "ref": "dependabot/github_actions/actions-b02de50619",
            "sha": SHA,
            "repo": {"full_name": REPO},
        },
    }
    assert _run(tmp_path, pull=pull)["approve"] == "true"


@needs_jq
def test_one_failing_required_check_does_not_approve(tmp_path):
    out = _run(
        tmp_path,
        pages=[[_run_ok("build"), _check("test", "COMPLETED", "FAILURE")]],
    )
    assert out["approve"] == "false"
    assert "test" in out["_stdout"]


@needs_jq
def test_one_pending_required_check_does_not_approve(tmp_path):
    out = _run(
        tmp_path,
        pages=[[_run_ok("build"), _check("test", "IN_PROGRESS", None)]],
    )
    assert out["approve"] == "false"
    assert "test" in out["_stdout"]


@needs_jq
def test_a_queued_required_check_does_not_approve(tmp_path):
    out = _run(tmp_path, pages=[[_check("test", "QUEUED", None)]])
    assert out["approve"] == "false"


@needs_jq
def test_a_failing_status_context_does_not_approve(tmp_path):
    status = {
        "__typename": "StatusContext",
        "context": "legacy/ci",
        "state": "PENDING",
        "isRequired": True,
    }
    assert _run(tmp_path, pages=[[_run_ok("build"), status]])["approve"] == "false"
    status["state"] = "SUCCESS"
    assert _run(tmp_path, pages=[[_run_ok("build"), status]])["approve"] == "true"


@needs_jq
def test_a_failing_non_required_check_does_not_hold_the_approval(tmp_path):
    out = _run(
        tmp_path,
        pages=[
            [
                _run_ok("build"),
                _check("informational", "COMPLETED", "FAILURE", required=False),
            ]
        ],
    )
    assert out["approve"] == "true"


@needs_jq
def test_skipped_and_neutral_required_checks_count_as_passing(tmp_path):
    pages = [
        [
            _check("a", "COMPLETED", "SKIPPED"),
            _check("b", "COMPLETED", "NEUTRAL"),
            _run_ok("c"),
        ]
    ]
    assert _run(tmp_path, pages=pages)["approve"] == "true"


@needs_jq
def test_the_workflows_own_check_never_blocks_itself(tmp_path):
    own = _check("auto-merge", "IN_PROGRESS", None)
    assert _run(tmp_path, pages=[[_run_ok("build"), own]])["approve"] == "true"
    # The control: the same pending check under any other name does block.
    other = _check("not-me", "IN_PROGRESS", None)
    assert _run(tmp_path, pages=[[_run_ok("build"), other]])["approve"] == "false"


@needs_jq
def test_a_head_with_no_required_check_fails_closed(tmp_path):
    out = _run(tmp_path, pages=[[_run_ok("build", required=False)]])
    assert out["approve"] == "false"
    out = _run(tmp_path, pages=[[]])
    assert out["approve"] == "false"


@needs_jq
def test_required_checks_on_a_later_page_are_read(tmp_path):
    pages = [[_run_ok("build")], [_check("test", "COMPLETED", "FAILURE")]]
    assert _run(tmp_path, pages=pages)["approve"] == "false"
    pages = [[_run_ok("build")], [_run_ok("test")]]
    assert _run(tmp_path, pages=pages)["approve"] == "true"


@needs_jq
def test_a_human_authored_pr_is_never_approved(tmp_path):
    pull = {
        "user": {"login": "someone"},
        "state": "open",
        "head": {"sha": SHA, "repo": {"full_name": REPO}},
    }
    assert _run(tmp_path, pull=pull)["approve"] == "false"


@needs_jq
def test_a_fork_pr_is_never_approved(tmp_path):
    pull = {
        "user": {"login": "dependabot[bot]"},
        "state": "open",
        "head": {
            "sha": SHA,
            "repo": {"full_name": "someone/automated-security-helper"},
        },
    }
    assert _run(tmp_path, pull=pull)["approve"] == "false"


@needs_jq
def test_a_run_for_an_older_head_is_never_approved(tmp_path):
    pull = {
        "user": {"login": "dependabot[bot]"},
        "state": "open",
        "head": {"sha": "b" * 40, "repo": {"full_name": REPO}},
    }
    assert _run(tmp_path, pull=pull)["approve"] == "false"


@needs_jq
def test_a_closed_pr_is_never_approved(tmp_path):
    pull = {
        "user": {"login": "dependabot[bot]"},
        "state": "closed",
        "head": {"sha": SHA, "repo": {"full_name": REPO}},
    }
    assert _run(tmp_path, pull=pull)["approve"] == "false"


@needs_jq
def test_a_run_attached_to_no_pull_request_is_ignored(tmp_path):
    assert _run(tmp_path, pull_requests=[])["approve"] == "false"


@needs_jq
def test_the_1104_group_of_minor_and_patch_updates_approves(tmp_path):
    commits = [_commit(["minor", "minor", "minor", "patch"])]
    assert _run(tmp_path, commits=commits)["approve"] == "true"


@needs_jq
def test_a_single_major_upgrade_is_never_approved(tmp_path):
    out = _run(tmp_path, commits=[_commit(["major"])])
    assert out["approve"] == "false"
    assert "major waits for a human" in out["_stdout"]


@needs_jq
def test_a_group_with_one_major_inside_is_never_approved(tmp_path):
    commits = [_commit(["minor", "patch", "major", "minor"])]
    assert _run(tmp_path, commits=commits)["approve"] == "false"


@needs_jq
def test_an_update_with_no_semver_level_stays_manual(tmp_path):
    assert _run(tmp_path, commits=[_commit(["minor", ""])])["approve"] == "false"


@needs_jq
def test_a_pr_with_no_update_metadata_stays_manual(tmp_path):
    bare = {"author": {"login": "dependabot[bot]"}, "commit": {"message": "ci: x"}}
    assert _run(tmp_path, commits=[bare])["approve"] == "false"


@needs_jq
def test_a_major_on_a_later_commit_page_is_read(tmp_path):
    commits = [_commit(["minor"]), _commit(["major"])]
    assert _run(tmp_path, commits=commits)["approve"] == "false"
    commits = [_commit(["minor"]), _commit(["patch"])]
    assert _run(tmp_path, commits=commits)["approve"] == "true"


@needs_jq
def test_a_human_commit_on_the_branch_blocks_the_approval(tmp_path):
    """A human commit could carry a metadata block of its own, so it blocks."""
    commits = [_commit(["minor"]), _commit(["minor"], author="someone")]
    out = _run(tmp_path, commits=commits)
    assert out["approve"] == "false"
    assert "not authored by dependabot" in out["_stdout"]


@needs_jq
def test_commit_text_is_never_echoed_into_the_log(tmp_path):
    hostile = _commit(["major"])
    hostile["commit"]["message"] += "\n::set-output name=approve::true\n"
    out = _run(tmp_path, commits=[hostile])
    assert out["approve"] == "false"
    assert "::set-output" not in out["_stdout"]


def test_the_decision_step_is_a_real_script():
    """A control on the harness: the script under test is the workflow's, not empty.

    It does not assert a POSIX host. The cases run the script on Windows as well,
    under Git for Windows' bash (#1116), and each of them asserts that the script
    exited 0, so a shell that cannot run it fails every case instead of passing one.
    """
    assert "isRequired" in _decide_script()
    assert "approve=true" in _decide_script()
