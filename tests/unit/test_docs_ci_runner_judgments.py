# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How a CI-runner run is judged: the checks that decide whether a block passed.

WHY THIS EXISTS
---------------
The runs happen only on a GitHub-hosted runner, so every judgment the runner tests
make is checked here on synthetic logs and output trees, including the ways a check
could pass without proving anything:

* a negative control whose runner never started, or whose install failed on something
  other than the broken input, is not a control;
* the wheel is hashed again after each launch, since uv never checks the sha256 in its
  URL;
* the reusable workflow's install is proved by the record its own rewritten workflow
  prints, never by a log line that names the repository and the commit;
* each job run with an install print shows exactly one record, matrix entries counted;
* every job that gates on findings, in every matrix run, gives exactly one verdict;
* the jobs of a called workflow are expected under their own ids, and a workflow with
  nothing to expect fails;
* the stub actions' records are read: the check run's failures and the comment;
* the merged results are written after the merge step started;
* CodeBuild's report is JUnit with the findings as failures, and GitLab's gate reads
  the exit code the scan job kept;
* nothing secret-shaped and nothing under a dot directory is kept for upload;
* a step that stops workflow commands prints its resume line.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import sys
import types
import zipfile
import zlib
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
PACKAGE = "_ash_ci_runners"
HEAD = "0123456789abcdef0123456789abcdef01234567"
BASE = "f" * 40
REPOSITORY = "awslabs/automated-security-helper"
TOKEN = "0a1b2c3d4e5f60718293a4b5c6d7e8f9"


def _module(stem: str):
    if PACKAGE not in sys.modules:
        init = CI_RUNNERS / "__init__.py"
        if not init.is_file():
            pytest.fail("missing tests/integration/docs/ci_runners/__init__.py")
        spec = importlib.util.spec_from_file_location(
            PACKAGE, init, submodule_search_locations=[str(CI_RUNNERS)]
        )
        assert spec and spec.loader
        package = importlib.util.module_from_spec(spec)
        sys.modules[PACKAGE] = package
        spec.loader.exec_module(package)
    if not (CI_RUNNERS / f"{stem}.py").is_file():
        pytest.fail(f"missing tests/integration/docs/ci_runners/{stem}.py")
    return importlib.import_module(f"{PACKAGE}.{stem}")


def _api(stem: str, name: str):
    module = _module(stem)
    if not hasattr(module, name):
        pytest.fail(f"tests/integration/docs/ci_runners/{stem}.py defines no {name}")
    return getattr(module, name)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _act(job: str, msg: str, matrix: dict | None = None, **fields) -> str:
    return json.dumps(
        {
            "job": job,
            "jobID": job,
            "level": "info",
            "matrix": matrix or {},
            "msg": msg,
            "time": "2026-10-12T21:00:00Z",
            **fields,
        }
    )


def _applied(rule: str, job: str | None = None, count: int = 1, matrix: bool = False):
    return types.SimpleNamespace(
        rule=rule, old="", new="", count=count, job=job, matrix=matrix
    )


def _run(runner: str, kind: str, event: str | None = "pull_request", changed=False):
    return _api("census", "CensusRun")(
        runner=runner,
        page="docs/content/how-to/ci/example.md",
        ordinal=1,
        line=10,
        kind=kind,
        event=event,
        changed_files=changed,
        composed_from=None,
    )


KINDS = {
    "act": "github-actions",
    "gitlab-ci-local": "gitlab-ci",
    "jenkinsfile-runner-lts": "jenkinsfile",
    "jenkinsfile-runner-bundled": "jenkinsfile",
    "codebuild-agent": "buildspec",
    "circleci": "circleci",
}

RELEASE = (
    "automated-security-helper[cdk] @ git+https://github.com/awslabs/"
    "automated-security-helper"
    ".git@v1.2.3"
)
REUSABLE_CALL = (
    "uses: awslabs/automated-security-helper/.github/workflows/"
    "run-ash-security-scan.yml@v1.2.3"
)


def _wheel(tmp_path: Path) -> tuple[Path, str]:
    wheel = tmp_path / "wheel" / "automated_security_helper-3.7.0-py3-none-any.whl"
    wheel.parent.mkdir(parents=True, exist_ok=True)
    wheel.write_bytes(b"the wheel under test")
    return wheel, hashlib.sha256(wheel.read_bytes()).hexdigest()


def _prepared(
    tmp_path: Path,
    runner: str,
    *,
    rewritten: str = "",
    composed: str | None = None,
    applied=(),
    called=None,
    called_applied=(),
    expected=None,
    event: str | None = "pull_request",
    changed: bool = False,
    under_test=None,
):
    pipelines = _module("pipelines")
    wheel, digest = _wheel(tmp_path)
    project = tmp_path / "project"
    (project / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    out = tmp_path / "out"
    work = tmp_path / "work"
    out.mkdir(exist_ok=True)
    work.mkdir(exist_ok=True)
    if composed is None:
        composed = (
            REUSABLE_CALL
            if "run-ash-security-scan.yml" in rewritten
            else f'INSTALL_SPEC: "{RELEASE}"\n' + rewritten
        )
    return pipelines.Prepared(
        run=_run(runner, KINDS[runner], event, changed),
        under_test=under_test
        or pipelines.UnderTest(
            wheel=wheel, wheel_sha256=digest, head_sha=HEAD, repository=REPOSITORY
        ),
        path=".github/workflows/ash.yml",
        composed=composed,
        rewritten=rewritten,
        applied=list(applied),
        fixture=types.SimpleNamespace(
            project=project,
            home=tmp_path / "home",
            head_sha=HEAD,
            base_sha=BASE,
            branch="add-changed-file",
        ),
        out=out,
        work=work,
        expected={"app.py": 2, "changed.py": 1} if expected is None else expected,
        called=dict(called or {}),
        called_applied=list(called_applied),
    )


def _launched(tmp_path: Path, text: str, code: int = 1, **extra):
    log = tmp_path / "out" / "runner.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(text, encoding="utf-8")
    return _api("pipelines", "Launched")(log=log, code=code, **extra)


# ---------------------------------------------------------------------------
# A negative control proves something only if the install failed on its input
# ---------------------------------------------------------------------------

#: A runner that could not start at all: no step ran.
NEVER_STARTED = "env: 'java': No such file or directory\n"


def _refusal(runner: str, name: str) -> list[str]:
    """What the installer prints when ``name``, the input a control broke, is not
    there: git's refusal of a commit the repository lacks, inside uv's error under act
    and pip's elsewhere; uv's refusal of a wheel path under act, pip's OSError for one
    elsewhere."""
    if len(name) == 40 and all(c in "0123456789abcdef" for c in name):
        if runner == "act":
            return [
                f"error: Failed to fetch: `git+https://github.com/{REPOSITORY}@{name}`",
                "  Caused by: Git operation failed",
                f"  Caused by: failed to fetch commit `{name}`",
                "--- stderr",
                f"fatal: remote error: upload-pack: not our ref {name}",
            ]
        return [
            "  error: subprocess-exited-with-error",
            (
                f"  × git fetch -q https://github.com/{REPOSITORY}.git {name} did not "
                "run successfully."
            ),
            "  │ exit code: 128",
            "  ╰─> [1 lines of output]",
            f"      fatal: remote error: upload-pack: not our ref {name}",
            "      [end of output]",
        ]
    if runner == "act":
        return [f"error: Distribution not found at: file:///w/{name}"]
    return [
        (
            "ERROR: Could not install packages due to an OSError: [Errno 2] No such "
            f"file or directory: '/ash-wheel/{name}'"
        )
    ]


def _broken_install_log(runner: str, name: str) -> tuple[str, int]:
    """A log in which the job's script started and its install failed on ``name``.

    The lines are the runners' own shapes: act's ``--json`` entries, with what a step
    printed marked ``raw_output``; gitlab-ci-local's ``<job> > `` output lines; the
    CodeBuild agent's container prefix.
    """
    refusal = _refusal(runner, name)
    if runner == "act":
        lines = [
            _act("ash", "⭐ Run Main Install ASH"),
            *(_act("ash", line, raw_output=True) for line in refusal),
            _act("ash", "  ❌  Failure - Main Install ASH"),
            _act("ash", "🏁  Job failed", jobResult="failure"),
        ]
        return "\n".join(lines), 1
    if runner == "gitlab-ci-local":
        lines = [
            'ash-scan $ /opt/ash/bin/pip install --quiet "$INSTALL_SPEC"',
            *(f"ash-scan > {line}" for line in refusal),
            "ash-scan finished in 3 s FAIL",
        ]
        return "\n".join(lines), 1
    if runner.startswith("jenkinsfile-runner"):
        lines = [
            "[Pipeline] sh",
            f"+ pip install --quiet automated-security-helper[cdk] @ file:///w/{name}",
            *refusal,
            "ERROR: script returned exit code 1",
            "Finished: FAILURE",
        ]
        return "\n".join(lines), 1
    if runner == "codebuild-agent":
        prefix = "build_1  | [Container] 2026/10/12 21:04:05"
        lines = [
            f"{prefix} Entering phase INSTALL",
            f"{prefix} Running command /opt/ash/bin/pip install",
            *(f"build_1  | {line}" for line in refusal),
            f"{prefix} Phase complete: INSTALL State: FAILED",
        ]
        return "\n".join(lines), 0
    lines = [
        "====>> Install ASH and the scanner tools",
        "  #!/bin/bash -eo pipefail",
        '"$HOME/ash-venv/bin/pip" install --quiet "$INSTALL_SPEC"',
        *refusal,
        "Error: Exited with code exit status 1",
    ]
    return "\n".join(lines), 1


RUNNERS = sorted(KINDS)


@pytest.mark.parametrize("runner", RUNNERS)
def test_a_control_whose_runner_never_started_fails(tmp_path, runner):
    """Exit 127, an empty job log, and no verdict."""
    prepared = _prepared(tmp_path, runner)
    launched = _launched(tmp_path, NEVER_STARTED, code=127)
    problems = _api("pipelines", "control_problems")(prepared, launched)
    assert problems, "a runner that never started is not a negative control"


@pytest.mark.parametrize("runner", RUNNERS)
def test_a_control_whose_install_failed_on_the_broken_wheel_passes(tmp_path, runner):
    pipelines = _module("pipelines")
    name = (
        pipelines.ABSENT_COMMIT
        if runner == "codebuild-agent"
        else pipelines.ABSENT_WHEEL_NAME
    )
    prepared = _prepared(tmp_path, runner)
    text, code = _broken_install_log(runner, name)
    assert pipelines.control_problems(prepared, _launched(tmp_path, text, code)) == []


@pytest.mark.parametrize("runner", RUNNERS)
def test_a_control_must_fail_on_the_input_it_broke(tmp_path, runner):
    """The script started and failed, but on something else: not this control."""
    prepared = _prepared(tmp_path, runner)
    text, code = _broken_install_log(runner, "some-other-file.whl")
    problems = _api("pipelines", "control_problems")(
        prepared, _launched(tmp_path, text, code)
    )
    assert problems and any("names" in p or "broken" in p for p in problems), problems


@pytest.mark.parametrize("runner", ["gitlab-ci-local", "jenkinsfile-runner-lts"])
def test_a_control_whose_script_never_started_fails_even_naming_the_input(
    tmp_path, runner
):
    """The runner itself named the missing wheel, and no job script ran."""
    pipelines = _module("pipelines")
    prepared = _prepared(tmp_path, runner)
    text = f"error: {pipelines.ABSENT_WHEEL_NAME} does not exist\n"
    problems = pipelines.control_problems(prepared, _launched(tmp_path, text, 1))
    assert problems and any("script" in p for p in problems), problems


def test_a_command_echo_naming_the_input_is_not_its_install_failing(tmp_path):
    """Under ``sh -x`` the echo names the wheel; the install failed on another file."""
    pipelines = _module("pipelines")
    prepared = _prepared(tmp_path, "jenkinsfile-runner-lts")
    text, code = _broken_install_log("jenkinsfile-runner-lts", "some-other-file.whl")
    text = text.replace(
        "file:///w/some-other-file.whl", f"file:///w/{pipelines.ABSENT_WHEEL_NAME}"
    )
    problems = pipelines.control_problems(prepared, _launched(tmp_path, text, code))
    assert problems and any("names" in p for p in problems), problems


def test_a_git_control_names_the_absent_commit(tmp_path):
    pipelines = _module("pipelines")
    prepared = _prepared(
        tmp_path,
        "act",
        rewritten="uses: ./.github/workflows/run-ash-security-scan.yml\n",
    )
    assert prepared.mechanism == "git"
    text, code = _broken_install_log("act", pipelines.ABSENT_COMMIT)
    assert pipelines.control_problems(prepared, _launched(tmp_path, text, code)) == []
    text, code = _broken_install_log("act", pipelines.ABSENT_WHEEL_NAME)
    assert pipelines.control_problems(prepared, _launched(tmp_path, text, code))


def _names_problem(problems: list[str]) -> bool:
    return any("names" in problem for problem in problems)


def test_a_control_reads_only_what_was_printed_after_the_script_started(tmp_path):
    """gitlab-ci-local printed the input before the job's script started (a refusal
    of its own, here); after the start the install failed on something else."""
    pipelines = _module("pipelines")
    prepared = _prepared(tmp_path, "gitlab-ci-local")
    early = _refusal("gitlab-ci-local", pipelines.ABSENT_WHEEL_NAME)[0]
    text, code = _broken_install_log("gitlab-ci-local", "some-other-file.whl")
    problems = pipelines.control_problems(
        prepared, _launched(tmp_path, f"{early}\n{text}", code)
    )
    assert _names_problem(problems), problems


def test_a_control_needs_the_installer_s_refusal_not_only_the_name(tmp_path):
    """The install line names the wheel whatever went wrong; only the installer's
    refusal of the path says the wheel was not there."""
    pipelines = _module("pipelines")
    prepared = _prepared(tmp_path, "jenkinsfile-runner-lts")
    name = pipelines.ABSENT_WHEEL_NAME
    text = "\n".join(
        [
            "[Pipeline] sh",
            f"Processing /w/{name}",
            (
                "ERROR: Could not install packages due to an OSError: [Errno 28] No "
                "space left on device"
            ),
            "ERROR: script returned exit code 1",
        ]
    )
    problems = pipelines.control_problems(prepared, _launched(tmp_path, text, 1))
    assert _names_problem(problems), problems


@pytest.mark.parametrize("runner", ["act", "codebuild-agent"])
def test_a_git_control_that_failed_on_the_network_is_not_one(tmp_path, runner):
    """uv and pip quote the whole requirement, so a fetch that failed for any reason
    names the absent commit; only git's own refusal says the commit is not there."""
    pipelines = _module("pipelines")
    if runner == "act":
        prepared = _prepared(
            tmp_path,
            runner,
            rewritten="uses: ./.github/workflows/run-ash-security-scan.yml\n",
        )
    else:
        prepared = _prepared(tmp_path, runner)
    assert prepared.mechanism == "git"
    commit = pipelines.ABSENT_COMMIT
    refusal = _refusal(runner, commit)
    unreachable = (
        "fatal: unable to access 'https://github.com/awslabs/automated-security-helper"
        "/': Could not resolve host: github.com"
    )
    text, code = _broken_install_log(runner, commit)
    text = text.replace(refusal[-2 if runner != "act" else -1], unreachable)
    assert commit in text and "not our ref" not in text
    problems = pipelines.control_problems(prepared, _launched(tmp_path, text, code))
    assert _names_problem(problems), problems


def test_act_s_own_messages_are_not_the_install_s_output(tmp_path):
    """act prints a step's name and its own errors as messages of its own; only what a
    step printed, which act marks raw_output, is the installer's."""
    pipelines = _module("pipelines")
    prepared = _prepared(tmp_path, "act")
    name = pipelines.ABSENT_WHEEL_NAME
    lines = [
        _act("ash", "⭐ Run Main Install ASH"),
        _act("ash", f"  ❗  error: Distribution not found at: file:///w/{name}"),
        _act("ash", "error: some other failure", raw_output=True),
        _act("ash", "  ❌  Failure - Main Install ASH"),
        _act("ash", "🏁  Job failed", jobResult="failure"),
    ]
    problems = pipelines.control_problems(
        prepared, _launched(tmp_path, "\n".join(lines), 1)
    )
    assert _names_problem(problems), problems


def test_the_circleci_agent_s_echo_of_a_command_is_not_its_output(tmp_path):
    """The CircleCI agent prints each run command under ``#!/bin/bash -eo pipefail``
    before it runs it; a line of the command is never the installer's output, however
    it reads."""
    pipelines = _module("pipelines")
    name = pipelines.ABSENT_WHEEL_NAME
    command = (
        f"pip install /ash-wheel/{name} 2>&1 | grep -v 'No such file or directory: "
        f"/ash-wheel/{name}'"
    )
    config = (
        "version: 2.1\njobs:\n  ash:\n    steps:\n      - run:\n"
        f"          name: Install ASH\n          command: {json.dumps(command)}\n"
    )
    prepared = _prepared(tmp_path, "circleci", rewritten=config)
    lines = [
        "====>> Install ASH",
        "  #!/bin/bash -eo pipefail",
        command,
        "ERROR: some other failure",
        "Error: Exited with code exit status 1",
    ]
    problems = pipelines.control_problems(
        prepared, _launched(tmp_path, "\n".join(lines), 1)
    )
    assert _names_problem(problems), problems


@pytest.mark.parametrize(
    "line",
    [
        "fatal: remote error: upload-pack: not our ref {commit}",
        "fatal: couldn't find remote ref {commit}",
    ],
    ids=["not our ref", "no such remote ref"],
)
def test_git_s_refusals_of_an_absent_commit_are_both_read(tmp_path, line):
    pipelines = _module("pipelines")
    prepared = _prepared(tmp_path, "codebuild-agent")
    prefix = "build_1  | [Container] 2026/10/12 21:04:05"
    text = "\n".join(
        [
            f"{prefix} Running command /opt/ash/bin/pip install",
            "build_1  | " + line.format(commit=pipelines.ABSENT_COMMIT),
            f"{prefix} Phase complete: INSTALL State: FAILED",
        ]
    )
    assert pipelines.control_problems(prepared, _launched(tmp_path, text, 0)) == []


def test_uv_s_refusal_of_a_commit_it_fetched_and_did_not_find_is_read(tmp_path):
    """uv fetches a full commit id by itself; were it to fetch the branches and tags
    instead, it says it found no such commit in what it fetched."""
    pipelines = _module("pipelines")
    prepared = _prepared(
        tmp_path,
        "act",
        rewritten="uses: ./.github/workflows/run-ash-security-scan.yml\n",
    )
    commit = pipelines.ABSENT_COMMIT
    lines = [
        _act("ash", "⭐ Run Main Install ASH"),
        _act("ash", "  Caused by: Git operation failed", raw_output=True),
        _act(
            "ash",
            f"  Caused by: failed to find branch, tag, or commit `{commit}`",
            raw_output=True,
        ),
        _act("ash", "🏁  Job failed", jobResult="failure"),
    ]
    launched = _launched(tmp_path, "\n".join(lines), 1)
    assert pipelines.control_problems(prepared, launched) == []


# ---------------------------------------------------------------------------
# The wheel is hashed again after each launch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("runner", ["act", "gitlab-ci-local", "circleci"])
def test_the_wheel_must_still_be_the_one_the_session_hashed(tmp_path, runner):
    check = _api("pipelines", "wheel_hash_problems")
    prepared = _prepared(tmp_path, runner)
    assert check(prepared) == []
    prepared.under_test.wheel.write_bytes(b"another wheel")
    problems = check(prepared)
    assert problems and str(prepared.under_test.wheel) in problems[0]
    prepared.under_test.wheel.unlink()
    assert check(prepared)


def test_a_git_install_has_no_wheel_to_hash(tmp_path):
    prepared = _prepared(tmp_path, "codebuild-agent")
    prepared.under_test.wheel.unlink()
    assert prepared.mechanism == "git"
    assert _api("pipelines", "wheel_hash_problems")(prepared) == []


# ---------------------------------------------------------------------------
# Install records, one per job run with an insertion
# ---------------------------------------------------------------------------


def _record(direct_url: dict) -> list[str]:
    begin = _api("provenance", "PROVENANCE_BEGIN")
    end = _api("provenance", "PROVENANCE_END")
    return [begin, json.dumps(direct_url), end]


def _git_record() -> dict:
    return {
        "url": f"https://github.com/{REPOSITORY}",
        "vcs_info": {"vcs": "git", "commit_id": HEAD, "requested_revision": HEAD},
    }


def _wheel_record(prepared) -> dict:
    uri = _api("provenance", "file_uri")(prepared.under_test.wheel)
    return {
        "url": uri,
        "archive_info": {"hashes": {"sha256": prepared.under_test.wheel_sha256}},
    }


CALLER = """\
on:
  pull_request:
jobs:
  ash:
    uses: ./.github/workflows/run-ash-security-scan.yml
    with:
      ash-version: 0123456789abcdef0123456789abcdef01234567
"""
CALLED = {
    "run-ash-security-scan.yml": """\
on:
  workflow_call:
jobs:
  ash:
    runs-on: ubuntu-latest
    steps:
      - name: Run ASH
        run: uvx --reinstall --from "${ASH_UVX_SOURCE}" ash --source-dir .
      - uses: mikepenz/action-junit-report@a9170d5795813c01ab4901ffb045b52bab4ab09d
      - uses: mshick/add-pr-comment@ec328af66588ab8f77cdeb2c264f14aba45bbf59
"""
}


def test_a_reusable_install_is_proved_by_its_record_and_never_by_a_log_line(tmp_path):
    """uv's progress line names the repository and the commit
    before a fetch that fails; an echo of the source does too."""
    problems = _api("pipelines", "provenance_problems")
    prepared = _prepared(
        tmp_path,
        "act",
        rewritten=CALLER,
        called=CALLED,
        called_applied=[_applied("called-provenance", job="ash")],
    )
    lines = [
        _act("ash", f"  |    Updating https://github.com/{REPOSITORY} ({HEAD})"),
        _act("ash", f"  | installing from git+https://github.com/{REPOSITORY}@{HEAD}"),
    ]
    assert problems(prepared, "\n".join(lines)), "a log line is not an install record"
    lines += [_act("ash", f"  | {line}") for line in _record(_git_record())]
    assert problems(prepared, "\n".join(lines)) == []


def test_the_reusable_record_must_be_of_the_head_commit(tmp_path):
    prepared = _prepared(
        tmp_path,
        "act",
        rewritten=CALLER,
        called=CALLED,
        called_applied=[_applied("called-provenance", job="ash")],
    )
    record = {**_git_record(), "vcs_info": {"vcs": "git", "commit_id": BASE}}
    log = "\n".join(_act("ash", f"  | {line}") for line in _record(record))
    assert _api("pipelines", "provenance_problems")(prepared, log)


SHARDED = """\
on:
  pull_request:
jobs:
  shard:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        shard: [0, 1, 2, 3]
    steps:
      - run: uv tool install "${INSTALL_SPEC}"
      - run: ash scan --no-fail-on-findings --shard-index "${SHARD}" --shard-count 4
  merge:
    needs: shard
    runs-on: ubuntu-latest
    steps:
      - run: uv tool install "${INSTALL_SPEC}"
      - name: Merge the shards
        run: ash merge --fail-on-findings --output-dir .ash/ash_output
"""


def _sharded_prints(prepared, shards: list[int], merge: int = 1) -> str:
    lines = []
    for shard in shards:
        lines += [
            _act("shard", f"  | {line}", {"shard": shard})
            for line in _record(_wheel_record(prepared))
        ]
    for _ in range(merge):
        lines += [
            _act("merge", f"  | {line}") for line in _record(_wheel_record(prepared))
        ]
    return "\n".join(lines)


def test_each_matrix_run_and_each_job_prints_exactly_one_record(tmp_path):
    problems = _api("pipelines", "provenance_problems")
    prepared = _prepared(
        tmp_path,
        "act",
        rewritten=SHARDED,
        applied=[
            _applied("provenance", job="shard", matrix=True),
            _applied("provenance", job="merge"),
        ],
    )
    assert problems(prepared, _sharded_prints(prepared, [0, 1, 2, 3])) == []
    two = _sharded_prints(prepared, [0], merge=1)
    assert problems(prepared, two), "2 prints for 5 job runs"
    extra = _sharded_prints(prepared, [0, 1, 2, 3], merge=2)
    assert problems(prepared, extra), "one record too many"
    twice = _sharded_prints(prepared, [0, 0, 2, 3])
    assert problems(prepared, twice), "one matrix run printed twice, another not at all"


def test_a_record_from_a_job_the_rewrite_added_no_print_to_is_a_problem(tmp_path):
    problems = _api("pipelines", "provenance_problems")
    prepared = _prepared(
        tmp_path,
        "act",
        rewritten=SHARDED,
        applied=[_applied("provenance", job="shard", matrix=True)],
    )
    assert problems(prepared, _sharded_prints(prepared, [0, 1, 2, 3], merge=0)) == []
    found = problems(prepared, _sharded_prints(prepared, [0, 1, 2, 3], merge=1))
    assert found and any("merge" in p for p in found), found


def test_records_without_a_job_are_counted_exactly(tmp_path):
    prepared = _prepared(
        tmp_path, "jenkinsfile-runner-lts", applied=[_applied("provenance")]
    )
    one = "\n".join(_record(_wheel_record(prepared)))
    check = _api("pipelines", "provenance_problems")
    assert check(prepared, one) == []
    assert check(prepared, one + "\n" + one)
    assert check(prepared, "")


# ---------------------------------------------------------------------------
# The controls' own junit file
# ---------------------------------------------------------------------------


def test_the_controls_are_one_per_leg_page_and_mechanism():
    pipelines = _module("pipelines")
    census = _module("census")
    runs = [
        census.CensusRun(
            "act", "a.md", n, n, "github-actions", "pull_request", False, None
        )
        for n in (1, 2, 3, 4)
    ] + [
        census.CensusRun(
            "gitlab-ci-local", "g.md", 1, 1, "gitlab-ci", "push", False, None
        )
    ]
    texts = {
        ("act", 1): REUSABLE_CALL,
        ("act", 2): RELEASE,
        ("act", 3): RELEASE,
        ("act", 4): "no install",
        (
            "gitlab-ci-local",
            1,
        ): "image: registry.example.com/security/automated-security-helper:ci",
    }
    controls = pipelines.negative_controls(
        runs, composed=lambda run: texts[(run.runner, run.ordinal)]
    )
    assert [(run.runner, run.ordinal, mechanism) for run, mechanism in controls] == [
        ("act", 1, "git"),
        ("act", 2, "wheel"),
    ]


def _junit(
    tmp_path: Path, passed: int, skipped: int = 0, tests: int | None = None
) -> Path:
    """A junit file as pytest writes it: its testsuite's ``tests`` counts its cases."""
    cases = [f'<testcase classname="t" name="p{n}"/>' for n in range(passed)]
    cases += [
        f'<testcase classname="t" name="s{n}"><skipped message="x"/></testcase>'
        for n in range(skipped)
    ]
    count = len(cases) if tests is None else tests
    path = tmp_path / "junit-controls.xml"
    path.write_text(
        f'<testsuites><testsuite name="pytest" skipped="{skipped}" tests="{count}">'
        f"{''.join(cases)}</testsuite></testsuites>",
        encoding="utf-8",
    )
    return path


def test_the_controls_junit_holds_every_control_and_the_outer_ash_test(tmp_path):
    check = _api("check_junit", "control_problems")
    assert check(_junit(tmp_path, 3), controls=2, installs=True) == []
    assert check(_junit(tmp_path, 2), controls=2, installs=True), "one short"
    assert check(_junit(tmp_path, 2, skipped=1), controls=2, installs=True)
    problems = check(_junit(tmp_path, 1), controls=0, installs=True)
    assert problems and any("no negative control" in p for p in problems)
    assert check(_junit(tmp_path, 1), controls=0, installs=False) == []


def _check_controls(
    tmp_path,
    monkeypatch,
    texts: list[str],
    junit: Path,
    *,
    kind: str = "github-actions",
    runner: str = "act",
) -> int:
    """check_junit.py --controls on a page whose blocks are ``texts``, of ``kind``
    under ``runner``, the census and the composed blocks given; the rest is the
    script's own."""
    census = _module("census")
    pipelines = _module("pipelines")
    runs = [
        census.CensusRun(runner, "docs/x.md", n, n, kind, "push", False, None)
        for n in range(1, len(texts) + 1)
    ]
    monkeypatch.setattr(census, "leg_runs", lambda runner, page: runs)
    monkeypatch.setattr(pipelines, "composed_text", lambda run: texts[run.ordinal - 1])
    return _api("check_junit", "main")(
        ["--junit", str(junit), "--runner", runner, "--page", "docs/x.md", "--controls"]
    )


def test_a_page_whose_block_runs_ash_with_no_install_a_control_breaks_fails(
    tmp_path, monkeypatch, capsys
):
    """The block runs ``ash scan`` and installs ASH some way the harness does not know,
    so no control is made for it; the controls' junit holds only the outer-ash test."""
    text = (
        "steps:\n  - run: pipx install automated-security-helper\n  - run: ash scan\n"
    )
    code = _check_controls(tmp_path, monkeypatch, [text], _junit(tmp_path, 1))
    out = capsys.readouterr().out
    assert code == 1, out
    assert "block 1" in out and "runs ASH" in out, out


def test_a_page_whose_blocks_all_have_controls_passes(tmp_path, monkeypatch, capsys):
    texts = [RELEASE + "\nrun: ash scan --mode local\n", "run: echo no ASH here\n"]
    code = _check_controls(tmp_path, monkeypatch, texts, _junit(tmp_path, 2))
    assert code == 0, capsys.readouterr().out


#: Commands that run an ASH scan or merge. The scan is the CLI's default command, so
#: ``ash`` followed by an option scans as ``ash scan`` does.
RUNS_ASH = [
    "ash scan",
    "ash scan --mode local",
    "ash merge --output-dir out",
    "ash --source-dir . --output-dir out",
    "ash --mode local",
    "ash -v --source-dir .",
    "run: ash --source-dir . --no-progress",
    "- ash --mode local || ash_exit=$?",
    'uvx --from "$SRC" ash --source-dir .',
    "cd repo && ash --offline",
    "ash \\\n  --source-dir . \\\n  --mode local",
    "ash \\\r\n  scan",
    "ash -v --version",
]
#: Commands that do not: ASH's own help and version, another program, a word that
#: holds ``ash``, a subcommand that is neither a scan nor a merge, a dash that starts
#: no option, an ``ash`` at the end of a line whose next line starts with a YAML list
#: marker, and a ``merge`` that starts the next command of a script.
RUNS_NO_ASH = [
    "run: |\n  cd ash\n  merge.sh out\n",
    "- name: ash - security scan\n  run: echo skipped\n",
    "matrix:\n  tool:\n    - name: ash\n    - name: bandit\n",
    "tags:\n  - ash\n  - docker\n",
    "script:\n  - cd ash\n  - make\n",
    "steps:\n  - run: pipx install ash\n  - run: echo installed\n",
    "ash --help",
    "ash --version",
    "ash report",
    "ash config validate",
    "echo ash",
    "flash --erase",
    "ash-version: 3.2.1",
    "pipx install automated-security-helper",
    "bash -c true",
    "dash -n script.sh",
]


@pytest.mark.parametrize("text", RUNS_ASH)
def test_ash_with_an_option_runs_a_scan(text):
    assert _api("pipelines", "runs_ash")(text), text


@pytest.mark.parametrize("text", RUNS_NO_ASH)
def test_what_does_not_run_a_scan_or_a_merge(text):
    assert not _api("pipelines", "runs_ash")(text), text
    assert not _module("reports").RUNS_SCAN.search(text), text


#: Blocks of a pipeline kind that run ASH. A YAML kind's block is read as YAML loads
#: it, so a folded or plain multi-line scalar is one command with its lines joined,
#: a literal block keeps its line breaks, and an unquoted command holding ``: ``
#: becomes a mapping key; a Jenkinsfile is read as written. In a GitLab block a node
#: under a tag such as ``!reference`` is read as the value it tags, a sequence, a
#: mapping or a scalar, ASH inside it included, and each of several documents is read.
#: A YAML block that does not parse is read as written, with ``ash`` and its first
#: argument allowed on separate lines, so a scalar YAML would have joined is still
#: counted; so is a block of another kind that holds a tag, which only GitLab defines.
KIND_RUNS_ASH = [
    (
        "gitlab-ci",
        (
            "scan:\n  script:\n    - !reference [.setup, script]\n"
            "    - >-\n      ash\n      --source-dir .\n"
        ),
    ),
    ("gitlab-ci", "scan:\n  script: !custom\n    - ash --source-dir .\n"),
    ("gitlab-ci", "steps:\n  - !custom\n    run: ash scan\n"),
    ("gitlab-ci", "run: !custom >-\n  ash\n  --source-dir .\n"),
    (
        "gitlab-ci",
        (
            "include: local.yml\n---\nscan:\n  script:\n    - >-\n      ash\n"
            "      scan --source-dir .\n"
        ),
    ),
    (
        "gitlab-ci",
        (
            "scan:\n  script:\n    - >-\n      ash\n      --source-dir .\n"
            "  tags: [unclosed\n"
        ),
    ),
    ("github-actions", "run: >-\n  ash\n  --source-dir .\n"),
    ("github-actions", "steps:\n  - run: ash\n      --source-dir .\n"),
    ("github-actions", "run: >-\n  ash\n  scan --source-dir .\n"),
    ("github-actions", "steps:\n  - run: ash\n      scan --source-dir .\n"),
    ("github-actions", "run: |\n  ash \\\n    --source-dir .\n"),
    ("gitlab-ci", "scan:\n  script:\n    - ash --source-dir . --mode local\n"),
    (
        "gitlab-ci",
        "scan:\n  script:\n    - ash --config-overrides sarif.enabled: true\n",
    ),
    ("buildspec", "phases:\n  build:\n    commands:\n      - ash scan\n"),
    (
        "circleci",
        "steps:\n  - run:\n      command: >-\n        ash\n        merge --output-dir out\n",
    ),
    (
        "jenkinsfile",
        "stage('scan') {\n  steps {\n    sh 'ash --source-dir .'\n  }\n}\n",
    ),
    ("github-actions", "jobs: [unclosed\n  ash scan\n"),
    (
        "github-actions",
        (
            "steps:\n  - !reference [.setup, steps]\n  - run: |\n      cd ash\n"
            "      merge.sh out\n"
        ),
    ),
    (
        "circleci",
        (
            "jobs:\n  scan:\n    steps:\n      - !custom [setup]\n      - run: |\n"
            "          cd ash\n          merge.sh out\n"
        ),
    ),
    (
        "buildspec",
        (
            "phases:\n  build:\n    commands:\n      - !custom setup\n      - |\n"
            "        cd ash\n        merge.sh out\n"
        ),
    ),
]
#: Blocks of a pipeline kind that do not: a literal block or a script whose next
#: line is a command of its own, also beside a tag or in a second document, YAML list
#: markers after an ``ash``, a stage named ``ash`` before a job named ``scan``, and a
#: comment.
KIND_RUNS_NO_ASH = [
    ("github-actions", "run: |\n  cd ash\n  merge.sh out\n"),
    ("github-actions", "run: |\n  pipx install ash\n  scan-report --all\n"),
    ("gitlab-ci", "job:\n  tags:\n    - ash\n    - docker\n  script:\n    - make\n"),
    ("gitlab-ci", "script:\n  - cd ash\n  - make\n"),
    ("github-actions", "matrix:\n  tool:\n    - name: ash\n    - name: bandit\n"),
    (
        "github-actions",
        "steps:\n  # ash --source-dir . runs on main only\n  - run: make\n",
    ),
    ("jenkinsfile", "sh 'cd ash'\nsh 'merge.sh'\n"),
    (
        "gitlab-ci",
        (
            "job:\n  tags:\n    - ash\n    - !reference [.tags, list]\n  script:\n"
            "    - make\n"
        ),
    ),
    (
        "gitlab-ci",
        (
            "job:\n  script:\n    - !reference [.setup, script]\n    - |\n"
            "      cd ash\n      merge.sh out\n"
        ),
    ),
    (
        "gitlab-ci",
        (
            "stages:\n  - ash\nscan:\n  stage: ash\n  script:\n"
            "    - !reference [.setup, script]\n    - make\n"
        ),
    ),
    (
        "gitlab-ci",
        (
            "spec:\n  inputs:\n    stage:\n      default: test\n---\njob:\n"
            "  script:\n    - |\n      cd ash\n      merge.sh out\n"
        ),
    ),
]


@pytest.mark.parametrize("kind,text", KIND_RUNS_ASH)
def test_a_block_of_its_kind_runs_ash(kind, text):
    assert _api("pipelines", "runs_ash")(text, kind), (kind, text)


@pytest.mark.parametrize("kind,text", KIND_RUNS_NO_ASH)
def test_a_block_of_its_kind_does_not_run_ash(kind, text):
    assert not _api("pipelines", "runs_ash")(text, kind), (kind, text)


@pytest.mark.parametrize(
    "scalar",
    [
        ">-\n          ash\n          --source-dir .\n",
        "ash\n          --source-dir .\n",
        ">-\n          ash\n          scan --source-dir .\n",
        "ash\n          scan --source-dir .\n",
    ],
    ids=["folded", "plain", "folded-scan", "plain-scan"],
)
def test_a_scan_split_over_yaml_lines_needs_a_control_as_it_gates(scalar):
    """YAML joins the lines of a folded or plain multi-line scalar, so the step runs
    ``ash --source-dir .`` or ``ash scan --source-dir .``. The act plan, which reads
    the parsed workflow, gates on it, and the controls check counts it as running ASH
    too."""
    text = f"jobs:\n  scan:\n    steps:\n      - run: {scalar}"
    reports = _module("reports")
    plan = reports.act_job_plan(reports.load_workflow(text), {})
    assert plan["scan"].gates, plan
    assert _api("pipelines", "runs_ash")(text, "github-actions"), text


def test_a_page_whose_block_splits_ash_scan_over_yaml_lines_needs_a_control(
    tmp_path, monkeypatch, capsys
):
    """check_junit.py --controls reads each block by its kind, so a folded ``ash`` /
    ``scan`` with no install a control breaks is a block no control covers."""
    text = (
        "steps:\n  - run: pipx install automated-security-helper\n"
        "  - run: >-\n      ash\n      scan --source-dir .\n"
    )
    code = _check_controls(tmp_path, monkeypatch, [text], _junit(tmp_path, 1))
    out = capsys.readouterr().out
    assert code == 1, out
    assert "block 1" in out and "runs ASH" in out, out


def test_a_page_whose_block_has_a_yaml_tag_still_needs_a_control(
    tmp_path, monkeypatch, capsys
):
    """A node under GitLab's ``!reference`` tag is read as the value it tags; the
    folded ``ash`` / ``--source-dir .`` beside it still counts as running ASH, so
    with no install a control breaks it is a block no control covers."""
    text = (
        "scan:\n  script:\n    - pipx install automated-security-helper\n"
        "    - !reference [.scan, script]\n"
        "    - >-\n      ash\n      --source-dir .\n"
    )
    code = _check_controls(
        tmp_path,
        monkeypatch,
        [text],
        _junit(tmp_path, 1),
        kind="gitlab-ci",
        runner="gitlab-ci-local",
    )
    out = capsys.readouterr().out
    assert code == 1, out
    assert "block 1" in out and "runs ASH" in out, out


#: A literal block beside a tag, ``cd ash`` and ``merge.sh out`` on lines of their
#: own, in a GitLab pipeline and in a GitHub Actions workflow.
LITERAL_BESIDE_A_TAG = {
    "gitlab-ci": (
        "scan:\n  script:\n    - !reference [.setup, script]\n"
        "    - |\n      cd ash\n      merge.sh out\n"
    ),
    "github-actions": (
        "steps:\n  - !reference [.setup, steps]\n"
        "  - run: |\n      cd ash\n      merge.sh out\n"
    ),
}


def test_a_page_whose_block_has_a_literal_beside_a_yaml_tag_needs_no_control(
    tmp_path, monkeypatch, capsys
):
    """A literal block beside GitLab's ``!reference`` keeps its line breaks, so ``cd
    ash`` and ``merge.sh out`` are two commands: the block runs no ASH, and the
    controls' junit holds only the outer-ash test."""
    code = _check_controls(
        tmp_path,
        monkeypatch,
        [LITERAL_BESIDE_A_TAG["gitlab-ci"]],
        _junit(tmp_path, 1),
        kind="gitlab-ci",
        runner="gitlab-ci-local",
    )
    assert code == 0, capsys.readouterr().out


def test_a_tag_in_a_block_of_a_kind_without_tags_errs_toward_a_control(
    tmp_path, monkeypatch, capsys
):
    """Only GitLab defines a local tag, so a GitHub Actions block that holds one is
    read as a block that does not parse, as written, with ``ash`` and its next line
    read together: it counts as running ASH, and with no install a control breaks
    it is a block no control covers."""
    code = _check_controls(
        tmp_path,
        monkeypatch,
        [LITERAL_BESIDE_A_TAG["github-actions"]],
        _junit(tmp_path, 1),
    )
    out = capsys.readouterr().out
    assert code == 1, out
    assert "block 1" in out and "runs ASH" in out, out


def test_a_page_whose_block_runs_ash_with_options_and_no_install_fails(
    tmp_path, monkeypatch, capsys
):
    """``ash --source-dir .`` scans as ``ash scan`` does, so a block that runs it with
    no install a control breaks is not covered by any control."""
    text = (
        "steps:\n  - run: pipx install automated-security-helper\n"
        "  - run: ash --source-dir . --output-dir out\n"
    )
    code = _check_controls(tmp_path, monkeypatch, [text], _junit(tmp_path, 1))
    out = capsys.readouterr().out
    assert code == 1, out
    assert "block 1" in out and "runs ASH" in out, out


@pytest.mark.parametrize(
    "command,gates",
    [
        ("ash --source-dir . --output-dir out", True),
        ("ash \\\n  --source-dir . \\\n  --output-dir out\n", True),
        ("ash --mode local --no-fail-on-findings", False),
        ("ash --version", False),
        ("pipx install ash\n- echo installed\n", False),
    ],
)
def test_a_github_job_that_runs_ash_with_options_gates_on_findings(command, gates):
    """A job whose step runs ``ash`` with options scans, and fails on the planted
    findings unless it says ``--no-fail-on-findings``."""
    reports = _module("reports")
    workflow = {"jobs": {"scan": {"steps": [{"name": "Scan", "run": command}]}}}
    plan = reports.act_job_plan(workflow, {})
    assert plan["scan"].gates is gates, plan
    assert plan["scan"].result == ("failure" if gates else "success"), plan


@pytest.mark.parametrize(
    "run,found",
    [
        ("ash merge --output-dir out", True),
        ("ash \\\n  merge --output-dir out", True),
        ("cd ash\nmerge.sh out", False),
    ],
)
def test_the_merge_step_is_ash_merge_on_one_line_or_a_continuation(run, found):
    gating_step = _api("reports", "gating_step")
    workflow = {"jobs": {"m": {"steps": [{"name": "Merge", "run": run}]}}}
    assert gating_step(workflow, "merge") == (("m", "Merge") if found else None)


GITLAB_BARE_ASH = """\
ash-scan:
  script:
    - ash --source-dir . --mode local
"""


def test_a_gitlab_job_that_runs_ash_with_options_gives_its_one_verdict(tmp_path):
    check = _api("pipelines", "scan_verdict_problems")
    prepared = _prepared(tmp_path, "gitlab-ci-local", rewritten=GITLAB_BARE_ASH)
    log = f"ash-scan $ ash --source-dir . --mode local\nash-scan > {VERDICT}"
    assert check(prepared, log) == []
    problems = check(prepared, "ash-scan $ ash --source-dir . --mode local")
    assert problems, "a scan job that gave no verdict passed"


def test_the_gitlab_scan_job_is_found_when_it_runs_ash_with_options():
    pipelines = _module("pipelines")
    document = {
        "lint": {"script": ["ash --version"]},
        "ash-scan": {"script": ["ash --source-dir . --mode local"]},
    }
    name, _ = pipelines._gitlab_scan_job(document)
    assert name == "ash-scan"


def test_a_skipped_test_fails_the_census_on_its_own(tmp_path):
    """4 ran, 1 skipped, 4 expected: the count matches, the skip still fails."""
    path = tmp_path / "junit.xml"
    cases = "".join(f'<testcase classname="t" name="p{n}"/>' for n in range(4))
    cases += '<testcase classname="t" name="s"><skipped message="x"/></testcase>'
    path.write_text(
        f'<testsuites><testsuite skipped="1" tests="5">{cases}</testsuite></testsuites>',
        "utf-8",
    )
    problems = _api("verdict", "junit_census_problems")(path, expected=4)
    assert problems and "skipped" in problems[0]


@pytest.mark.parametrize(
    "tests",
    ['tests="0"', 'tests="3"', "", 'tests="four"'],
    ids=["setup-plan", "fewer", "missing", "not a number"],
)
def test_a_testsuite_whose_count_is_not_its_cases_fails_the_census(tmp_path, tests):
    """Under ``--setup-plan`` pytest writes a testcase per test with nothing run, and
    the testsuite's ``tests="0"``; the count pytest gives must be the cases listed."""
    path = tmp_path / "junit.xml"
    cases = "".join(f'<testcase classname="t" name="p{n}"/>' for n in range(4))
    path.write_text(
        f'<testsuites><testsuite name="pytest" {tests}>{cases}</testsuite></testsuites>',
        "utf-8",
    )
    problems = _api("verdict", "junit_census_problems")(path, expected=4)
    assert problems and any("tests" in problem for problem in problems), problems


def test_a_testsuite_that_counts_its_cases_passes_the_census(tmp_path):
    assert (
        _api("verdict", "junit_census_problems")(_junit(tmp_path, 4), expected=4) == []
    )


# ---------------------------------------------------------------------------
# What is kept for upload
# ---------------------------------------------------------------------------


def test_kept_trees_leave_dot_entries_behind_but_keep_ash_output(tmp_path):
    source = tmp_path / "artifacts" / "ash-scan"
    (source / ".ash" / "ash_output" / "reports").mkdir(parents=True)
    (source / ".ash" / "ash_output" / "ash_aggregated_results.json").write_text("{}")
    (source / ".ash" / "ash_output" / "reports" / "ash.sarif").write_text("{}")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("x")
    (source / "ash-exit-code.txt").write_text("2\n")
    _api("reports", "keep_tree")(source, tmp_path / "kept")
    kept = sorted(
        p.relative_to(tmp_path / "kept").as_posix()
        for p in (tmp_path / "kept").rglob("*")
        if p.is_file()
    )
    assert kept == [
        "ash-exit-code.txt",
        "ash_output/ash_aggregated_results.json",
        "ash_output/reports/ash.sarif",
    ]


def test_kept_trees_leave_secret_shaped_names_behind(tmp_path):
    source = tmp_path / "artifacts"
    (source / "secrets").mkdir(parents=True)
    (source / "secrets" / "master.key").write_text("k")
    for name in ("secret.key", "secret.key.not-so-secret", "identity.key.enc"):
        (source / name).write_text("k")
    (source / "deploy.pem").write_text("k")
    (source / "ash.sarif").write_text("{}")
    _api("reports", "keep_tree")(source, tmp_path / "kept")
    kept = sorted(p.name for p in (tmp_path / "kept").rglob("*"))
    assert kept == ["ash.sarif"]


def test_only_the_jenkins_build_record_is_kept_and_no_key(tmp_path):
    home = tmp_path / "jenkins-home"
    build = home / "jobs" / "job" / "builds" / "1"
    (build / "archive" / ".ash" / "ash_output").mkdir(parents=True)
    (
        build / "archive" / ".ash" / "ash_output" / "ash_aggregated_results.json"
    ).write_text("{}")
    for name in ("log", "build.xml", "junitResult.xml"):
        (build / name).write_text(name)
    (home / "secrets").mkdir()
    (home / "secrets" / "master.key").write_text("k")
    (home / "secret.key").write_text("k")
    (home / "identity.key.enc").write_text("k")
    (home / "config.xml").write_text("c")
    _api("pipelines", "keep_jenkins_build")(home, tmp_path / "out")
    kept = sorted(
        p.relative_to(tmp_path / "out").as_posix()
        for p in (tmp_path / "out").rglob("*")
        if p.is_file()
    )
    assert kept == [
        "jenkins-build/archive/ash_output/ash_aggregated_results.json",
        "jenkins-build/build.xml",
        "jenkins-build/junitResult.xml",
        "jenkins-build/log",
    ]


#: Every name in a Jenkins home that may hold or protect a key: Jenkins writes the
#: first four when a home starts, the controller key under secrets/, the instance's
#: identity, and the users' and instance's configuration.
JENKINS_HOME_NAMES = frozenset(
    {
        "secret.key",
        "secret.key.not-so-secret",
        "secrets",
        "identity.key.enc",
        "master.key",
        "hudson.util.Secret",
        "config.xml",
        "users",
        "jobs",
    }
)


def _whole_jenkins_home(home: Path) -> None:
    """A Jenkins home as a Jenkinsfile Runner build leaves it."""
    build = home / "jobs" / "job" / "builds" / "1"
    (build / "archive").mkdir(parents=True)
    (build / "archive" / "report.txt").write_text("r")
    for name in ("log", "build.xml", "junitResult.xml"):
        (build / name).write_text(name)
    (home / "jobs" / "job" / "config.xml").write_text("c")
    (home / "secrets").mkdir()
    (home / "secrets" / "master.key").write_text("k")
    (home / "secrets" / "hudson.util.Secret").write_text("k")
    for name in ("secret.key", "secret.key.not-so-secret", "identity.key.enc"):
        (home / name).write_text("k")
    (home / "config.xml").write_text("c")
    (home / "users" / "someone").mkdir(parents=True)
    (home / "users" / "someone" / "config.xml").write_text("c")


def test_kept_trees_never_copy_a_jenkins_home(tmp_path):
    """Not its keys, and not the rest of it either: a Jenkins home that a kept tree
    holds is left out whole."""
    source = tmp_path / "artifacts"
    _whole_jenkins_home(source / "nested" / "jenkins-home")
    (source / "ash.sarif").write_text("{}")
    _api("reports", "keep_tree")(source, tmp_path / "kept")
    kept = sorted(
        p.relative_to(tmp_path / "kept").as_posix()
        for p in (tmp_path / "kept").rglob("*")
        if p.is_file()
    )
    assert kept == ["ash.sarif"]
    home = tmp_path / "home-alone"
    _whole_jenkins_home(home)
    _api("reports", "keep_tree")(home, tmp_path / "kept-home")
    assert not [p for p in (tmp_path / "kept-home").rglob("*") if p.is_file()]


def _session(tmp_path: Path, *, out: Path, work: Path):
    pipelines = _module("pipelines")
    wheel, digest = _wheel(tmp_path)
    return pipelines.Session(
        options=pipelines.Options(
            bin_dir=tmp_path / "bin",
            wheel=wheel,
            out=out,
            jenkins_dir=tmp_path / "jenkins",
            launch_timeout=60.0,
        ),
        under_test=pipelines.UnderTest(
            wheel=wheel, wheel_sha256=digest, head_sha=HEAD, repository=REPOSITORY
        ),
        pins={},
        work=work,
        tool_cache=work / "ash-tool-download-cache",
    )


def test_the_work_directory_and_the_upload_root_never_overlap(tmp_path):
    """The Jenkins homes live in the work directory (pytest's basetemp), so a work
    directory inside --ci-runner-out would upload them."""
    error = _api("pipelines", "HarnessError")
    temp = tmp_path / "runner-temp"
    upload = temp / "ci-runner-out" / "runs"
    for work in (upload / "ci-runner-work0", upload):
        with pytest.raises(error, match="ci-runner-out"):
            _session(tmp_path, out=upload, work=work)
    with pytest.raises(error):
        _session(tmp_path, out=temp / "ci-runner-work" / "out", work=temp)
    _session(tmp_path, out=upload, work=temp / "ci-runner-work" / "ci-runner-work0")


@pytest.mark.parametrize(
    "leg", ["jenkinsfile-runner-lts", "jenkinsfile-runner-bundled"]
)
def test_every_jenkins_home_is_in_the_work_directory_and_none_is_uploaded(
    tmp_path, monkeypatch, leg
):
    """Laid out as the workflow lays it out: the basetemp and the upload root are
    siblings under the runner's temp directory."""
    temp = tmp_path / "runner-temp"
    session = _session(
        tmp_path,
        out=temp / "ci-runner-out" / "runs",
        work=temp / "ci-runner-work" / "ci-runner-work0",
    )
    out, work = session.directories("other-ci-3")
    prepared = _prepared(tmp_path, leg)
    prepared.out, prepared.work = out, work
    started: list[dict] = []

    def jenkinsfile_runner(leg, *, command, jenkins_home, plugin_copy, log, **rest):
        started.append({"home": jenkins_home, "plugins": plugin_copy})
        _whole_jenkins_home(Path(jenkins_home))
        Path(plugin_copy).mkdir(parents=True)
        Path(log).write_text("Finished: FAILURE\n", encoding="utf-8")
        return 0 if command == "lint" else 1

    monkeypatch.setattr(
        _module("run_jenkinsfile_runner"), "run_jenkinsfile_runner", jenkinsfile_runner
    )
    _api("pipelines", "launch")(prepared, session)
    assert len(started) == 2, "the lint and the run"
    upload = session.options.out
    for paths in started:
        for path in paths.values():
            assert Path(path).is_relative_to(session.work), path
            assert not Path(path).is_relative_to(upload), path
    uploaded = list(upload.rglob("*"))
    assert not [p for p in uploaded if p.name in JENKINS_HOME_NAMES], uploaded
    assert (out / "jenkins-build" / "log").is_file(), "the build record is kept"


# ---------------------------------------------------------------------------
# An install from a package index is seen
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "Downloading automated_security_helper-3.7.0-py3-none-any.whl (1.5 MB)",
        "  Downloading automated_security_helper-3.7.0-py3-none-any.whl.metadata (12 kB)",
        " + automated-security-helper==3.7.0",
        "Downloading automated-security-helper (1.4MiB)",
        "https://files.pythonhosted.org/packages/aa/automated_security_helper-3.7.0.whl",
    ],
)
def test_an_install_from_a_package_index_is_reported(line):
    assert _api("reports", "index_download_problems")(f"Resolved 9 packages\n{line}\n")


@pytest.mark.parametrize(
    "line",
    [
        " + automated-security-helper==3.7.0 (from file:///ash-wheel/automated_security_helper-3.7.0-py3-none-any.whl#sha256=00)",
        f" + automated-security-helper==3.7.0 (from git+https://github.com/{REPOSITORY}@{HEAD})",
        "Processing /ash-wheel/automated_security_helper-3.7.0-py3-none-any.whl",
        "Downloading bandit-1.8.0-py3-none-any.whl (130 kB)",
    ],
)
def test_an_install_of_the_wheel_or_the_commit_is_not(line):
    assert _api("reports", "index_download_problems")(line) == []


# ---------------------------------------------------------------------------
# One verdict per gating job and matrix run
# ---------------------------------------------------------------------------

VERDICT = "ERROR (2) Exiting due to 3 actionable findings found in ASH scan"
MERGE_VERDICT = (
    "ERROR (2) Exiting due to 3 actionable findings across the merged shards"
)


def test_every_gating_job_gives_its_own_verdict():
    """Two gating jobs fail, and only one gave a verdict."""
    check = _api("verdict", "act_verdict_problems")
    log = "\n".join(
        [
            _act("scan-a", f"  | {VERDICT}"),
            _act("scan-a", "🏁  Job failed", jobResult="failure"),
            _act("scan-b", "🏁  Job failed", jobResult="failure"),
        ]
    )
    problems = check(log, gating={"scan-a": 1, "scan-b": 1}, actionable=3)
    assert problems and any("scan-b" in p for p in problems), problems
    both = log + "\n" + _act("scan-b", f"  | {VERDICT}")
    assert check(both, gating={"scan-a": 1, "scan-b": 1}, actionable=3) == []


def test_a_job_gives_one_verdict_per_matrix_run_and_others_none():
    check = _api("verdict", "act_verdict_problems")
    log = "\n".join(
        [_act("merge", f"  | {MERGE_VERDICT}")]
        + [
            _act("shard", "🏁  Job succeeded", {"shard": n}, jobResult="success")
            for n in range(4)
        ]
    )
    assert check(log, gating={"merge": 1}, source="merge", actionable=3) == []
    twice = log + "\n" + _act("merge", f"  | {MERGE_VERDICT}")
    assert check(twice, gating={"merge": 1}, source="merge", actionable=3)
    elsewhere = log + "\n" + _act("upload", f"  | {VERDICT}")
    assert check(elsewhere, gating={"merge": 1}, source="merge", actionable=3)


def test_a_verdict_must_exit_2():
    log = "ERROR (1) Exiting due to 3 actionable findings found in ASH scan\n"
    problems = _api("verdict", "verdict_problems")(log, actionable=3)
    assert problems and "2" in problems[0]


def test_a_verdict_in_an_act_message_with_a_carriage_return_is_read():
    log = _act("ash", f"  | 45%\r  | {VERDICT}")
    assert _api("verdict", "verdict_problems")(log, actionable=3) == []


# ---------------------------------------------------------------------------
# The jobs a reusable call runs, and nothing to expect
# ---------------------------------------------------------------------------

REUSABLE_CALLER = """\
on:
  pull_request:
jobs:
  ash:
    uses: ./.github/workflows/run-ash-security-scan.yml
  sarif:
    needs: ash
    if: ${{ !cancelled() }}
    uses: ./.github/workflows/upload-ash-sarif.yml
"""
CALLED_BOTH = {
    **CALLED,
    "upload-ash-sarif.yml": """\
on:
  workflow_call:
jobs:
  upload-sarif:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2
""",
}


def test_a_reusable_call_expects_the_called_workflow_s_own_jobs():
    reports = _module("reports")
    plan = reports.act_job_plan(
        reports.load_workflow(REUSABLE_CALLER),
        {name: reports.load_workflow(text) for name, text in CALLED_BOTH.items()},
    )
    assert {job: (p.result, p.runs, p.gates) for job, p in plan.items()} == {
        "ash": ("failure", 1, True),
        "upload-sarif": ("success", 1, False),
    }


def test_a_dependent_of_the_gated_scan_is_left_out_without_an_if_that_admits_it():
    """GitHub skips a job whose ``needs`` failed unless its ``if`` says otherwise, so
    a SARIF job with a plain ``needs: ash`` never runs after the gated scan fails,
    and act is not expected to report it."""
    reports = _module("reports")
    plain = REUSABLE_CALLER.replace("    if: ${{ !cancelled() }}\n", "")
    plan = reports.act_job_plan(
        reports.load_workflow(plain),
        {name: reports.load_workflow(text) for name, text in CALLED_BOTH.items()},
    )
    assert sorted(plan) == ["ash"], plan


def test_a_call_of_a_workflow_that_was_not_copied_is_an_error():
    reports = _module("reports")
    with pytest.raises(Exception, match="upload-ash-sarif.yml"):
        reports.act_job_plan(reports.load_workflow(REUSABLE_CALLER), {})


def test_a_workflow_with_nothing_to_expect_fails(tmp_path):
    """No jobs means no expectations, which must not mean no problems."""
    prepared = _prepared(tmp_path, "act", rewritten="on:\n  pull_request:\njobs: {}\n")
    problems = _api("pipelines", "run_problems")(
        prepared, _launched(tmp_path, ""), None
    )
    assert any("nothing to expect" in p for p in problems), problems


def test_matrix_runs_count_every_entry():
    reports = _module("reports")
    job = reports.load_workflow(SHARDED)["jobs"]["shard"]
    assert reports.matrix_runs(job) == 4
    assert (
        reports.matrix_runs({"strategy": {"matrix": {"a": [1, 2], "b": [1, 2, 3]}}})
        == 6
    )
    assert reports.matrix_runs({"runs-on": "x"}) == 1


# ---------------------------------------------------------------------------
# The stubs' records are read
# ---------------------------------------------------------------------------


def _stub_record(tmp_path: Path, name: str, number: int, record: dict) -> None:
    stubs = tmp_path / "out" / "stubs"
    stubs.mkdir(parents=True, exist_ok=True)
    (stubs / f"{name}-{number}.json").write_text(json.dumps(record), encoding="utf-8")


def test_the_called_scan_s_check_run_and_comment_are_required(tmp_path):
    check = _api("pipelines", "stub_problems")
    prepared = _prepared(tmp_path, "act", rewritten=CALLER, called=CALLED)
    problems = check(prepared)
    assert any("action-junit-report" in p for p in problems), problems
    assert any("add-pr-comment" in p for p in problems), problems
    _stub_record(tmp_path, "action-junit-report", 1, {"tests": 3, "failures": 2})
    _stub_record(
        tmp_path, "add-pr-comment", 1, {"issue": 1, "files": {"x/ash.summary.md": "0"}}
    )
    problems = check(prepared)
    assert problems and all("action-junit-report" in p for p in problems), problems
    _stub_record(tmp_path, "action-junit-report", 1, {"tests": 4, "failures": 3})
    assert check(prepared) == []


def test_a_push_needs_no_comment(tmp_path):
    prepared = _prepared(tmp_path, "act", rewritten=CALLER, called=CALLED, event="push")
    _stub_record(tmp_path, "action-junit-report", 1, {"tests": 3, "failures": 3})
    prepared.expected = {"app.py": 3}
    assert _api("pipelines", "stub_problems")(prepared) == []


# ---------------------------------------------------------------------------
# The merged results are the merge's
# ---------------------------------------------------------------------------


def test_a_file_older_than_the_step_is_not_its_output(tmp_path):
    check = _api("verdict", "written_after_problems")
    path = tmp_path / "ash_aggregated_results.json"
    path.write_text("{}", encoding="utf-8")
    os.utime(path, (2_000_000_000, 2_000_000_000))
    assert check(path, started=2_000_000_000 - 1) == []
    assert check(path, started=2_000_000_000) == []
    assert check(path, started=2_000_000_000 + 60)
    assert check(tmp_path / "absent.json", started=0)


# ---------------------------------------------------------------------------
# CodeBuild's report and GitLab's kept exit code
# ---------------------------------------------------------------------------


def _junit_report(path: Path, failures: int, passed: int) -> None:
    cases = "".join(
        f'<testcase name="f{n}"><failure message="x"/></testcase>'
        for n in range(failures)
    ) + "".join(f'<testcase name="p{n}"/>' for n in range(passed))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"<testsuites><testsuite>{cases}</testsuite></testsuites>", "utf-8")


def test_junit_counts_read_every_report_under_a_directory(tmp_path):
    counts = _api("reports", "junit_counts")
    assert counts(tmp_path) == (0, 0)
    _junit_report(tmp_path / "ash-findings" / "ash.junit.xml", 3, 2)
    (tmp_path / "ash-findings" / "summary.json").write_text("{}")
    (tmp_path / "broken.xml").write_text("not xml")
    assert counts(tmp_path) == (5, 3)


def test_junit_counts_read_the_reports_the_codebuild_agent_zips(tmp_path):
    """The CodeBuild agent keeps each report group as ``reports-<name>.zip`` holding the
    JUnit files (measured on the hosted codebuild-agent leg: ``reports-ash-findings.zip``
    with one ``ash.junit.xml``); the zipped members count like plain files, a member
    that is not JUnit XML counts nothing, and a file that is not a zip is skipped."""
    counts = _api("reports", "junit_counts")
    _junit_report(tmp_path / "plain" / "ash.junit.xml", 1, 1)
    zipped = tmp_path / "zipped"
    zipped.mkdir()
    _junit_report(zipped / "ash.junit.xml", 3, 2)
    (zipped / "notes.xml").write_text("not xml", "utf-8")
    with zipfile.ZipFile(tmp_path / "reports-ash-findings.zip", "w") as archive:
        archive.write(zipped / "ash.junit.xml", "ash.junit.xml")
        archive.write(zipped / "notes.xml", "notes.xml")
        archive.writestr("readme.txt", "<testcase name='not counted'/>")
    (tmp_path / "zipped" / "ash.junit.xml").unlink()
    (tmp_path / "zipped" / "notes.xml").unlink()
    (tmp_path / "broken.zip").write_bytes(b"PK\x03\x04 not a zip")
    # 1 failed + 1 passed in the plain report, 3 failed + 2 passed in the zipped one.
    assert counts(tmp_path) == (7, 4)


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(zlib.error("corrupt deflate data"), id="corrupt deflate data"),
        pytest.param(EOFError("truncated member"), id="truncated member"),
        pytest.param(RuntimeError("File 'x' is encrypted"), id="encrypted member"),
        pytest.param(
            NotImplementedError("compression method"), id="unsupported method"
        ),
    ],
)
def test_junit_counts_pass_over_a_zip_whose_members_cannot_be_read(
    tmp_path, monkeypatch, error
):
    """Each error zipfile raises while reading a member leaves that archive counted
    as nothing, the way a file that is not a zip is, and the plain reports still count;
    none of them escapes to abort the leg's judge."""
    counts = _api("reports", "junit_counts")
    _junit_report(tmp_path / "plain" / "ash.junit.xml", 1, 1)
    _junit_report(tmp_path / "zipped" / "ash.junit.xml", 3, 2)
    with zipfile.ZipFile(tmp_path / "reports-ash-findings.zip", "w") as archive:
        archive.write(tmp_path / "zipped" / "ash.junit.xml", "ash.junit.xml")
    (tmp_path / "zipped" / "ash.junit.xml").unlink()

    def failing_read(self, name, pwd=None):
        raise error

    monkeypatch.setattr(zipfile.ZipFile, "read", failing_read)
    assert counts(tmp_path) == (2, 1)


def test_the_gate_job_reads_the_exit_code_the_scan_job_kept(tmp_path):
    check = _api("pipelines", "gitlab_exit_code_problems")
    pipeline = """\
ash-scan:
  script:
    - ash scan --mode local || ash_exit=$?
    - echo "$ash_exit" > ash-exit-code.txt
  artifacts:
    when: always
    paths:
      - .ash/ash_output/
ash-gate:
  needs: [ash-scan]
  script:
    - exit "$(cat ash-exit-code.txt)"
"""
    prepared = _prepared(tmp_path, "gitlab-ci-local", rewritten=pipeline)
    problems = check(prepared)
    assert problems and "ash-exit-code.txt" in problems[0], (
        "read by the gate, so checked"
    )
    kept = prepared.project / ".gitlab-ci-local" / "artifacts" / "ash-scan"
    kept.mkdir(parents=True)
    (kept / "ash-exit-code.txt").write_text("1\n", encoding="utf-8")
    assert check(prepared)
    (kept / "ash-exit-code.txt").write_text("2\n", encoding="utf-8")
    assert check(prepared) == []


GATED_ON_ANOTHER_FILE = """\
ash-scan:
  script:
    - ash scan --mode local || ash_exit=$?
    - echo "$ash_exit" > scan-result/code
  artifacts:
    when: always
    paths:
      - .ash/ash_output/
ash-gate:
  needs: [ash-scan]
  script:
    - exit "$(cat scan-result/code)"
"""


def test_a_gate_that_reads_a_file_the_harness_cannot_find_fails(tmp_path):
    """The gate exits with what a file holds; whatever its name, that file must be in
    the scan job's kept artifacts and hold ASH's 2. A gate whose file is missing
    exits 2 too (``exit ""`` is a usage error), for no reason the page gives."""
    check = _api("pipelines", "gitlab_exit_code_problems")
    prepared = _prepared(tmp_path, "gitlab-ci-local", rewritten=GATED_ON_ANOTHER_FILE)
    problems = check(prepared)
    assert problems and "scan-result/code" in problems[0], problems
    kept = prepared.project / ".gitlab-ci-local" / "artifacts" / "ash-scan"
    (kept / "scan-result").mkdir(parents=True)
    (kept / "scan-result" / "code").write_text("1\n", encoding="utf-8")
    assert check(prepared)
    (kept / "scan-result" / "code").write_text("2\n", encoding="utf-8")
    assert check(prepared) == []


def test_a_gate_whose_file_the_harness_cannot_tell_fails(tmp_path):
    check = _api("pipelines", "gitlab_exit_code_problems")
    pipeline = GATED_ON_ANOTHER_FILE.replace(
        'exit "$(cat scan-result/code)"', 'exit "$(head -n 1 scan-result/code)"'
    )
    prepared = _prepared(tmp_path, "gitlab-ci-local", rewritten=pipeline)
    problems = check(prepared)
    assert problems and "ash-gate" in problems[0], problems


GITLAB_PIPELINE = GATED_ON_ANOTHER_FILE


@pytest.mark.parametrize(
    "lines,ok",
    [
        ([f"ash-scan > {VERDICT}"], True),
        ([f"ash-scan > {VERDICT}", f"ash-scan > {VERDICT}"], False),
        ([f"ash-scan > {VERDICT}", f"ash-gate > {VERDICT}"], False),
        ([f"ash-gate > {VERDICT}"], False),
        ([VERDICT], False),
        ([], False),
    ],
    ids=[
        "one",
        "two from the scan",
        "one from the gate",
        "only the gate",
        "no job",
        "none",
    ],
)
def test_each_gitlab_job_that_runs_ash_gives_exactly_one_verdict(tmp_path, lines, ok):
    """gitlab-ci-local prints each job's output line as ``<job> > <line>``, so each
    verdict is attributed to its job."""
    check = _api("pipelines", "scan_verdict_problems")
    prepared = _prepared(tmp_path, "gitlab-ci-local", rewritten=GITLAB_PIPELINE)
    problems = check(prepared, "\n".join(["ash-scan $ ash scan", *lines]))
    assert (problems == []) is ok, problems


@pytest.mark.parametrize(
    "runner", ["jenkinsfile-runner-lts", "codebuild-agent", "circleci"]
)
def test_a_runner_that_runs_one_job_shows_exactly_one_verdict(tmp_path, runner):
    """Jenkinsfile Runner, the CodeBuild agent and circleci local execute each run one
    build per launch, and the pages' blocks scan once in it."""
    check = _api("pipelines", "scan_verdict_problems")
    prepared = _prepared(tmp_path, runner)
    assert check(prepared, f"x\n{VERDICT}\n") == []
    problems = check(prepared, f"{VERDICT}\n{VERDICT}\n")
    assert problems and any("2 verdicts" in p for p in problems), problems
    assert check(prepared, "no verdict\n")


def test_a_jenkins_run_with_two_verdicts_fails(tmp_path):
    prepared = _prepared(tmp_path, "jenkinsfile-runner-lts")
    launched = _launched(tmp_path, f"{VERDICT}\n{VERDICT}\n", steps={"lint": 0})
    problems = _api("pipelines", "run_problems")(prepared, launched, None)
    assert any("2 verdicts" in p for p in problems), problems


# ---------------------------------------------------------------------------
# The built image, failure tails, the system PATH and time limits
# ---------------------------------------------------------------------------


def test_the_built_image_job_must_run_the_image_the_run_built(tmp_path):
    check = _api("pipelines", "built_image_problems")
    prepared = _prepared(
        tmp_path,
        "gitlab-ci-local",
        composed="image: registry.example.com/security/automated-security-helper:ci",
    )
    image = "sha256:" + "c" * 64
    assert check(
        prepared, _launched(tmp_path, "ash-scan pulled nothing", image_id=image)
    )
    named = f"ash-scan > Using docker image {image}"
    assert check(prepared, _launched(tmp_path, named, image_id=image)) == []
    assert check(prepared, _launched(tmp_path, named, image_id=None)), "no id recorded"


BUILT_JOB = "image: registry.example.com/security/automated-security-helper:ci"


def _built_record(record: dict) -> str:
    return "\n".join(f"ash-scan > {line}" for line in _record(record))


def test_the_built_image_job_shows_one_record_of_what_the_image_holds(
    tmp_path, monkeypatch
):
    """The image the run builds from the checkout records which ASH it holds; the
    rewrite prints that record once in the job that runs on the image, and the check
    H-core provides decides whether it is the pull request's head."""
    seen: list[tuple] = []

    def built_provenance_problems(record, *, head_sha, wheel, wheel_sha256):
        seen.append((record, head_sha, wheel, wheel_sha256))
        if record == {"built": "head"}:
            return []
        return ["the image holds another ASH"]

    monkeypatch.setattr(
        _module("provenance"),
        "built_provenance_problems",
        built_provenance_problems,
        raising=False,
    )
    check = _api("pipelines", "provenance_problems")
    prepared = _prepared(
        tmp_path,
        "gitlab-ci-local",
        composed=BUILT_JOB,
        applied=[_applied("built-provenance", job="ash-scan")],
    )
    one = _built_record({"built": "head"})
    assert check(prepared, one) == []
    under_test = prepared.under_test
    assert seen == [
        ({"built": "head"}, HEAD, under_test.wheel, under_test.wheel_sha256)
    ], "checked against the wheel the session built from the same checkout"
    assert check(prepared, ""), "no record"
    assert check(prepared, one + "\n" + one), "two records for one run of the job"
    other = check(prepared, _built_record({"built": "elsewhere"}))
    assert "the image holds another ASH" in other, other
    unprinted = _prepared(tmp_path, "gitlab-ci-local", composed=BUILT_JOB)
    assert check(unprinted, one), "a job on the built image with no print"


BUILT_WHEEL_MANIFEST = "built-wheel-manifest.json"
BUILT_RECORD_KEYS = (
    "version",
    "file_count",
    "files_sha256",
    "metadata_sha256",
    "entry_points_sha256",
)


def _built_wheel(tmp_path: Path) -> tuple[Path, str]:
    """A wheel with one package file, a METADATA and an entry_points.txt."""
    wheel = tmp_path / "built" / "automated_security_helper-3.7.0-py3-none-any.whl"
    wheel.parent.mkdir(parents=True, exist_ok=True)
    dist_info = "automated_security_helper-3.7.0.dist-info"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("automated_security_helper/__init__.py", "")
        archive.writestr(
            f"{dist_info}/METADATA",
            "Metadata-Version: 2.1\nName: automated-security-helper\nVersion: 3.7.0\n",
        )
        archive.writestr(
            f"{dist_info}/entry_points.txt",
            "[console_scripts]\nash = automated_security_helper.cli.main:main\n",
        )
    return wheel, hashlib.sha256(wheel.read_bytes()).hexdigest()


def _built_prepared(tmp_path: Path, wheel: Path, digest: str, count: int = 1):
    pipelines = _module("pipelines")
    return _prepared(
        tmp_path,
        "gitlab-ci-local",
        composed=BUILT_JOB,
        applied=[_applied("built-provenance", job="ash-scan", count=count)],
        under_test=pipelines.UnderTest(
            wheel=wheel, wheel_sha256=digest, head_sha=HEAD, repository=REPOSITORY
        ),
    )


def test_a_failed_check_of_the_built_image_writes_the_wheel_s_side(tmp_path):
    """The record holds a count and a digest of the image's files, so a failed check
    says only which of them differs. The wheel's side, file by file, is written to
    built-wheel-manifest.json in the run's output directory and named in the failure,
    to compare with a listing of the image's files; a record that passes writes
    nothing."""
    check = _api("pipelines", "built_record_problems")
    manifest_of = _api("provenance", "built_wheel_manifest")
    wheel, digest = _built_wheel(tmp_path)
    manifest = manifest_of(wheel, wheel_sha256=digest)
    record = {"direct_url": None, **{key: manifest[key] for key in BUILT_RECORD_KEYS}}
    other = {**record, "files_sha256": "0" * 64}

    prepared = _built_prepared(tmp_path / "one", wheel, digest)
    written = prepared.out / BUILT_WHEEL_MANIFEST
    assert check(prepared, _built_record(record)) == []
    assert not written.exists(), "a record that passes writes nothing"
    problems = check(prepared, _built_record(other))
    assert any("files digest differs" in p for p in problems), problems
    assert json.loads(written.read_text(encoding="utf-8")) == manifest
    assert sum(str(written) in p for p in problems) == 1, problems

    twice = _built_prepared(tmp_path / "two", wheel, digest, count=2)
    log = _built_record(other) + "\n" + _built_record(other)
    problems = check(twice, log)
    written = twice.out / BUILT_WHEEL_MANIFEST
    assert json.loads(written.read_text(encoding="utf-8")) == manifest
    assert sum(str(written) in p for p in problems) == 1, "named once for two records"

    first = _built_prepared(tmp_path / "first", wheel, digest, count=2)
    problems = check(first, _built_record(other) + "\n" + _built_record(record))
    written = first.out / BUILT_WHEEL_MANIFEST
    assert json.loads(written.read_text(encoding="utf-8")) == manifest
    assert sum(str(written) in p for p in problems) == 1, "a later pass undoes nothing"


def test_a_failed_check_names_why_the_wheel_s_side_was_not_written(tmp_path):
    """A wheel whose sha256 is not the run's is no reference, so there is no side to
    write; and a manifest that cannot be written leaves the check's own problems."""
    check = _api("pipelines", "built_record_problems")
    wheel, digest = _built_wheel(tmp_path)
    record = {"direct_url": None, "version": "3.7.0", "file_count": 1}

    stale = _built_prepared(tmp_path / "stale", wheel, "f" * 64)
    problems = check(stale, _built_record(record))
    assert not (stale.out / BUILT_WHEEL_MANIFEST).exists()
    assert any("not the wheel the run built" in p for p in problems), problems
    assert any(
        f"no {BUILT_WHEEL_MANIFEST} was written" in p and "f" * 64 in p
        for p in problems
    ), problems

    blocked = _built_prepared(tmp_path / "blocked", wheel, digest)
    (blocked.out / BUILT_WHEEL_MANIFEST).mkdir()
    problems = check(blocked, _built_record(record))
    assert any("could not be written" in p for p in problems), problems
    assert any("file_count and files_sha256" in p for p in problems), problems


def test_a_failure_tail_is_bounded_by_characters(tmp_path):
    log = tmp_path / "act.log"
    log.write_text("short\n" + "x" * 100_000 + "\n", encoding="utf-8")
    tail = _api("reports", "tail")(log, lines=20, chars=2000)
    assert len(tail) <= 2000 and tail.endswith("x")


def test_an_ash_on_the_system_path_is_refused(tmp_path):
    check = _api("pipelines", "system_ash_problem")
    assert check(str(tmp_path)) is None
    ash = tmp_path / "ash"
    ash.write_text("#!/bin/sh\n", encoding="utf-8")
    ash.chmod(0o755)
    problem = check(f"/nonexistent{os.pathsep}{tmp_path}")
    assert problem and str(ash) in problem


class _Config:
    def __init__(self, **values):
        self.values = values

    def getoption(self, name):
        return self.values.get(name)


def test_every_launch_has_a_time_limit(tmp_path):
    options = _module("pipelines").Options
    wheel, _ = _wheel(tmp_path)
    values = {
        "--ci-runner-bin": str(tmp_path / "bin"),
        "--ci-runner-wheel": str(wheel),
        "--ci-runner-out": str(tmp_path / "out"),
        "--ci-runner-launch-timeout": 1800.0,
    }
    assert options.from_config(_Config(**values)).launch_timeout == 1800.0
    values["--ci-runner-launch-timeout"] = 0
    with pytest.raises(Exception, match="launch-timeout"):
        options.from_config(_Config(**values))


def test_a_launch_that_ran_out_of_time_fails_with_its_tail(tmp_path):
    prepared = _prepared(tmp_path, "gitlab-ci-local")
    launched = _launched(
        tmp_path, "ash-scan > still installing\n", code=-9, timed_out="after 1800 s"
    )
    problems = _api("pipelines", "run_problems")(prepared, launched, None)
    assert problems and "1800" in problems[0], problems


# ---------------------------------------------------------------------------
# A step that stops workflow commands prints its resume line
# ---------------------------------------------------------------------------


def _wrapped_step(
    job: str, step: str, *, resume: bool, token: str = TOKEN
) -> list[str]:
    lines = [
        _act(job, f"⭐ Run Main {step}"),
        _act(job, f"  ⚙  ::stop-commands::{token}", command="stop-commands"),
        _act(job, f"  | {VERDICT}"),
    ]
    if resume:
        lines.append(_act(job, f"  ⚙  ::{token}::"))
    lines.append(_act(job, f"  ❌  Failure - Main {step}"))
    return lines


def test_a_wrapped_step_shows_its_resume_line():
    check = _api("verdict", "resume_token_problems")
    log = "\n".join(_wrapped_step("ash", "Run ASH", resume=True))
    assert check(log, ["Run ASH"]) == []


def test_a_wrapped_step_without_its_resume_line_is_named():
    check = _api("verdict", "resume_token_problems")
    log = "\n".join(
        _wrapped_step("ash", "Install ASH", resume=True)
        + _wrapped_step("ash", "Run ASH", resume=False, token="f" * 32)
    )
    problems = check(log, ["Install ASH", "Run ASH"])
    assert problems and all("Run ASH" in p for p in problems), problems


def test_a_resume_line_must_be_on_a_line_of_its_own():
    check = _api("verdict", "resume_token_problems")
    lines = _wrapped_step("ash", "Run ASH", resume=False)
    lines.insert(-1, _act("ash", f"  | echo ::{TOKEN}:: and more"))
    assert check("\n".join(lines), ["Run ASH"])


def test_a_wrapped_step_that_ran_without_stopping_commands_is_named():
    check = _api("verdict", "resume_token_problems")
    log = "\n".join(
        [
            _act("ash", "⭐ Run Main Run ASH"),
            _act("ash", f"  | {VERDICT}"),
            _act("ash", "  ❌  Failure - Main Run ASH"),
            _act("ash", "🏁  Job failed", jobResult="failure"),
        ]
    )
    problems = check(log, ["Run ASH"])
    assert problems and "Run ASH" in problems[0]
    problems = check(log, ["Some step that did not run"])
    assert problems and "Some step that did not run" in problems[0], (
        "act ran a job and no step of that name ran in it: the check had nothing to read"
    )


def test_each_wrapped_step_of_a_job_act_ran_must_have_run():
    check = _api("verdict", "resume_token_problems")
    log = "\n".join(
        _wrapped_step("ash", "Run ASH", resume=True)
        + [_act("ash", "🏁  Job failed", jobResult="failure")]
    )
    assert check(log, [("ash", "Run ASH")]) == []
    problems = check(log, [("ash", "Install ASH"), ("ash", "Run ASH")])
    assert problems and all("Install ASH" in p for p in problems), problems
    assert check(log, [("merge", "Merge the shards")]) == [], (
        "a job act reported no result for is the job results' check, not this one"
    )


def _shard_run(shard: int, *, step_ran: bool) -> list[str]:
    """One matrix run of job ``scan``, which act reports a result for."""
    matrix = {"shard": shard}
    lines = []
    if step_ran:
        lines = [
            _act("scan", "⭐ Run Main Scan one shard", matrix),
            _act("scan", f"  ⚙  ::stop-commands::{TOKEN}", matrix),
            _act("scan", f"  ⚙  ::{TOKEN}::", matrix),
            _act("scan", "  ✅  Success - Main Scan one shard", matrix),
        ]
    return lines + [_act("scan", "🏁  Job succeeded", matrix, jobResult="success")]


def test_a_wrapped_step_must_run_in_every_matrix_run_of_its_job():
    check = _api("verdict", "resume_token_problems")
    both = _shard_run(1, step_ran=True) + _shard_run(2, step_ran=True)
    assert check("\n".join(both), [("scan", "Scan one shard")]) == []
    one = _shard_run(1, step_ran=True) + _shard_run(2, step_ran=False)
    problems = check("\n".join(one), [("scan", "Scan one shard")])
    assert problems and all('"shard": 2' in p for p in problems), problems


def test_the_wrapped_steps_are_named_with_their_jobs():
    workflow = {
        "jobs": {
            "shard": {
                "steps": [
                    {"name": "Scan one shard", "run": "printf '::stop-commands::x'"},
                    {"name": "Upload", "uses": "actions/upload-artifact@v4"},
                ]
            },
            "merge": {
                "steps": [{"name": "Install ASH", "run": "echo ::stop-commands::y"}]
            },
        }
    }
    called = {"jobs": {"ash": {"steps": [{"name": "Install ASH", "run": "echo"}]}}}
    assert _api("reports", "wrapped_job_steps")([workflow, called]) == [
        ("shard", "Scan one shard"),
        ("merge", "Install ASH"),
    ]


# ---------------------------------------------------------------------------
# Jenkins record counts: more failures than expected, and skipped cases
# ---------------------------------------------------------------------------


def _jenkins_home(tmp_path: Path, cases: list[str]) -> Path:
    home = tmp_path / "jenkins-home"
    build = home / "jobs" / "job" / "builds" / "1"
    build.mkdir(parents=True)
    (build / "junitResult.xml").write_text(
        "<?xml version='1.1' encoding='UTF-8'?>\n<result><suites><suite><cases>"
        + "".join(cases)
        + "</cases></suite></suites></result>\n",
        encoding="utf-8",
    )
    return home


FAILED = (
    "<case><testName>f</testName><skipped>false</skipped>"
    "<errorDetails>B602</errorDetails><failedSince>1</failedSince></case>"
)
SKIPPED_WITH_DETAILS = (
    "<case><testName>s</testName><skipped>true</skipped>"
    "<errorDetails>suppressed</errorDetails></case>"
)


def test_jenkins_with_more_failed_tests_than_expected_fails(tmp_path):
    home = _jenkins_home(tmp_path, [FAILED] * 3)
    assert _api("verdict", "jenkins_junit_problems")(home, failures=2)


def test_jenkins_skipped_cases_are_not_failures(tmp_path):
    home = _jenkins_home(tmp_path, [FAILED, FAILED, SKIPPED_WITH_DETAILS])
    assert _api("verdict", "jenkins_junit_problems")(home, failures=2) == []
