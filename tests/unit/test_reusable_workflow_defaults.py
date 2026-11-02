# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A caller of run-ash-security-scan.yml that sets nothing must get a scan that works.

Why this file exists
--------------------
Two defaults made the reusable workflow fail, or move under its callers, for anyone
who did not override them:

* ``ash-version`` defaulted to ``main``. Every caller that did not pin it installed
  whatever ``main`` was on the day of the run, so the same caller at the same
  workflow ref scanned with a different ASH from one day to the next, and with an
  ASH newer than the workflow file it was called through.
* The four ``install-*`` inputs (grype, syft, opengrep, cfn-nag) defaulted to
  false. All four tools back default scanners, so a caller with the defaults got
  those scanners reported MISSING, and the incomplete-scan check failed the job
  with exit 1 whatever ``fail-on-findings`` said.

``ash-version`` is not pinned to the packaged release for ``cz bump`` to move: a
caller of ``@main`` would install v3.7.0 with main's steps, and v3.7.0 has no
``ash dependencies install --tool``, so the install steps would fail. Pinning
cannot be right between releases.

What is asserted
----------------
* ``ash-version`` and ``ash-repo`` default to empty, and a step resolves them to
  ``job.workflow_sha`` and ``job.workflow_repository``: the commit and repository
  the workflow file itself came from, so the steps always run against the ASH they
  were written for. Explicit inputs win, and with neither available the step
  fails with a message naming the inputs, never falling back to a branch.
* Nothing else reads ``inputs.ash-version`` or ``inputs.ash-repo``, so no step can
  install a different ASH than the one resolved.
* Every ``install-*`` input defaults to true. A new scanner input added with
  ``default: false`` is the same defect again.

The resolution step's shell is run, not only read: with each combination of inputs
and job context, against real ``GITHUB_ENV`` and ``GITHUB_OUTPUT`` files.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.parse
from pathlib import Path

import pytest
import yaml

from tests.utils.workflow_one_line import (
    COMMAND_TEXT,
    COMMAND_TEXT_SHOWN,
    command_lines,
    write_helper,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
WORKFLOW_RELATIVE = WORKFLOW.relative_to(REPO_ROOT).as_posix()

SHA = "0123456789abcdef0123456789abcdef01234567"


def _document() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _inputs() -> dict:
    document = _document()
    # PyYAML reads the bare key `on` as the boolean True (YAML 1.1).
    triggers = document.get("on", document.get(True))
    return triggers["workflow_call"]["inputs"]


def _steps() -> list[dict]:
    return _document()["jobs"]["ash"]["steps"]


def _resolve_step() -> dict:
    steps = [step for step in _steps() if step.get("id") == "ash-source"]
    assert len(steps) == 1, f"expected one step with id ash-source, found {len(steps)}"
    return steps[0]


@pytest.mark.unit
def test_ash_version_and_repo_default_to_the_workflows_own_commit():
    inputs = _inputs()

    assert inputs["ash-version"]["default"] == "", (
        f"{WORKFLOW_RELATIVE} defaults ash-version to {inputs['ash-version']['default']!r}. "
        "A literal default names one ASH for every ref the workflow is called at; "
        "empty lets the workflow install the ASH of its own commit."
    )
    assert inputs["ash-repo"]["default"] == ""

    step = _resolve_step()
    env = step["env"]
    # The job context as a whole, read for workflow_sha and workflow_repository;
    # see the step's comment for why not job.workflow_sha directly.
    assert env["JOB_CONTEXT"] == "${{ toJSON(job) }}"
    assert "workflow_sha" in step["run"] and "workflow_repository" in step["run"]
    # The input check's outputs, never the inputs as given
    # (test_an_input_cannot_add_a_workflow_command.py).
    assert env["CHECKED_ASH_VERSION"] == "${{ steps.inputs.outputs.ash_version }}"
    assert env["CHECKED_ASH_REPO"] == "${{ steps.inputs.outputs.ash_repo }}"


@pytest.mark.unit
def test_no_step_reads_the_raw_inputs():
    """Every step installs the ASH the resolution step chose, or none at all.

    The workflow-level ASH_UVX_SOURCE and ASH_ASSETS_URL still name the inputs as
    given (workflow env cannot read a step's output); the pin step replaces both
    through GITHUB_ENV before any step uses them, and nothing before the resolve
    step reads them (test_scan_workflow_pins_the_ash_ref.py).
    """
    readers = [
        step.get("name")
        for step in _steps()
        if step.get("id") != "ash-source"
        and ("inputs.ash-version" in str(step) or "inputs.ash-repo" in str(step))
    ]
    assert not readers, f"these steps read ash-version or ash-repo directly: {readers}"

    order = [step.get("id") for step in _steps()]
    first_use = next(
        index
        for index, step in enumerate(_steps())
        if step.get("id") != "ash-source" and "ASH_UVX_SOURCE" in str(step)
    )
    assert order.index("ash-source") < first_use, (
        "ASH_UVX_SOURCE is used before the step that sets it"
    )


def _job_context(**fields: str) -> str:
    """A job context as toJSON(job) renders it, with or without the workflow fields."""
    return json.dumps({"status": "success", "check_run_id": 1, **fields})


def _run_resolve(
    tmp_path: Path, **env: str
) -> tuple[subprocess.CompletedProcess, str, str]:
    bash = shutil.which("bash")
    assert bash, "bash is required to run the step"
    github_env = tmp_path / "github_env"
    github_output = tmp_path / "github_output"
    github_env.write_text("", encoding="utf-8")
    github_output.write_text("", encoding="utf-8")
    # The job's definer runs before this step does, into the same RUNNER_TEMP.
    runner_temp = tmp_path / "runner_temp"
    write_helper(_steps(), runner_temp)
    full_env = {
        "PATH": os.environ.get("PATH", ""),
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_ENV": str(github_env),
        "GITHUB_OUTPUT": str(github_output),
        "CHECKED_ASH_VERSION": "",
        "CHECKED_ASH_REPO": "",
        "JOB_CONTEXT": _job_context(),
        **env,
    }
    result = subprocess.run(
        [bash, "-e", "-o", "pipefail", "-c", _resolve_step()["run"]],
        env=full_env,
        capture_output=True,
        text=True,
        check=False,
    )
    return (
        result,
        github_env.read_text(encoding="utf-8"),
        github_output.read_text(encoding="utf-8"),
    )


pytestmark_posix = pytest.mark.skipif(
    os.name == "nt",
    reason="runs the step's bash script, which the workflow runs on Linux",
)


@pytest.mark.integration
@pytestmark_posix
class TestTheResolutionStep:
    def test_unset_inputs_install_the_workflows_own_commit(self, tmp_path):
        result, github_env, github_output = _run_resolve(
            tmp_path,
            JOB_CONTEXT=_job_context(
                workflow_sha=SHA,
                workflow_repository="awslabs/automated-security-helper",
            ),
        )

        assert result.returncode == 0, result.stderr
        assert (
            "ASH_UVX_SOURCE=automated-security-helper[cdk] @ "
            f"git+https://github.com/awslabs/automated-security-helper@{SHA}"
        ) in github_env.splitlines()
        assert f"version={SHA}" in github_output.splitlines()
        assert "repo=awslabs/automated-security-helper" in github_output.splitlines()

    def test_explicit_inputs_win(self, tmp_path):
        result, github_env, _ = _run_resolve(
            tmp_path,
            CHECKED_ASH_VERSION="v3.7.1",
            CHECKED_ASH_REPO="a-fork/automated-security-helper",
            JOB_CONTEXT=_job_context(
                workflow_sha=SHA,
                workflow_repository="awslabs/automated-security-helper",
            ),
        )

        assert result.returncode == 0, result.stderr
        assert (
            "ASH_UVX_SOURCE=automated-security-helper[cdk] @ "
            "git+https://github.com/a-fork/automated-security-helper@v3.7.1"
        ) in github_env.splitlines()

    def test_without_the_job_context_it_fails_instead_of_guessing(self, tmp_path):
        """GitHub Enterprise Server provides no job.workflow_* values."""
        # toJSON(job) there holds status and the rest, but no workflow_* keys.
        result, github_env, _ = _run_resolve(tmp_path)

        assert result.returncode != 0
        output = result.stdout + result.stderr
        assert "ash-version" in output and "ash-repo" in output, output
        assert "ASH_UVX_SOURCE" not in github_env

    @pytest.mark.parametrize(
        "given, missing",
        [
            ({"CHECKED_ASH_VERSION": "v3.7.1"}, "ash-repo"),
            ({"CHECKED_ASH_REPO": "awslabs/automated-security-helper"}, "ash-version"),
        ],
        ids=["only-ash-version", "only-ash-repo"],
    )
    def test_without_the_job_context_both_inputs_are_required(
        self, tmp_path, given, missing
    ):
        """One input is not enough on GHES: there is nothing to take the other from.

        The only-ash-repo case is also what catches a fallback to `main` for the
        version, which would otherwise install a moving branch without a word.
        """
        result, github_env, github_output = _run_resolve(tmp_path, **given)

        assert result.returncode != 0, github_env
        output = result.stdout + result.stderr
        assert missing in output and "both" in output, output
        assert github_env == "" and github_output == ""

    def test_without_the_job_context_both_inputs_are_enough(self, tmp_path):
        result, github_env, _ = _run_resolve(
            tmp_path,
            CHECKED_ASH_VERSION="v3.7.1",
            CHECKED_ASH_REPO="awslabs/automated-security-helper",
        )

        assert result.returncode == 0, result.stdout + result.stderr
        assert (
            "ASH_UVX_SOURCE=automated-security-helper[cdk] @ "
            "git+https://github.com/awslabs/automated-security-helper@v3.7.1"
        ) in github_env.splitlines()

    def test_another_repository_without_a_version_is_refused(self, tmp_path):
        """job.workflow_sha is a commit of the workflow's repository, not of a fork.

        Installing it from the fork's URL would install the upstream code the fork
        was meant to replace (GitHub serves a fork network's commits from any of its
        URLs), so an ash-repo other than the workflow's own needs an ash-version.
        """
        result, github_env, _ = _run_resolve(
            tmp_path,
            CHECKED_ASH_REPO="a-fork/automated-security-helper",
            JOB_CONTEXT=_job_context(
                workflow_sha=SHA,
                workflow_repository="awslabs/automated-security-helper",
            ),
        )

        assert result.returncode != 0, github_env
        output = result.stdout + result.stderr
        assert "ash-version" in output and "a-fork/automated-security-helper" in output
        assert github_env == ""

    @pytest.mark.parametrize("field", ["workflow_sha", "workflow_repository"])
    def test_a_job_context_value_cannot_add_a_workflow_command(self, tmp_path, field):
        """The fork refusal prints the job context's commit and repository.

        Nothing checks those two before that message, so a line break or `::` in
        either would start a command of its own. They are printed through one_line.
        """
        context = {
            "workflow_sha": SHA,
            "workflow_repository": "awslabs/automated-security-helper",
        }
        context[field] += COMMAND_TEXT
        result, github_env, _ = _run_resolve(
            tmp_path,
            CHECKED_ASH_REPO="a-fork/automated-security-helper",
            JOB_CONTEXT=_job_context(**context),
        )

        output = result.stdout + result.stderr
        assert result.returncode != 0, output
        assert github_env == ""
        (line,) = command_lines(output)
        assert line.startswith("::error::ash-repo is a-fork/automated-security-helper")
        assert COMMAND_TEXT_SHOWN in line, "the value must be shown, not dropped"

    def test_the_workflows_own_repository_without_a_version_uses_its_commit(
        self, tmp_path
    ):
        """GitHub compares owner/repo without regard to case, and so does the step."""
        result, github_env, _ = _run_resolve(
            tmp_path,
            CHECKED_ASH_REPO="AWSLabs/Automated-Security-Helper",
            JOB_CONTEXT=_job_context(
                workflow_sha=SHA,
                workflow_repository="awslabs/automated-security-helper",
            ),
        )

        assert result.returncode == 0, result.stdout + result.stderr
        assert f"@{SHA}" in github_env

    @pytest.mark.parametrize(
        "field, value",
        [
            ("CHECKED_ASH_VERSION", "main\nPATH=/tmp/evil"),
            ("CHECKED_ASH_VERSION", "v3.7.1 extra"),
            ("CHECKED_ASH_VERSION", "feat..x"),
            ("CHECKED_ASH_VERSION", "feat.lock"),
            ("CHECKED_ASH_VERSION", "feat:x"),
            ("CHECKED_ASH_VERSION", "feat~1"),
            ("CHECKED_ASH_VERSION", "@"),
            ("CHECKED_ASH_VERSION", "feat@{1}"),
        ],
    )
    def test_a_value_that_is_not_a_ref_is_refused(self, tmp_path, field, value):
        result, github_env, _ = _run_resolve(
            tmp_path,
            JOB_CONTEXT=_job_context(
                workflow_sha=SHA,
                workflow_repository="awslabs/automated-security-helper",
            ),
            **{field: value},
        )

        assert result.returncode != 0, github_env
        assert github_env == "", "nothing may reach GITHUB_ENV from a refused value"
        assert "check-ref-format" in result.stdout + result.stderr

    @pytest.mark.parametrize(
        "repo",
        [
            "awslabs/automated-security-helper\nINJECTED=1",
            "a/b\nINJECTED=1",
            "not-a-repo",
            "owner/repo/extra",
            "owner/re po",
        ],
    )
    @pytest.mark.parametrize("context", [True, False], ids=["context", "no-context"])
    def test_a_value_that_is_not_a_repository_is_refused(self, tmp_path, repo, context):
        """With ash-version set, so the owner/repo check is what refuses it.

        Without ash-version, another repository is refused before the shape is read,
        and a test that left it empty passed with both owner/repo checks deleted.
        """
        result, github_env, github_output = _run_resolve(
            tmp_path,
            CHECKED_ASH_VERSION="v3.7.1",
            CHECKED_ASH_REPO=repo,
            JOB_CONTEXT=_job_context(
                workflow_sha=SHA,
                workflow_repository="awslabs/automated-security-helper",
            )
            if context
            else _job_context(),
        )

        assert result.returncode != 0, github_env
        assert github_env == "" and github_output == "", (
            "nothing may reach GITHUB_ENV or GITHUB_OUTPUT from a refused value"
        )
        assert "ash-repo must be owner/repo" in result.stdout + result.stderr

    def test_the_early_repo_check_refuses_before_the_value_is_echoed(self, tmp_path):
        """ash-repo is held to owner/repo before any message can print it.

        Without that first check, a cross-repository ash-repo with an empty
        ash-version reaches the message that names it, and a newline in it starts a
        line of its own, which the runner reads as a workflow command.
        """
        result, github_env, github_output = _run_resolve(
            tmp_path,
            CHECKED_ASH_REPO="a/b\n::warning::INJECTED",
            JOB_CONTEXT=_job_context(
                workflow_sha=SHA,
                workflow_repository="awslabs/automated-security-helper",
            ),
        )

        output = result.stdout + result.stderr
        assert result.returncode != 0, output
        assert "ash-repo must be owner/repo" in output, output
        commands = [line for line in output.splitlines() if line.startswith("::")]
        assert len(commands) == 1, commands
        assert github_env == "" and github_output == ""

    def test_the_late_repo_check_refuses_a_bad_workflow_repository(self, tmp_path):
        """The repository taken from the job context is held to owner/repo too.

        Without the second check, a job.workflow_repository with a newline would
        reach GITHUB_ENV as a variable of its own.
        """
        result, github_env, github_output = _run_resolve(
            tmp_path,
            CHECKED_ASH_VERSION="v3.7.1",
            JOB_CONTEXT=_job_context(
                workflow_sha=SHA, workflow_repository="a/b\nINJECTED=1"
            ),
        )

        assert result.returncode != 0, github_env
        assert "ash-repo must be owner/repo" in result.stdout + result.stderr
        assert github_env == "" and github_output == ""

    @pytest.mark.parametrize(
        "ref, in_url",
        [
            ("feat@x", "feat%40x"),
            ("a,b=c", "a%2Cb%3Dc"),
            ("ünï", "%C3%BCn%C3%AF"),
            ("x#y", "x%23y"),
            ("feat/x", "feat/x"),
        ],
    )
    def test_a_branch_git_accepts_is_installed_percent_encoded(
        self, tmp_path, ref, in_url
    ):
        """Any name `git check-ref-format` accepts, written so the URL keeps its shape.

        A raw `@` would split the URL at the wrong place and a raw `#` would start a
        fragment; uv percent-decodes the revision of a git URL (measured with uv
        0.12.0 against a local repository with these branch names).
        """
        result, github_env, github_output = _run_resolve(
            tmp_path,
            CHECKED_ASH_VERSION=ref,
            JOB_CONTEXT=_job_context(
                workflow_sha=SHA,
                workflow_repository="awslabs/automated-security-helper",
            ),
        )

        assert result.returncode == 0, result.stdout + result.stderr
        assert (
            "ASH_UVX_SOURCE=automated-security-helper[cdk] @ "
            f"git+https://github.com/awslabs/automated-security-helper@{in_url}"
        ) in github_env.splitlines()
        assert f"version-url={in_url}" in github_output.splitlines()
        assert urllib.parse.unquote(in_url) == ref


@pytest.mark.unit
def test_the_cfn_nag_assets_url_takes_the_pinned_commit():
    """The cfn-nag Gemfile URL names the commit the pin step resolved.

    The pin step (id ash-pin) writes ASH_ASSETS_URL with that commit to GITHUB_ENV,
    so the Install cfn-nag step must not set it in its own env, which would win over
    GITHUB_ENV and could name the ref again. A commit id needs no percent-encoding.
    Reads YAML only, so it runs on every platform rather than with the shell tests.
    """
    (step,) = [step for step in _steps() if step.get("name") == "Install cfn-nag"]
    assert "ASH_ASSETS_URL" not in (step.get("env") or {}), step.get("env")
    (pin,) = [step for step in _steps() if step.get("id") == "ash-pin"]
    assert (
        "ASH_ASSETS_URL=https://raw.githubusercontent.com/${ASH_REPO}/${COMMIT}"
        "/automated_security_helper/assets"
    ) in pin["run"], pin["run"]
    # Only the pin reads the raw ref, for `git ls-remote`; nothing puts it in a URL.
    readers = [
        step.get("name")
        for step in _steps()
        if step.get("id") != "ash-pin"
        and "steps.ash-source.outputs.version }}" in str(step)
    ]
    assert not readers, f"these steps put the raw ref in a URL: {readers}"


@pytest.mark.unit
@pytest.mark.parametrize("name", ["ash-version", "ash-repo"])
def test_the_inputs_say_a_copy_outside_ash_must_set_both(name):
    """A copy kept in another repository resolves job.workflow_* to that repository."""
    description = _inputs()[name]["description"]
    assert "copy of this file kept outside ASH's repository" in description, description


@pytest.mark.unit
def test_every_install_input_defaults_to_true():
    inputs = _inputs()
    installs = {
        name: spec for name, spec in inputs.items() if name.startswith("install-")
    }

    assert installs, f"no install-* inputs found in {WORKFLOW_RELATIVE}"
    off = sorted(
        name for name, spec in installs.items() if spec.get("default") is not True
    )
    assert not off, (
        f"these install inputs default to off: {off}. Each installs the tool behind a "
        "default scanner, so a caller that leaves it unset gets that scanner MISSING "
        "and the incomplete-scan check fails the job."
    )
