# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan job resolves the ASH ref to one commit, once, before anything installs ASH.

Why this file exists
--------------------
``ash-version`` may name a branch or a tag (``refs/heads/main`` in the merge queue,
``main`` by default). Every ``uv``/``uvx`` call and the cfn-nag asset URL resolved that
name again, so a merge that landed while the job ran could give one step one ASH and
the next step another, or install one ASH and the cfn-nag Gemfile of another.

The "Resolve the ASH to install" step turns the checked inputs into a repository
and a ref (an empty input means the workflow file's own commit; see
test_reusable_workflow_defaults.py), and the pin step right after it resolves that
ref in that repository to a commit with ``git ls-remote`` and writes
``ASH_UVX_SOURCE`` and ``ASH_ASSETS_URL`` with that commit to ``GITHUB_ENV``, which
the runner applies over the workflow-level values for every later step.

What this asserts
-----------------
1. The pinning step follows only the input check, which only reads its environment,
   the one_line definer and the resolve step, which contacts nothing; and for a
   branch name, a full branch ref, an annotated tag and a lightweight tag it writes
   the commit the ref points at (the tag's commit, not the tag object) into both
   variables.
2. Every later step that installs ASH or fetches the cfn-nag Gemfile uses that commit,
   even after the branch has moved on.
3. A full commit id is used as given, without contacting the repository.
4. A name that is both a branch and a tag on different commits, a name that matches
   nothing, a value that starts with ``-``, and an ``ash-repo`` that is not
   ``owner/name`` are refused.

``https://github.com/<ash-repo>.git`` is served from a local repository through git's
``url.<base>.insteadOf``, set in the environment (``GIT_CONFIG_COUNT``), so the step's
own command line is what runs.

What it does not cover
----------------------
GitHub serving ``ls-remote`` for the repository, and a private ``ash-repo`` (which
``uvx`` could not install either, since it fetches without credentials).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import urllib.parse
from pathlib import Path
from typing import Any

import pytest

from tests.utils import github_actions as ga
from tests.utils import workflow_commands as wc
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS

pytestmark = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None or shutil.which("git") is None,
    reason="the steps under test are bash steps that run git on ubuntu-latest",
)

SCAN_WORKFLOW = ga.WORKFLOWS_DIR / "run-ash-security-scan.yml"
ASH_REPO = "awslabs/automated-security-helper"
ASH_URL = f"https://github.com/{ASH_REPO}.git"


def _git(*args: str, cwd: Path) -> str:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(cwd),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    proc = subprocess.run(  # nosec B603 B607 — fixed git argv in a temp directory
        ["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=CHILD_TIMEOUT_SECONDS,
    )
    assert proc.returncode == 0, f"git {' '.join(args)}: {proc.stderr}"
    return proc.stdout.strip()


class AshRepository:
    """A stand-in for ash-repo: main, an annotated and a lightweight tag, and `dup`."""

    def __init__(self, root: Path):
        self.origin = root / "ash.git"
        self.seed = root / "seed"
        self.seed.mkdir(parents=True)
        _git("init", "-q", "--bare", str(self.origin), cwd=root)
        _git("init", "-q", ".", cwd=self.seed)
        self.first = self.commit("first")
        _git("tag", "-a", "v9.9.9", "-m", "release", cwd=self.seed)
        _git("tag", "light", cwd=self.seed)
        _git("branch", "dup", cwd=self.seed)
        self.second = self.commit("second")
        _git("tag", "dup", cwd=self.seed)
        self.push()

    def commit(self, name: str) -> str:
        (self.seed / name).write_text(name, encoding="utf-8")
        _git("add", "-A", cwd=self.seed)
        _git("commit", "-q", "-m", name, cwd=self.seed)
        return _git("rev-parse", "HEAD", cwd=self.seed)

    def push(self) -> None:
        _git(
            "push",
            "-q",
            "--force",
            str(self.origin),
            "refs/heads/*:refs/heads/*",
            "refs/tags/*:refs/tags/*",
            cwd=self.seed,
        )

    def git_env(self, origin: Path | None = None) -> dict[str, str]:
        """Serve ASH_URL from `origin` (default: this repository) for the step's git."""
        return {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"url.file://{origin or self.origin}.insteadOf",
            "GIT_CONFIG_VALUE_0": ASH_URL,
        }


def _workflow_and_job() -> tuple[ga.Workflow, dict[str, Any]]:
    workflow = ga.load_workflow(SCAN_WORKFLOW)
    return workflow, workflow.jobs["ash"]


PIN_STEP_ID = "ash-pin"
RESOLVE_STEP_ID = "ash-source"
RESOLVE_STEP_NAME = "Resolve the ASH to install"


def _pin_step() -> dict[str, Any]:
    _, job = _workflow_and_job()
    found = [step for step in job.get("steps") or [] if step.get("id") == PIN_STEP_ID]
    assert len(found) == 1, f"expected one step with id {PIN_STEP_ID!r}, found {found}"
    run = str(found[0].get("run") or "")
    # The resolve step writes ASH_UVX_SOURCE with the name as given; the pin is the
    # step that writes both variables with the commit.
    assert "GITHUB_ENV" in run and "ASH_UVX_SOURCE=" in run and "ASH_ASSETS_URL=" in run
    return found[0]


def _with_resolved_source(context: dict[str, Any]) -> dict[str, Any]:
    """The resolve step's outputs for the checked ash-version and ash-repo.

    The pin step reads steps.ash-source.outputs (the resolve step keeps a given
    value and percent-encodes it for the URL; test_reusable_workflow_defaults.py
    runs that step itself), so a test that runs the pin alone supplies them from the
    input check's outputs the way the resolve step would write them.
    """
    checked = context["steps"][ga.INPUT_CHECK_STEP_ID]["outputs"]
    version, repo = checked["ash_version"], checked["ash_repo"]
    out = dict(context)
    out["steps"] = {
        **context["steps"],
        RESOLVE_STEP_ID: {
            "outputs": {
                "version": version,
                "version-url": urllib.parse.quote(version, safe="/"),
                "repo": repo,
            }
        },
    }
    return out


def _context(ash_version: str, ash_repo: str = ASH_REPO) -> dict[str, Any]:
    context = ga.base_context(
        event_name="merge_group",
        repository=ASH_REPO,
        repository_owner="awslabs",
        ref="refs/heads/gh-readonly-queue/main/pr-812-" + "3" * 40,
        event={"repository": {"default_branch": "main", "full_name": ASH_REPO}},
    )
    workflow, _ = _workflow_and_job()
    caller = {
        "with": {
            "ash-version": ash_version,
            "ash-repo": ash_repo,
            "install-grype": True,
            "install-syft": True,
            "install-cfn-nag": True,
        }
    }
    return _with_resolved_source(
        ga.with_inputs(context, ga.call_inputs(caller, workflow, context))
    )


def _run_pin(tmp_path: Path, repo: AshRepository, context, origin: Path | None = None):
    workflow, job = _workflow_and_job()
    sandbox = ga.StepSandbox(tmp_path / "runner")
    run = ga.run_step(
        sandbox, workflow, job, _pin_step(), context, extra_env=repo.git_env(origin)
    )
    return sandbox, run


def _source_ref(value: str) -> str:
    assert "git+https://github.com/" in value, value
    return value.rsplit("@", 1)[1]


class TestTheAshRefIsResolvedOnce:
    def test_the_pin_follows_only_the_input_check(self):
        # The input check (test_an_input_cannot_add_a_workflow_command.py) runs
        # first, so nothing prints an input before it is checked. It runs no tool and
        # writes only its own outputs. The one_line definer comes next: it writes the
        # helper file and nothing else (tests/utils/workflow_commands.py). The
        # resolve step comes third: it reads the checked inputs and the job context
        # and contacts no repository (test_reusable_workflow_defaults.py runs it). So
        # the pin is still the first step that resolves anything remotely or
        # installs anything.
        _, job = _workflow_and_job()
        steps = job.get("steps") or []
        names = [step.get("name") for step in steps]
        index = names.index(_pin_step().get("name"))
        assert names[:index] == [
            "Refuse an input that could start a workflow command",
            wc.DEFINER_NAME,
            RESOLVE_STEP_NAME,
        ], f"the steps before the one that pins the ASH ref: {names[:index]}"
        check = steps[0]
        assert "uses" not in check, check
        script = str(check.get("run") or "")
        for word in ("git ", "uv ", "uvx ", "curl ", "GITHUB_ENV", "GITHUB_PATH"):
            assert word not in script, (
                f"the input check runs or writes {word.strip()!r}"
            )
        definer = steps[1]
        assert "uses" not in definer, definer
        assert definer.get("run") == wc.DEFINER_RUN, definer.get("run")
        resolve = steps[2]
        assert resolve.get("id") == RESOLVE_STEP_ID, resolve
        assert "uses" not in resolve, resolve
        script = str(resolve.get("run") or "")
        for word in ("git ls-remote", "git fetch", "uv ", "uvx ", "curl "):
            assert word not in script, f"the resolve step runs {word.strip()!r}"

    @pytest.mark.parametrize(
        "ash_version,expected",
        [
            pytest.param("main", "second", id="branch name"),
            pytest.param("refs/heads/main", "second", id="full branch ref"),
            pytest.param("v9.9.9", "first", id="annotated tag"),
            pytest.param("light", "first", id="lightweight tag"),
        ],
    )
    def test_the_ref_is_written_as_a_commit(self, tmp_path, ash_version, expected):
        repo = AshRepository(tmp_path / "ash")
        sandbox, run = _run_pin(tmp_path, repo, _context(ash_version))
        assert run.proc.returncode == 0, run.describe()
        commit = getattr(repo, expected)
        env = ga.read_github_env(sandbox)
        assert _source_ref(env.get("ASH_UVX_SOURCE", "")) == commit, env
        assert env.get("ASH_ASSETS_URL") == (
            f"https://raw.githubusercontent.com/{ASH_REPO}/{commit}"
            "/automated_security_helper/assets"
        ), env

    def test_later_steps_use_the_pinned_commit_after_the_branch_moved(self, tmp_path):
        repo = AshRepository(tmp_path / "ash")
        context = _context("refs/heads/main")
        sandbox, run = _run_pin(tmp_path, repo, context)
        assert run.proc.returncode == 0, run.describe()
        pinned = repo.second
        repo.commit("third")
        repo.push()

        workflow, job = _workflow_and_job()
        github_env = ga.read_github_env(sandbox)
        sources, urls = [], []
        for name in (
            "Compute cache keys",
            "Install Grype",
            "Install Syft",
            "Install cfn-nag",
        ):
            (step,) = [s for s in job["steps"] if s.get("name") == name]
            later = ga.run_step(
                sandbox, workflow, job, step, context, github_env=github_env
            )
            assert later.proc.returncode == 0, later.describe()
            for call in later.calls:
                argv = call["argv"]
                for flag in ("--from", "--with"):
                    if flag in argv:
                        sources.append((name, argv[argv.index(flag) + 1]))
                if call["tool"] == "curl":
                    urls.append((name, call["url"]))
        assert sources and urls, (sources, urls)
        wrong = [(n, s) for n, s in sources if _source_ref(s) != pinned]
        wrong += [(n, u) for n, u in urls if f"/{pinned}/" not in u]
        assert not wrong, (
            f"after the pin, these steps resolve ASH somewhere other than {pinned}: "
            f"{wrong}"
        )

    @pytest.mark.parametrize("ash_version", ["main", "main\n"], ids=["plain", "block"])
    def test_a_one_line_block_scalar_pins_like_the_plain_value(
        self, tmp_path, ash_version
    ):
        # Through the real input check: its output is what the pin step reads.
        repo = AshRepository(tmp_path / "ash")
        workflow, job = _workflow_and_job()
        (check,) = [s for s in job["steps"] if s.get("id") == ga.INPUT_CHECK_STEP_ID]
        check_sandbox = ga.StepSandbox(tmp_path / "check")
        checked = ga.run_step(
            check_sandbox, workflow, job, check, _context(ash_version)
        )
        assert checked.proc.returncode == 0, checked.describe()
        context = _context(ash_version)
        context["steps"] = {
            **context["steps"],
            ga.INPUT_CHECK_STEP_ID: {"outputs": ga.read_github_output(check_sandbox)},
        }
        # The resolve step's outputs, from what the check wrote.
        context = _with_resolved_source(context)
        sandbox, run = _run_pin(tmp_path, repo, context)
        assert run.proc.returncode == 0, run.describe()
        assert _source_ref(ga.read_github_env(sandbox)["ASH_UVX_SOURCE"]) == repo.second

    def test_a_full_commit_id_is_used_without_contacting_the_repository(self, tmp_path):
        repo = AshRepository(tmp_path / "ash")
        commit = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret
        sandbox, run = _run_pin(
            tmp_path, repo, _context(commit), origin=tmp_path / "no-such-repository"
        )
        assert run.proc.returncode == 0, run.describe()
        assert _source_ref(ga.read_github_env(sandbox)["ASH_UVX_SOURCE"]) == commit


class TestARefThatDoesNotNameOneCommitIsRefused:
    @pytest.mark.parametrize(
        "ash_version",
        [
            pytest.param("dup", id="a branch and a tag on different commits"),
            pytest.param("no-such-ref", id="matches nothing"),
            pytest.param("--upload-pack=touch", id="starts with a dash"),
        ],
    )
    def test_the_ref_is_refused(self, tmp_path, ash_version):
        repo = AshRepository(tmp_path / "ash")
        sandbox, run = _run_pin(tmp_path, repo, _context(ash_version))
        assert run.proc.returncode != 0, run.describe()
        assert "::error::" in run.proc.stdout, run.describe()
        assert "ASH_UVX_SOURCE" not in ga.read_github_env(sandbox)

    @pytest.mark.parametrize(
        "ash_repo",
        ["awslabs", "awslabs/automated-security-helper/extra", "awslabs/x\nEXTRA=1"],
    )
    def test_an_ash_repo_that_is_not_owner_and_name_is_refused(
        self, tmp_path, ash_repo
    ):
        repo = AshRepository(tmp_path / "ash")
        sandbox, run = _run_pin(tmp_path, repo, _context("main", ash_repo=ash_repo))
        assert run.proc.returncode != 0, run.describe()
        assert "::error::" in run.proc.stdout, run.describe()
        assert ga.read_github_env(sandbox) == {}


class TestARefusalPrintsOneErrorLineAndNotTheValue:
    """The runner starts a new line at a line feed or a carriage return, and reads a
    line that starts with `::` as a workflow command. Both refusals printed the value
    they refused, so `ash-repo: "a/b\\n::warning::EXTRA"` issued a warning of the
    caller's choosing. They must print one `::error::` line that does not hold it.

    The pin step reads the resolve step's outputs, which carry the input check's
    values; ga.with_inputs and _with_resolved_source supply those as the two steps
    would write them, so this runs the pin step's own refusals."""

    @pytest.mark.parametrize("brk", ["\n", "\r"], ids=["line feed", "carriage return"])
    @pytest.mark.parametrize("which", ["ash-repo", "ash-version"])
    def test_no_second_workflow_command_line_appears(self, tmp_path, which, brk):
        repo = AshRepository(tmp_path / "ash")
        if which == "ash-repo":
            context = _context("main", ash_repo=f"a/b{brk}::warning::EXTRA")
        else:
            context = _context(f"x{brk}::warning::EXTRA")
        sandbox, run = _run_pin(tmp_path, repo, context)
        commands = ga.workflow_command_lines(run.proc.stdout, run.proc.stderr)
        assert run.proc.returncode != 0, run.describe()
        assert len(commands) == 1 and commands[0].startswith("::error::"), (
            commands,
            run.describe(),
        )
        assert "EXTRA" not in run.proc.stdout + run.proc.stderr, run.describe()
        assert ga.read_github_env(sandbox) == {}
