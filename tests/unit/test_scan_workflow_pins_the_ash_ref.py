# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan job resolves the ASH ref to one commit, once, before anything installs ASH.

Why this file exists
--------------------
``ash-version`` may name a branch or a tag (``refs/heads/main`` in the merge queue,
``main`` by default). Every ``uv``/``uvx`` call and the cfn-nag asset URL resolved that
name again, so a merge that landed while the job ran could give one step one ASH and
the next step another, or install one ASH and the cfn-nag Gemfile of another.

The job's first step now resolves ``ash-version`` in ``ash-repo`` to a commit with
``git ls-remote`` and writes ``ASH_UVX_SOURCE`` and ``ASH_ASSETS_URL`` with that commit
to ``GITHUB_ENV``, which the runner applies over the workflow-level values for every
later step.

What this asserts
-----------------
1. The pinning step is the job's first step, and for a branch name, a full branch ref,
   an annotated tag and a lightweight tag it writes the commit the ref points at (the
   tag's commit, not the tag object) into both variables.
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
from pathlib import Path
from typing import Any

import pytest

from tests.utils import github_actions as ga

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


def _pin_step() -> dict[str, Any]:
    _, job = _workflow_and_job()
    found = [
        step
        for step in job.get("steps") or []
        if "GITHUB_ENV" in str(step.get("run") or "")
        and "ASH_UVX_SOURCE=" in str(step.get("run") or "")
    ]
    assert len(found) == 1, (
        "expected one step that writes ASH_UVX_SOURCE to GITHUB_ENV, found "
        f"{[s.get('name') for s in found]}"
    )
    return found[0]


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
    return ga.with_inputs(context, ga.call_inputs(caller, workflow, context))


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
    def test_the_pin_is_the_jobs_first_step(self):
        _, job = _workflow_and_job()
        assert (job.get("steps") or [])[0] is _pin_step() or (
            (job.get("steps") or [])[0].get("name") == _pin_step().get("name")
        ), "the step that pins the ASH ref is not the job's first step"

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

    def test_a_full_commit_id_is_used_without_contacting_the_repository(self, tmp_path):
        repo = AshRepository(tmp_path / "ash")
        commit = "0123456789abcdef0123456789abcdef01234567"
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
