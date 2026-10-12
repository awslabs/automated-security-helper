# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The required ASH check scans a pull request with the base branch's ASH config.

Why this file exists
--------------------
``ash / SAST, SCA, and IaC Scan`` installs ASH from the pull request's base commit
(tests/unit/test_required_scan_installs_ash_from_the_base_branch.py). The config it
scanned with still came from the checkout: ``--source-dir .`` with no ``--config``,
so ASH discovered the pull request's own ``.ash/.ash.yaml``. A pull request could
then add a suppression or an ignore path for its own finding and pass the check
that gates it.

The required check reads its config from the base
commit and passes it as ``--config`` (which also stops ASH discovering one in the
checkout), and the informational job keeps the pull request's own config. Config
edits in a pull request reach the required check once merged.

``run-ash-security-scan.yml`` does this behind a ``config-ref`` input, so external
callers keep reading their checkout unless they opt in.

What this asserts
-----------------
Each step's own shell is run (``tests/utils/github_actions.py``) against a real git
repository: an ``origin`` holding a base commit, and a checkout whose working tree
holds a different config, as a pull request's merge commit would.

1. For a same-repository pull request, a fork pull request and a pull request into
   a branch other than the default, the required check asks for its config from the
   base commit (``config-ref``); for a merge-queue entry, from the default branch,
   as it does for the ASH install (``merge_group.base_sha`` of an entry behind the
   first is the previous entry's unmerged, temporary commit). Every step that runs
   ASH (the scan and ``ash report``) then gets ``--config`` and ``ASH_CONFIG``
   naming a file outside the checkout whose bytes are that commit's, never the
   checkout's.
2. A base commit without the file scans with ASH's defaults, written out as an
   empty config so discovery cannot fall back to the checkout's, and says so.
3. The step refuses, rather than reads as missing, a ``config-ref`` without
   ``config``, a path that is absolute or has an empty, ``.`` or ``..`` segment,
   and a base-commit entry that is a symlink.
4. The informational job passes no ``config-ref``, so it scans with the pull
   request's own config; and a caller that sets neither input gets no
   ``--config`` at all (controls; both pass before the fix).

What it does not cover
----------------------
* Tool config files the config names by a relative path
  (``scanners.<name>.options.config_file``, such as ``.ash/.grype.yaml``) are still
  read from the checkout, as are files each scanner discovers on its own and inline
  suppression comments. ASH already refuses some in-tree tool config paths
  (``config/path_trust.py``); the rest is not something a workflow input can change.
* A config that ``extends`` another file fails to load with ``config-ref``, because
  only the one file is fetched. This repository's config extends nothing.
* Whether GitHub serves ``git fetch origin <sha>`` for the base commit is GitHub's
  behavior; here ``origin`` is a local repository configured to allow it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.utils import github_actions as ga
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS

pytestmark = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None or shutil.which("git") is None,
    reason="the steps under test are bash steps that run git on ubuntu-latest",
)

REQUIRED_SCAN_CHECK = "ash / SAST, SCA, and IaC Scan"
SCAN_WORKFLOW = ga.WORKFLOWS_DIR / "run-ash-security-scan.yml"
BASE_REPO = "awslabs/automated-security-helper"
FORK_REPO = "contributor/automated-security-helper"
DEFAULT_BRANCH = "main"
PR_NUMBER = 812
HEAD_SHA = "2222222222222222222222222222222222222222"
MERGE_SHA = "3333333333333333333333333333333333333333"

CONFIG_PATH = ".ash/.ash.yaml"
BASE_CONFIG = "# the base commit's config\nproject_name: base\n"
CHECKOUT_CONFIG = (
    "# the checkout's config\nproject_name: checkout\nglobal_settings:\n"
    "  ignore_paths:\n    - path: '**'\n      reason: added by the pull request\n"
)


# --------------------------------------------------------------------------- git


def _git(*args: str, cwd: Path, home: Path) -> str:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
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


class Repository:
    """An origin with one base commit, and a checkout of a different tree."""

    def __init__(
        self,
        root: Path,
        *,
        base_files: dict[str, str | None],
        checkout_files: dict[str, str] | None = None,
    ):
        self.sandbox = ga.StepSandbox(root / "runner")
        # `uv run ... -- python ...` runs that python here, as the real uv would run
        # it from the environment it builds; this interpreter has ASH and PyYAML.
        shim_dir = root / "uv-shim"
        shim_dir.mkdir()
        shim = shim_dir / "uv"
        shim.write_text(
            "#!/bin/sh\n"
            'while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done\n'
            '[ "$#" -gt 0 ] && shift\n'
            '[ "$1" = "python" ] && shift\n'
            f'exec "{sys.executable}" "$@"\n',
            encoding="utf-8",
        )
        shim.chmod(0o755)
        self.uv_env = {
            "PATH": os.pathsep.join(
                [str(shim_dir), str(self.sandbox.stub_dir), os.environ.get("PATH", "")]
            )
        }
        home = self.sandbox.home
        origin = root / "origin.git"
        origin.mkdir()
        _git("init", "-q", "--bare", ".", cwd=origin, home=home)
        _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=origin, home=home)
        seed = root / "seed"
        seed.mkdir()
        _git("init", "-q", ".", cwd=seed, home=home)
        (seed / "README").write_text("base\n", encoding="utf-8")
        for name, content in base_files.items():
            path = seed / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if content is None:
                path.symlink_to("/etc/hostname")
            else:
                path.write_text(content, encoding="utf-8")
        _git("add", "-A", cwd=seed, home=home)
        _git("commit", "-q", "-m", "base", cwd=seed, home=home)
        _git(
            "push",
            "-q",
            f"file://{origin}",
            "HEAD:refs/heads/main",
            cwd=seed,
            home=home,
        )
        self.base_sha = _git("rev-parse", "HEAD", cwd=seed, home=home)
        self.origin = origin
        self._seed = seed

        workspace = self.sandbox.workspace
        _git("init", "-q", ".", cwd=workspace, home=home)
        _git("remote", "add", "origin", f"file://{origin}", cwd=workspace, home=home)
        checkout_config = workspace / CONFIG_PATH
        checkout_config.parent.mkdir(parents=True)
        checkout_config.write_text(CHECKOUT_CONFIG, encoding="utf-8")
        for name, content in (checkout_files or {}).items():
            path = workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def advance(self, files: dict[str, str]) -> str:
        """Commit `files` on main and push it: the branch moves on mid-run."""
        home = self.sandbox.home
        for name, content in files.items():
            path = self._seed / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        _git("add", "-A", cwd=self._seed, home=home)
        _git("commit", "-q", "-m", "later", cwd=self._seed, home=home)
        _git(
            "push",
            "-q",
            f"file://{self.origin}",
            "HEAD:refs/heads/main",
            cwd=self._seed,
            home=home,
        )
        return _git("rev-parse", "HEAD", cwd=self._seed, home=home)

    def ash_url_env(self) -> dict[str, str]:
        """Serve https://github.com/<BASE_REPO>.git from origin, for the pin step's git."""
        return {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"url.file://{self.origin}.insteadOf",
            "GIT_CONFIG_VALUE_0": f"https://github.com/{BASE_REPO}.git",
        }


# --------------------------------------------------------------------------- contexts


def _pull_request(base_sha: str, *, fork: bool, base_ref: str = DEFAULT_BRANCH):
    head_repo = FORK_REPO if fork else BASE_REPO
    return ga.base_context(
        event_name="pull_request",
        repository=BASE_REPO,
        repository_owner=BASE_REPO.split("/")[0],
        ref=f"refs/pull/{PR_NUMBER}/merge",
        ref_name=f"{PR_NUMBER}/merge",
        sha=MERGE_SHA,
        head_ref="feature-branch",
        base_ref=base_ref,
        event={
            "repository": {"default_branch": DEFAULT_BRANCH, "full_name": BASE_REPO},
            "pull_request": {
                "number": PR_NUMBER,
                "head": {
                    "ref": "feature-branch",
                    "sha": HEAD_SHA,
                    "repo": {"full_name": head_repo},
                },
                "base": {
                    "ref": base_ref,
                    "sha": base_sha,
                    "repo": {"full_name": BASE_REPO},
                },
            },
        },
    )


# merge_group.base_sha of an entry behind the first in the queue: the previous
# entry's temporary merge commit, which origin does not have.
PREVIOUS_ENTRY_SHA = "4444444444444444444444444444444444444444"


def _merge_group(base_sha: str, target: str = DEFAULT_BRANCH):
    """A queue entry behind another; the target branch's tip is ``base_sha``."""
    queue = f"gh-readonly-queue/{target}/pr-{PR_NUMBER}-{MERGE_SHA}"
    return ga.base_context(
        event_name="merge_group",
        repository=BASE_REPO,
        repository_owner=BASE_REPO.split("/")[0],
        ref=f"refs/heads/{queue}",
        ref_name=queue,
        sha=MERGE_SHA,
        head_ref="",
        base_ref="",
        event={
            "repository": {"default_branch": DEFAULT_BRANCH, "full_name": BASE_REPO},
            "merge_group": {
                "base_ref": f"refs/heads/{target}",
                "base_sha": PREVIOUS_ENTRY_SHA,
                "head_ref": f"refs/heads/{queue}",
                "head_sha": MERGE_SHA,
            },
        },
    )


EVENTS = [
    pytest.param(lambda sha: _pull_request(sha, fork=False), id="same-repository PR"),
    pytest.param(lambda sha: _pull_request(sha, fork=True), id="fork PR"),
    pytest.param(
        lambda sha: _pull_request(sha, fork=False, base_ref="release-3.7"),
        id="PR into a non-default branch",
    ),
    pytest.param(_merge_group, id="merge queue entry"),
]


def _scan_callers(context: dict[str, Any]):
    """(check names, inputs) of every job the event starts that calls the scan workflow."""
    for workflow in ga.all_workflows():
        if not ga.triggers(workflow, context):
            continue
        scoped = dict(context)
        scoped["needs"] = {
            j: {"result": "success", "outputs": {}} for j in workflow.jobs
        }
        for job_id, job in workflow.jobs.items():
            called = ga.local_reusable_workflow(job)
            if called is None or called.path.resolve() != SCAN_WORKFLOW.resolve():
                continue
            if ga.job_runs(job, scoped):
                yield ga.check_names(job_id, job), ga.call_inputs(job, called, scoped)


def _required_inputs(context: dict[str, Any]) -> dict[str, Any]:
    found = [
        inputs
        for names, inputs in _scan_callers(context)
        if REQUIRED_SCAN_CHECK in names
    ]
    assert len(found) == 1, (
        f"expected one {REQUIRED_SCAN_CHECK!r} job, found {len(found)}"
    )
    return found[0]


def _informational_inputs(context: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        inputs
        for names, inputs in _scan_callers(context)
        if any("informational" in name.lower() for name in names)
    ]


# --------------------------------------------------------------------------- steps


def _job() -> tuple[ga.Workflow, dict[str, Any]]:
    workflow = ga.load_workflow(SCAN_WORKFLOW)
    return workflow, workflow.jobs["ash"]


def _config_ref_steps() -> list[dict[str, Any]]:
    _, job = _job()
    return [
        s
        for s in job.get("steps") or []
        if "inputs.config-ref" in str(s.get("if") or "")
    ]


def _ash_steps() -> list[dict[str, Any]]:
    """Steps that run ASH itself (the scan, the report), not a dependency install."""
    _, job = _job()
    return [
        s
        for s in job.get("steps") or []
        if "uvx" in str(s.get("run") or "")
        and " ash " in f" {s.get('run')} ".replace("\\\n", " ")
        and "dependencies install" not in str(s.get("run"))
    ]


def _outputs(sandbox: ga.StepSandbox) -> dict[str, str]:
    path = sandbox.runner_temp / "_runner_file_commands" / "output"
    if not path.exists():
        return {}
    pairs = [
        line.split("=", 1) for line in path.read_text().splitlines() if "=" in line
    ]
    return dict(pairs)


def _run_config_ref_step(
    repo: Repository,
    context: dict[str, Any],
    inputs: dict[str, Any],
    earlier: dict[str, Any] | None = None,
) -> tuple[ga.StepRun | None, dict[str, Any]]:
    """Run the steps gated on config-ref in order, stopping at the first failure.

    ``earlier`` is the steps context of steps that ran before them, such as the pin.
    """
    workflow, job = _job()
    ctx = ga.with_inputs(context, inputs)
    steps: dict[str, Any] = dict(earlier or {})
    run = None
    for step in _config_ref_steps():
        scoped = {**ctx, "steps": steps}
        if not ga.condition_holds(step.get("if"), scoped):
            continue
        output_file = repo.sandbox.runner_temp / "_runner_file_commands" / "output"
        if output_file.exists():
            output_file.write_text("", encoding="utf-8")
        run = ga.run_step(
            repo.sandbox, workflow, job, step, scoped, extra_env=repo.uv_env
        )
        ok = run.proc.returncode == 0
        steps[step["id"]] = {
            "outputs": _outputs(repo.sandbox) if ok else {},
            "outcome": "success" if ok else "failure",
            "stdout": run.proc.stdout,
        }
        if not ok:
            break
    return run, steps


def _ash_invocations(
    repo: Repository, context: dict[str, Any], inputs: dict[str, Any], steps: dict
) -> list[tuple[str, dict[str, Any]]]:
    workflow, job = _job()
    ctx = ga.with_inputs({**context, "steps": steps}, inputs)
    found = []
    for step in _ash_steps():
        run = ga.run_step(repo.sandbox, workflow, job, step, ctx)
        assert run.proc.returncode == 0, run.describe()
        calls = [c for c in run.calls_to("uvx") if "ash" in c["argv"]]
        assert calls, f"step {step.get('name')!r} ran no ASH:\n" + run.describe()
        found += [(str(step.get("name")), call) for call in calls]
    return found


def _config_argument(argv: list[str]) -> str | None:
    values = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a in ("--config", "-c")]
    return values[-1] if values else None


# --------------------------------------------------------------------------- 1 and 2


class TestTheRequiredCheckScansWithTheBaseCommitsConfig:
    def test_the_locators_find_the_steps(self):
        found = _config_ref_steps()
        assert found and found[0].get("id") == "config-ref", (
            "expected the steps gated on config-ref, starting with the fetch"
        )
        names = {str(s.get("name")) for s in _ash_steps()}
        assert len(names) >= 2, f"expected the scan and the report steps, found {names}"

    @pytest.mark.parametrize("make_context", EVENTS)
    def test_every_ash_step_gets_the_base_commits_config(self, tmp_path, make_context):
        repo = Repository(tmp_path, base_files={CONFIG_PATH: BASE_CONFIG})
        context = make_context(repo.base_sha)
        inputs = _required_inputs(context)
        if context["github"]["event_name"] == "merge_group":
            # The default branch, as for the ASH install: merge_group.base_sha is the
            # previous entry's unmerged commit here.
            expected = {DEFAULT_BRANCH, f"refs/heads/{DEFAULT_BRANCH}"}
        else:
            expected = {repo.base_sha}
        assert inputs.get("config-ref") in expected, (
            f"the required check reads its config from {inputs.get('config-ref')!r}, "
            f"not {sorted(expected)}"
        )
        run, steps = _run_config_ref_steps_or_fail(repo, context, inputs)
        invocations = _ash_invocations(repo, context, inputs, steps)
        for name, call in invocations:
            config = _config_argument(call["argv"])
            assert config, (
                f"step {name!r} runs ASH without --config, so ASH discovers the "
                f"checkout's config: {call['argv']}"
            )
            assert not repo.sandbox.is_inside_workspace(config), (
                f"step {name!r} passes --config {config}, a file in the checkout"
            )
            assert Path(config).read_text(encoding="utf-8") == BASE_CONFIG, (
                f"step {name!r} scans with {config}, which does not hold the base "
                "commit's config"
            )
            assert call["env"]["ASH_CONFIG"] == config, (
                f"step {name!r} passes --config {config} but ASH_CONFIG="
                f"{call['env']['ASH_CONFIG']!r}; the parts of ASH that read the "
                "variable would see another file"
            )

    @pytest.mark.parametrize(
        "missing",
        [
            pytest.param(None, id="config-ref-missing not passed"),
            pytest.param("refuse", id="config-ref-missing refuse"),
            pytest.param("", id="config-ref-missing empty"),
        ],
    )
    def test_a_base_commit_without_the_config_is_refused(self, tmp_path, missing):
        """The caller named a config; scanning without it would drop what it asked for.

        A case variant or a typo in `config` is the same as a missing file. For a
        caller whose config enables scanners that are off by default, or lowers the
        severity threshold, ASH's defaults are a weaker gate, so the step fails. Only
        `defaults` opts out; an empty value refuses like the default does.
        """
        repo = Repository(tmp_path, base_files={})
        context = _pull_request(repo.base_sha, fork=False)
        inputs = _required_inputs(context)
        if missing is not None:
            inputs = {**inputs, "config-ref-missing": missing}
        run, _ = _run_config_ref_step(repo, context, inputs)
        assert run is not None, "no step reads the config from config-ref"
        assert run.proc.returncode != 0, (
            "a config missing at config-ref was not refused:\n" + run.describe()
        )
        assert "::error::" in run.proc.stdout and CONFIG_PATH in run.proc.stdout, (
            run.describe()
        )
        assert "::warning::" not in run.proc.stdout, run.describe()

    def test_the_bootstrap_opt_in_scans_with_ash_defaults(self, tmp_path):
        """`config-ref-missing: defaults` is for the pull request adding a first config."""
        repo = Repository(tmp_path, base_files={})
        context = _pull_request(repo.base_sha, fork=False)
        inputs = {**_required_inputs(context), "config-ref-missing": "defaults"}
        run, steps = _run_config_ref_steps_or_fail(repo, context, inputs)
        assert (
            "::warning::" in steps["config-ref"]["stdout"]
            and "default config" in steps["config-ref"]["stdout"]
        ), run.describe()
        for name, call in _ash_invocations(repo, context, inputs, steps):
            config = _config_argument(call["argv"])
            assert config and not repo.sandbox.is_inside_workspace(config), call
            assert Path(config).read_text(encoding="utf-8").strip() == "{}", (
                f"step {name!r} does not scan with an empty (default) config"
            )

    @pytest.mark.parametrize("value", ["checkout", "Defaults", "true", "skip"])
    def test_an_unknown_config_ref_missing_value_is_refused(self, tmp_path, value):
        repo = Repository(tmp_path, base_files={CONFIG_PATH: BASE_CONFIG})
        context = _pull_request(repo.base_sha, fork=False)
        inputs = {**_required_inputs(context), "config-ref-missing": value}
        run, _ = _run_config_ref_step(repo, context, inputs)
        assert run is not None, "no step reads the config from config-ref"
        assert run.proc.returncode != 0, (
            f"config-ref-missing={value!r} was accepted:\n" + run.describe()
        )
        assert (
            "::error::" in run.proc.stdout and "config-ref-missing" in run.proc.stdout
        )


def _run_config_ref_steps_or_fail(repo, context, inputs):
    run, steps = _run_config_ref_step(repo, context, inputs)
    assert run is not None, "the config-ref step did not run for the required check"
    assert run.proc.returncode == 0, run.describe()
    return run, steps


# --------------------------------------------------------------------------- 3


class TestTheConfigRefStepRefusesWhatItCannotReadExactly:
    def _inputs(self, config: str, ref: str) -> dict[str, Any]:
        workflow, _ = _job()
        caller = {"with": {"config": config, "config-ref": ref}}
        return ga.call_inputs(caller, workflow, ga.base_context())

    def test_config_ref_without_config_is_refused(self, tmp_path):
        repo = Repository(tmp_path, base_files={CONFIG_PATH: BASE_CONFIG})
        context = _pull_request(repo.base_sha, fork=False)
        run, steps = _run_config_ref_step(
            repo, context, self._inputs("", repo.base_sha)
        )
        assert run is not None, "no step reads the config from config-ref"
        assert run.proc.returncode != 0, run.describe()
        assert "::error::" in run.proc.stdout
        assert steps == {} or not steps["config-ref"]["outputs"]

    @pytest.mark.parametrize(
        "config",
        [
            "/etc/hostname",
            "../outside.yaml",
            ".ash/../.ash/.ash.yaml",
            ".ash/./.ash.yaml",
            ".ash//.ash.yaml",
            ".ash/",
        ],
    )
    def test_a_path_git_would_not_read_as_written_is_refused(self, tmp_path, config):
        repo = Repository(tmp_path, base_files={CONFIG_PATH: BASE_CONFIG})
        context = _pull_request(repo.base_sha, fork=False)
        run, _ = _run_config_ref_step(
            repo, context, self._inputs(config, repo.base_sha)
        )
        assert run is not None, "no step reads the config from config-ref"
        assert run.proc.returncode != 0, (
            f"config {config!r} was accepted:\n" + run.describe()
        )
        assert "::warning::" not in run.proc.stdout, (
            "the path was read as a missing file and fell back to the defaults"
        )
        # The step's own check refuses it, not git failing on it later: git
        # refuses some of these spellings by itself ("outside repository"), which
        # would keep this test green with the step's check gone.
        assert (
            "::error::config must be a plain path inside the repository"
            in run.proc.stdout
        ), run.describe()

    def test_a_regular_file_with_a_non_ascii_name_is_read(self, tmp_path):
        """git ls-tree quotes such names unless -z is used; the file is still regular."""
        name = ".ash/\u00e1sh.yaml"
        repo = Repository(tmp_path, base_files={name: BASE_CONFIG})
        context = _pull_request(repo.base_sha, fork=False)
        run, steps = _run_config_ref_step(
            repo, context, self._inputs(name, repo.base_sha)
        )
        assert run is not None, "no step reads the config from config-ref"
        assert run.proc.returncode == 0, run.describe()
        path = steps["config-ref"]["outputs"]["path"]
        assert Path(path).read_text(encoding="utf-8") == BASE_CONFIG

    @pytest.mark.parametrize("failed", ["config-ref", "config-ref-files"])
    def test_no_step_runs_ash_after_a_config_ref_step_failed(self, tmp_path, failed):
        """With no path from the step, the fallback would be the checkout's config."""
        repo = Repository(tmp_path, base_files={CONFIG_PATH: BASE_CONFIG})
        context = _pull_request(repo.base_sha, fork=False)
        inputs = _required_inputs(context)
        assert inputs.get("config-ref"), "the required check sets no config-ref"
        assert failed in {s.get("id") for s in _config_ref_steps()}, failed
        steps = {"config-ref": {"outcome": "success", "outputs": {"path": "/x"}}}
        steps[failed] = {"outcome": "failure", "outputs": {}}
        ctx = ga.with_inputs(
            {**context, "__status__": "failure", "steps": steps}, inputs
        )
        running = [
            str(step.get("name"))
            for step in _ash_steps()
            if ga.condition_holds(step.get("if"), ctx)
        ]
        assert not running, (
            f"after the config-ref step failed, {running} still run ASH, and with no "
            "path from that step they would read the checkout's config"
        )

    def test_a_symlink_at_the_base_commit_is_refused(self, tmp_path):
        repo = Repository(tmp_path, base_files={CONFIG_PATH: None})
        context = _pull_request(repo.base_sha, fork=False)
        run, _ = _run_config_ref_step(repo, context, _required_inputs(context))
        assert run is not None, "no step reads the config from config-ref"
        assert run.proc.returncode != 0, run.describe()
        assert "not a regular file" in run.proc.stdout


# --------------------------------------------------------------------------- 4


class TestOtherScansKeepTheCheckoutsConfig:
    """Controls: both pass before the fix."""

    @pytest.mark.parametrize(
        "fork", [False, True], ids=["same-repository PR", "fork PR"]
    )
    def test_the_informational_scan_reads_the_pull_requests_own_config(
        self, tmp_path, fork
    ):
        repo = Repository(tmp_path, base_files={CONFIG_PATH: BASE_CONFIG})
        context = _pull_request(repo.base_sha, fork=fork)
        found = _informational_inputs(context)
        assert found, "no informational scan job was found for a pull request"
        for inputs in found:
            assert not inputs.get("config-ref"), inputs
            run, steps = _run_config_ref_step(repo, context, inputs)
            assert run is None
            for name, call in _ash_invocations(repo, context, inputs, steps):
                config = _config_argument(call["argv"])
                assert config is None or repo.sandbox.is_inside_workspace(
                    repo.sandbox.workspace / config
                ), f"step {name!r} scans the informational job with {config}"

    def test_a_caller_that_sets_neither_input_gets_no_config_argument(self, tmp_path):
        repo = Repository(tmp_path, base_files={CONFIG_PATH: BASE_CONFIG})
        context = _pull_request(repo.base_sha, fork=False)
        workflow, _ = _job()
        inputs = ga.call_inputs({"with": {}}, workflow, context)
        run, steps = _run_config_ref_step(repo, context, inputs)
        assert run is None
        for name, call in _ash_invocations(repo, context, inputs, steps):
            assert _config_argument(call["argv"]) is None, (name, call["argv"])
            assert call["env"]["ASH_CONFIG"] in (None, ""), (name, call["env"])

    def test_workflow_dispatch_reads_the_dispatched_refs_config(self):
        """No config-ref, and not the string `false` an `a && b` would render."""
        context = ga.base_context(
            event_name="workflow_dispatch",
            repository=BASE_REPO,
            repository_owner=BASE_REPO.split("/")[0],
            ref=f"refs/heads/{DEFAULT_BRANCH}",
            ref_name=DEFAULT_BRANCH,
            event={"repository": {"default_branch": DEFAULT_BRANCH}},
        )
        inputs = _required_inputs(context)
        assert ga.to_string(inputs.get("config-ref")) == "", inputs.get("config-ref")


# --------------------------------------------------------------------------- 5

TOOL_CONFIG_BASE = (
    "# the base commit's config, naming tool config files\n"
    "project_name: base\n"
    "scanners:\n"
    "  bandit:\n"
    "    options:\n"
    "      config_file: .ash/bandit.yaml\n"
    "  grype:\n"
    "    options:\n"
    "      config_file: ./.ash/.grype.yaml\n"
    "  checkov:\n"
    "    options:\n"
    "      config_file: /etc/an-operator-path.yaml\n"
)
BASE_BANDIT = "# bandit config at the base commit\nskips: []\n"
BASE_GRYPE = "# grype config at the base commit\nignore: []\n"
CHECKOUT_BANDIT = (
    "# bandit config in the pull request\nexclude_dirs: ['automated_security_helper']\n"
)
CHECKOUT_GRYPE = "# grype config in the pull request\nignore:\n  - package:\n      name: example-package\n"


def _scan_config(repo: Repository, context, inputs) -> Path:
    """The --config the scan step passes, after the config-ref steps ran."""
    run, steps = _run_config_ref_steps_or_fail(repo, context, inputs)
    configs = {
        _config_argument(call["argv"])
        for _, call in _ash_invocations(repo, context, inputs, steps)
    }
    assert len(configs) == 1 and None not in configs, configs
    return Path(configs.pop())


def _tool_config_paths(config: Path) -> dict[str, Any]:
    from automated_security_helper.config.ash_config import load_yaml_config

    with open(config, encoding="utf-8") as handle:
        document = load_yaml_config(handle)
    return {
        name: (section.get("options") or {}).get("config_file")
        for name, section in (document.get("scanners") or {}).items()
    }


class TestToolConfigFilesComeFromTheBaseCommit:
    """The base config's relative scanners.*.options.config_file are fetched too.

    bandit reads `config_file` relative to the working directory and grype relative
    to the source directory, both the checkout, so with only `.ash/.ash.yaml` taken
    from config-ref a pull request still set bandit's and grype's config for its own
    required check.
    """

    def _repo(self, tmp_path, base_files):
        return Repository(
            tmp_path,
            base_files=base_files,
            checkout_files={
                ".ash/bandit.yaml": CHECKOUT_BANDIT,
                ".ash/.grype.yaml": CHECKOUT_GRYPE,
            },
        )

    def test_each_relative_tool_config_comes_from_the_base_commit(self, tmp_path):
        repo = self._repo(
            tmp_path,
            {
                CONFIG_PATH: TOOL_CONFIG_BASE,
                ".ash/bandit.yaml": BASE_BANDIT,
                ".ash/.grype.yaml": BASE_GRYPE,
            },
        )
        context = _pull_request(repo.base_sha, fork=False)
        config = _scan_config(repo, context, _required_inputs(context))
        paths = _tool_config_paths(config)
        for scanner, expected in (("bandit", BASE_BANDIT), ("grype", BASE_GRYPE)):
            path = paths[scanner]
            assert path and Path(path).is_absolute(), (
                f"scanners.{scanner}.options.config_file is {path!r}, which resolves "
                "in the checkout, so the pull request's copy configures its own scan"
            )
            assert not repo.sandbox.is_inside_workspace(path), path
            assert Path(path).read_text(encoding="utf-8") == expected, (
                f"{path} does not hold the base commit's {scanner} config"
            )
        assert paths["checkov"] == "/etc/an-operator-path.yaml", (
            "an absolute path is the operator's and must be left as it is"
        )

    def test_a_tool_config_missing_at_the_base_commit_is_refused(self, tmp_path):
        repo = self._repo(
            tmp_path, {CONFIG_PATH: TOOL_CONFIG_BASE, ".ash/.grype.yaml": BASE_GRYPE}
        )
        context = _pull_request(repo.base_sha, fork=False)
        run, steps = _run_config_ref_step(repo, context, _required_inputs(context))
        assert run is not None and run.proc.returncode != 0, run and run.describe()
        assert (
            "::error::" in run.proc.stdout and ".ash/bandit.yaml" in run.proc.stdout
        ), run.describe()
        assert steps.get("config-ref-files", {}).get("outcome") == "failure", steps

    @pytest.mark.parametrize(
        "value", ["../outside.yaml", ".ash/../../outside.yaml", ".ash//bandit.yaml"]
    )
    def test_a_tool_config_path_outside_the_repository_is_refused(
        self, tmp_path, value
    ):
        config = TOOL_CONFIG_BASE.replace(".ash/bandit.yaml", value)
        repo = self._repo(
            tmp_path,
            {
                CONFIG_PATH: config,
                ".ash/bandit.yaml": BASE_BANDIT,
                ".ash/.grype.yaml": BASE_GRYPE,
            },
        )
        context = _pull_request(repo.base_sha, fork=False)
        run, _ = _run_config_ref_step(repo, context, _required_inputs(context))
        assert run is not None and run.proc.returncode != 0, run and run.describe()
        assert (
            "::error::" in run.proc.stdout and "scanners.bandit" in run.proc.stdout
        ), run.describe()

    def test_a_symlinked_tool_config_at_the_base_commit_is_refused(self, tmp_path):
        repo = self._repo(
            tmp_path,
            {
                CONFIG_PATH: TOOL_CONFIG_BASE,
                ".ash/bandit.yaml": None,
                ".ash/.grype.yaml": BASE_GRYPE,
            },
        )
        context = _pull_request(repo.base_sha, fork=False)
        run, _ = _run_config_ref_step(repo, context, _required_inputs(context))
        assert run is not None and run.proc.returncode != 0, run and run.describe()
        assert "not a regular file" in run.proc.stdout, run.describe()

    def test_the_rewritten_config_is_the_base_config_apart_from_those_paths(
        self, tmp_path, monkeypatch
    ):
        """This repository's own config, and environment references, survive the rewrite.

        The probes carry a default (``:dflt``): ASH resolves a reference only when it
        has one, so a probe without a default reads the same resolved or not and could
        not tell a kept reference from one written back as a literal. A quoted scalar
        is a literal in ASH's loader and must stay one.
        """
        from automated_security_helper.config.ash_config import load_yaml_config

        real = (ga.REPO_ROOT / CONFIG_PATH).read_text(encoding="utf-8")
        extra = (
            "\nash_env_probe:\n"
            "  explicit: !ENV ${ASH_PROBE_VALUE:dflt}\n"
            "  implicit: ${ASH_PROBE_VALUE:dflt}\n"
            "  single_quoted: '${ASH_PROBE_VALUE:dflt}'\n"
            '  double_quoted: "${ASH_PROBE_VALUE:dflt}"\n'
        )
        base_files = {CONFIG_PATH: real + extra}
        # Every relative tool config file the real config names, read from the tree.
        named = _tool_config_paths(ga.REPO_ROOT / CONFIG_PATH)
        relative = sorted(
            v.removeprefix("./") for v in named.values() if v and not v.startswith("/")
        )
        assert relative, "this repository's config names no tool config file"
        for name in relative:
            base_files[name] = (ga.REPO_ROOT / name).read_text(encoding="utf-8")
        repo = Repository(tmp_path, base_files=base_files)
        context = _pull_request(repo.base_sha, fork=False)
        config = _scan_config(repo, context, _required_inputs(context))

        monkeypatch.setenv("ASH_PROBE_VALUE", "resolved")
        original = load_yaml_config(base_files[CONFIG_PATH])
        rewritten = load_yaml_config(config.read_text(encoding="utf-8"))
        # Control: the probes resolve one way or the other in the original, so the
        # comparison below can see a change in either direction.
        assert original["ash_env_probe"] == {
            "explicit": "resolved",
            "implicit": "resolved",
            "single_quoted": "${ASH_PROBE_VALUE:dflt}",
            "double_quoted": "${ASH_PROBE_VALUE:dflt}",
        }, original["ash_env_probe"]
        assert rewritten.pop("ash_env_probe") == original.pop("ash_env_probe")
        for name, section in original["scanners"].items():
            value = (section.get("options") or {}).get("config_file")
            if value:
                new = rewritten["scanners"][name]["options"].pop("config_file")
                section["options"].pop("config_file")
                assert (
                    Path(new).read_text(encoding="utf-8")
                    == base_files[value.removeprefix("./")]
                )
        assert rewritten == original

        from automated_security_helper.config.resolve_config import resolve_config

        resolved = resolve_config(config_path=config, source_dir=repo.sandbox.workspace)
        assert resolved.project_name == original["project_name"]

    @pytest.mark.parametrize(
        "config_name,content",
        [
            pytest.param(
                ".ash/.ash.json",
                '{"project_name": "${ASH_PROBE_VALUE:dflt}", "scanners": '
                '{"bandit": {"options": {"config_file": ".ash/bandit.yaml"}}}}\n',
                id="json, where ASH resolves no reference",
            ),
            pytest.param(
                ".ashrc.toml",
                'project_name = "${ASH_PROBE_VALUE:dflt}"\n'
                "[scanners.bandit.options]\n"
                'config_file = ".ash/bandit.yaml"\n',
                id="toml, where ASH resolves every reference",
            ),
        ],
    )
    def test_references_in_json_and_toml_configs_keep_their_meaning(
        self, tmp_path, monkeypatch, config_name, content
    ):
        """The rewritten copy is YAML, so each string must be written the way that keeps it.

        ASH reads a JSON config without resolving ``${...}`` and resolves it in every
        TOML string; in YAML a plain ``${...}`` is a reference and a quoted one a literal.
        """
        from automated_security_helper.config.config_sources import read_config_file

        repo = Repository(
            tmp_path / "repo",
            base_files={config_name: content, ".ash/bandit.yaml": BASE_BANDIT},
        )
        context = _pull_request(repo.base_sha, fork=False)
        inputs = {**_required_inputs(context), "config": config_name}
        config = _scan_config(repo, context, inputs)

        monkeypatch.setenv("ASH_PROBE_VALUE", "resolved")
        original_file = tmp_path / "original" / config_name
        original_file.parent.mkdir(parents=True)
        original_file.write_text(content, encoding="utf-8")
        original = read_config_file(original_file)
        rewritten = read_config_file(config)
        assert config.suffix == ".yaml", config
        assert rewritten["project_name"] == original["project_name"], (
            f"project_name is {original['project_name']!r} when ASH reads "
            f"{config_name} and {rewritten['project_name']!r} after the rewrite"
        )
        assert (
            Path(rewritten["scanners"]["bandit"]["options"]["config_file"]).read_text(
                encoding="utf-8"
            )
            == BASE_BANDIT
        )


class TestTheMergeQueueResolvesItsOwnTarget:
    def test_a_queue_into_another_branch_installs_and_reads_from_that_branch(self):
        """`merge_group.base_ref` names the queue's target; the default branch need not be it."""
        context = _merge_group(PREVIOUS_ENTRY_SHA, target="release-3.7")
        inputs = _required_inputs(context)
        expected = {"release-3.7", "refs/heads/release-3.7"}
        assert inputs.get("ash-version") in expected, (
            f"a queue into release-3.7 installs ASH from {inputs.get('ash-version')!r}"
        )
        assert inputs.get("config-ref") in expected, (
            f"a queue into release-3.7 reads its config from {inputs.get('config-ref')!r}"
        )


# --------------------------------------------------------------------------- 6

RULES_CONFIG = (
    "project_name: base\n"
    "scanners:\n"
    "  semgrep:\n"
    "    options:\n"
    "      config: rules/semgrep.yaml\n"
    "  opengrep:\n"
    "    options:\n"
    "      config: ./rules/opengrep\n"
)
BASE_SEMGREP_RULES = "rules:\n  - id: base-semgrep-rule\n"
BASE_OPENGREP_A = "rules:\n  - id: base-opengrep-a\n"
BASE_OPENGREP_B = "rules:\n  - id: base-opengrep-b\n"
CHECKOUT_RULES = "rules: []  # the pull request's copy\n"


def _rule_option(config: Path, scanner: str) -> Any:
    from automated_security_helper.config.ash_config import load_yaml_config

    document = load_yaml_config(config.read_text(encoding="utf-8"))
    return document["scanners"][scanner]["options"]["config"]


class TestRuleFilesComeFromTheBaseCommit:
    """opengrep's and semgrep's `config` option names rules by a path in the checkout.

    The option takes a rules file, a directory of them, a URL or a registry name. A
    relative path resolves in the checkout, so it is read from config-ref like
    `config_file`; the other forms are not paths and are left alone.
    """

    def _repo(self, tmp_path, base_files):
        return Repository(
            tmp_path,
            base_files=base_files,
            checkout_files={
                "rules/semgrep.yaml": CHECKOUT_RULES,
                "rules/opengrep/a.yaml": CHECKOUT_RULES,
                "rules/opengrep/only-in-the-pull-request.yaml": CHECKOUT_RULES,
            },
        )

    def test_a_relative_rules_file_and_directory_come_from_the_base_commit(
        self, tmp_path
    ):
        repo = self._repo(
            tmp_path,
            {
                CONFIG_PATH: RULES_CONFIG,
                "rules/semgrep.yaml": BASE_SEMGREP_RULES,
                "rules/opengrep/a.yaml": BASE_OPENGREP_A,
                "rules/opengrep/sub/b.yml": BASE_OPENGREP_B,
            },
        )
        context = _pull_request(repo.base_sha, fork=False)
        config = _scan_config(repo, context, _required_inputs(context))

        semgrep = Path(_rule_option(config, "semgrep"))
        assert semgrep.is_absolute() and not repo.sandbox.is_inside_workspace(
            semgrep
        ), f"semgrep's rules come from {semgrep}, which resolves in the checkout"
        assert semgrep.read_text(encoding="utf-8") == BASE_SEMGREP_RULES

        opengrep = Path(_rule_option(config, "opengrep"))
        assert opengrep.is_absolute() and not repo.sandbox.is_inside_workspace(opengrep)
        # The step copies the rules under RUNNER_TEMP, which this test's sandbox puts
        # inside tmp_path. relative_to() fails the test if the copy is anywhere else,
        # and walking it as tmp_path / ... is a walk the repo-walk guard can see stays
        # in this test's own directory.
        rules_copy = tmp_path / opengrep.relative_to(tmp_path)
        files = {
            str(path.relative_to(rules_copy)): path.read_text(encoding="utf-8")
            for path in rules_copy.rglob("*")
            if path.is_file()
        }
        assert files == {"a.yaml": BASE_OPENGREP_A, "sub/b.yml": BASE_OPENGREP_B}, (
            f"the opengrep rules directory holds {sorted(files)}, not the base "
            "commit's two files"
        )

    @pytest.mark.parametrize(
        "value",
        [
            "p/ci",
            "auto",
            "r/python.lang.security.audit",
            "s/example",
            "policy",
            "supply-chain",
            "https://example.invalid/rules.yaml",
            "/opt/operator-rules",
        ],
    )
    def test_a_value_that_is_not_a_relative_path_is_left_alone(self, tmp_path, value):
        config_text = (
            "project_name: base\n"
            "scanners:\n"
            "  semgrep:\n"
            "    options:\n"
            f"      config: {value}\n"
            "  bandit:\n"
            "    options:\n"
            "      config_file: .ash/bandit.yaml\n"
        )
        repo = self._repo(
            tmp_path, {CONFIG_PATH: config_text, ".ash/bandit.yaml": BASE_BANDIT}
        )
        context = _pull_request(repo.base_sha, fork=False)
        config = _scan_config(repo, context, _required_inputs(context))
        assert _rule_option(config, "semgrep") == value

    def test_a_rules_path_missing_at_the_base_commit_is_refused(self, tmp_path):
        repo = self._repo(
            tmp_path,
            {CONFIG_PATH: RULES_CONFIG, "rules/opengrep/a.yaml": BASE_OPENGREP_A},
        )
        context = _pull_request(repo.base_sha, fork=False)
        run, steps = _run_config_ref_step(repo, context, _required_inputs(context))
        assert run is not None and run.proc.returncode != 0, run and run.describe()
        assert "::error::" in run.proc.stdout, run.describe()
        assert "scanners.semgrep.options.config" in run.proc.stdout, run.describe()
        assert steps.get("config-ref-files", {}).get("outcome") == "failure", steps

    def test_a_symlink_inside_a_rules_directory_is_refused(self, tmp_path):
        repo = self._repo(
            tmp_path,
            {
                CONFIG_PATH: RULES_CONFIG,
                "rules/semgrep.yaml": BASE_SEMGREP_RULES,
                "rules/opengrep/a.yaml": BASE_OPENGREP_A,
                "rules/opengrep/link.yaml": None,
            },
        )
        context = _pull_request(repo.base_sha, fork=False)
        run, _ = _run_config_ref_step(repo, context, _required_inputs(context))
        assert run is not None and run.proc.returncode != 0, run and run.describe()
        assert "not a regular file" in run.proc.stdout, run.describe()

    def test_a_rules_path_outside_the_repository_is_refused(self, tmp_path):
        config_text = RULES_CONFIG.replace("rules/semgrep.yaml", "../rules.yaml")
        repo = self._repo(
            tmp_path,
            {CONFIG_PATH: config_text, "rules/opengrep/a.yaml": BASE_OPENGREP_A},
        )
        context = _pull_request(repo.base_sha, fork=False)
        run, _ = _run_config_ref_step(repo, context, _required_inputs(context))
        assert run is not None and run.proc.returncode != 0, run and run.describe()
        assert "scanners.semgrep.options.config" in run.proc.stdout, run.describe()


# --------------------------------------------------------------------------- 7

CHECKOV_CONFIG_BASE = (
    "project_name: base\n"
    "scanners:\n"
    "  checkov:\n"
    "    options:\n"
    "      config_file: .ash/.checkov.yaml\n"
)


class TestFetchedToolConfigsLoadNoCodeFromTheCheckout:
    """A fetched tool config applies as the operator's file, but paths inside it do not move.

    ASH refuses an in-tree checkov config (config/path_trust.py); the copy config-ref
    fetches sits outside the tree, so it is applied. Paths inside it still resolve in
    checkov's working directory, the checkout. For a path that loads code, that would
    run the pull request's code in the required job: checkov's `external-checks-dir`
    loads Python checks, and a nested `config-file` brings its own. A relative value of
    either is refused; an absolute or home-relative one is the operator's.
    """

    def _run(self, tmp_path, checkov_config: str):
        repo = Repository(
            tmp_path,
            base_files={
                CONFIG_PATH: CHECKOV_CONFIG_BASE,
                ".ash/.checkov.yaml": checkov_config,
            },
            checkout_files={"checks/check.py": "# the pull request's check\n"},
        )
        context = _pull_request(repo.base_sha, fork=False)
        return _run_config_ref_step(repo, context, _required_inputs(context))

    @pytest.mark.parametrize(
        "checkov_config,key",
        [
            ("external-checks-dir: checks\n", "external-checks-dir"),
            (
                "external-checks-dir:\n  - /opt/checks\n  - ./checks\n",
                "external-checks-dir",
            ),
            ("external_checks_dir: checks\n", "external_checks_dir"),
            ("config-file: .ash/other-checkov.yaml\n", "config-file"),
        ],
    )
    def test_a_relative_code_loading_path_is_refused(
        self, tmp_path, checkov_config, key
    ):
        run, steps = self._run(tmp_path, checkov_config)
        assert run is not None, "no step reads the config from config-ref"
        assert run.proc.returncode != 0, (
            f"a fetched checkov config with a relative {key} was accepted:\n"
            + run.describe()
        )
        assert "::error::" in run.proc.stdout and key in run.proc.stdout, run.describe()
        assert steps.get("config-ref-files", {}).get("outcome") == "failure", steps

    @pytest.mark.parametrize(
        "checkov_config",
        [
            "external-checks-dir: /opt/operator-checks\n",
            "external-checks-dir:\n  - ~/operator-checks\n",
            "compact: true\nskip-check:\n  - CKV_AWS_1\n",
            "",
        ],
    )
    def test_an_operator_path_or_no_such_option_is_accepted(
        self, tmp_path, checkov_config
    ):
        run, steps = self._run(tmp_path, checkov_config)
        assert run is not None and run.proc.returncode == 0, run and run.describe()
        assert steps["config-ref-files"]["outcome"] == "success"

    def test_a_checkov_config_that_is_not_a_mapping_is_refused(self, tmp_path):
        """It cannot be checked for those options, so it is not passed on."""
        run, _ = self._run(tmp_path, "- external-checks-dir\n- checks\n")
        assert run is not None and run.proc.returncode != 0, run and run.describe()
        assert "::error::" in run.proc.stdout, run.describe()


# --------------------------------------------------------------------------- 8


class TestTheConfigComesFromTheCommitTheAshInstallIsPinnedTo:
    """In the merge queue, config-ref and ash-version both name refs/heads/main.

    The pin step resolves that name once, when the job starts; reading the config by
    name a moment later could read a newer commit than the ASH that scans with it.
    When config-ref names the same ref of the same repository as ash-version, the
    config-ref step reads the pinned commit.
    """

    def _pin(self, repo: Repository, context, inputs) -> dict[str, Any]:
        workflow, job = _job()
        (step,) = [s for s in job["steps"] if s.get("id") == "ash-pin"]
        run = ga.run_step(
            repo.sandbox,
            workflow,
            job,
            step,
            ga.with_inputs(context, inputs),
            extra_env=repo.ash_url_env(),
        )
        assert run.proc.returncode == 0, run.describe()
        return {"ash-pin": {"outputs": _outputs(repo.sandbox), "outcome": "success"}}

    def test_a_merge_after_the_pin_does_not_change_the_config(self, tmp_path):
        repo = Repository(tmp_path, base_files={CONFIG_PATH: BASE_CONFIG})
        context = _merge_group(PREVIOUS_ENTRY_SHA)
        inputs = _required_inputs(context)
        assert inputs["config-ref"] == inputs["ash-version"], inputs
        pinned = self._pin(repo, context, inputs)
        assert pinned["ash-pin"]["outputs"]["commit"] == repo.base_sha
        repo.advance(
            {CONFIG_PATH: "# merged after the job started\nproject_name: later\n"}
        )

        run, steps = _run_config_ref_step(repo, context, inputs, earlier=pinned)
        assert run is not None and run.proc.returncode == 0, run and run.describe()
        path = Path(steps["config-ref"]["outputs"]["path"])
        assert path.read_text(encoding="utf-8") == BASE_CONFIG, (
            "the config was read from a newer commit than the one ASH is pinned to"
        )
        assert steps["config-ref"]["outputs"]["commit"] == repo.base_sha

    def test_control_without_the_pin_the_name_reads_the_newer_commit(self, tmp_path):
        """Shows the race exists, so the test above can tell it from no race."""
        repo = Repository(tmp_path, base_files={CONFIG_PATH: BASE_CONFIG})
        context = _merge_group(PREVIOUS_ENTRY_SHA)
        inputs = _required_inputs(context)
        later = repo.advance({CONFIG_PATH: "project_name: later\n"})
        run, steps = _run_config_ref_step(repo, context, inputs)
        assert run is not None and run.proc.returncode == 0, run and run.describe()
        assert steps["config-ref"]["outputs"]["commit"] == later
