# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The required ASH check scans a pull request with the base branch's ASH.

Why this file exists
--------------------
``ash / SAST, SCA, and IaC Scan`` is a required check (DEVELOPMENT.md lists it with
``Validate PR title`` and ``required-checks``). It is the ``ash`` job of
``.github/workflows/ash-repo-scan.yml`` calling the reusable
``run-ash-security-scan.yml``, whose job is named ``SAST, SCA, and IaC Scan``.

On ``pull_request`` the caller passed ``ash-version: github.head_ref`` and
``ash-repo: github.event.pull_request.head.repo.full_name``, so the check installed
ASH from the pull request's own branch. A pull request that changes how ASH scans
(a scanner that stops reporting, a parser that drops results, a gate that exits 0)
was then judged by the ASH it ships. Now the required check installs ASH from the BASE branch on ``pull_request``, a separate job that nothing
requires runs the pull request's own ASH for information, and ``merge_group`` keeps
installing from the default branch (the queue branch is deleted mid-run, see the
comment in the caller).

What this asserts
-----------------
1. For a same-repository pull request, a fork pull request, and a pull request into a
   branch other than the default, every URL the required check installs ASH or its
   assets from names the base repository at the base branch (by name or by the base
   commit), never the head. Discovered by rendering every ``env:``, ``with:`` and
   ``run:`` value of the called workflow, so ``ASH_UVX_SOURCE`` and the cfn-nag
   ``ASH_ASSETS_URL`` are both covered, and so is any new one.
2. Control: on ``merge_group`` it installs from the default branch. Passes before the fix.
3. A job runs the pull request's own ASH; its check name is not a required check, says
   it does not gate, and it reports nothing to the pull request (no PR comment, no JUnit
   check run, no SARIF upload) that could be taken for the required check's result.
4. Guards that pass before the fix and keep the new job from breaking the required one:
   every caller grants the permissions the reusable workflow declares (GitHub refuses
   the whole run at startup otherwise), and scans in one workflow run do not upload the
   same artifact name (upload-artifact refuses the second, failing that job).
5. cfn-nag is installed from the Gemfile of the ASH ref being installed. The step used
   ``${GITHUB_WORKSPACE}/automated_security_helper/assets/Gemfile`` whenever the
   checkout had one, which is always the case when ASH scans itself: the pull request's
   Gemfile, not the base's. Run with stubbed ``curl``/``bundle``/``gem``/``ruby``.

Repository conventions for the informational job
------------------------------------------------
Work that must not gate is marked here with ``continue-on-error: true`` plus a name
saying it does not gate (the ``ty`` step in ash-unified-ci.yml). A job that calls a
reusable workflow cannot take ``continue-on-error`` (Actions does not allow it on a
``uses:`` job), so for this job the convention reduces to: not a required check, and a
check name that says it is informational.

What it does not cover
----------------------
* On ``pull_request`` Actions runs the workflow files from the pull request's merge
  commit, so a pull request that edits ``ash-repo-scan.yml`` or
  ``run-ash-security-scan.yml`` (called as ``./``) still changes its own gate. Review of
  workflow changes is the control for that; nothing in a workflow file can enforce it.
* Which config the required check scans with. It reads the base branch's; tests/unit/test_required_scan_reads_the_base_branchs_config.py
  asserts that.
* The informational job is recognized by its install URL naming the head ref, head
  commit or merge ref. A design that installs the pull request's ASH another way (for
  example ``uvx --from .``) needs the locator in ``_pr_code_scans`` extended.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.utils import github_actions as ga

# The cfn-nag tests run the step's bash. Same idiom and reasons as
# tests/unit/test_floating_major_tag_workflow.py: on a Windows runner `bash` is the WSL
# launcher stub, and the step only ever runs on ubuntu-latest.
_REQUIRES_BASH = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="the step under test is a bash step that runs on ubuntu-latest",
)

REQUIRED_SCAN_CHECK = "ash / SAST, SCA, and IaC Scan"
SCAN_WORKFLOW = ga.WORKFLOWS_DIR / "run-ash-security-scan.yml"
UPLOAD_SARIF_WORKFLOW = "./.github/workflows/upload-ash-sarif.yml"
DEVELOPMENT_MD = ga.REPO_ROOT / "DEVELOPMENT.md"

BASE_REPO = "awslabs/automated-security-helper"
FORK_REPO = "contributor/automated-security-helper"
DEFAULT_BRANCH = "main"
HEAD_REF = "feature-branch"
PR_NUMBER = 812
BASE_SHA = "1111111111111111111111111111111111111111"
HEAD_SHA = "2222222222222222222222222222222222222222"
MERGE_SHA = "3333333333333333333333333333333333333333"

_GIT_SOURCE = re.compile(
    r"git\+https://github\.com/(?P<repo>[^/@\s\"']+/[^/@\s\"']+?)(?:\.git)?@(?P<ref>[^\s#\"']+)"
)
_RAW_SOURCE = re.compile(
    r"https://raw\.githubusercontent\.com/(?P<repo>[^/\s\"']+/[^/\s\"']+)/"
    r"(?P<ref>\S+?)/automated_security_helper(?:/|\b)"
)


def _pull_request(*, fork: bool, base_ref: str = DEFAULT_BRANCH) -> dict[str, Any]:
    head_repo = FORK_REPO if fork else BASE_REPO
    return ga.base_context(
        event_name="pull_request",
        repository=BASE_REPO,
        repository_owner=BASE_REPO.split("/")[0],
        ref=f"refs/pull/{PR_NUMBER}/merge",
        ref_name=f"{PR_NUMBER}/merge",
        sha=MERGE_SHA,
        head_ref=HEAD_REF,
        base_ref=base_ref,
        event={
            "repository": {"default_branch": DEFAULT_BRANCH, "full_name": BASE_REPO},
            "pull_request": {
                "number": PR_NUMBER,
                "head": {
                    "ref": HEAD_REF,
                    "sha": HEAD_SHA,
                    "repo": {"full_name": head_repo},
                },
                "base": {
                    "ref": base_ref,
                    "sha": BASE_SHA,
                    "repo": {"full_name": BASE_REPO},
                },
            },
        },
    )


def _merge_group() -> dict[str, Any]:
    queue = f"gh-readonly-queue/{DEFAULT_BRANCH}/pr-{PR_NUMBER}-{MERGE_SHA}"
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
                "base_ref": f"refs/heads/{DEFAULT_BRANCH}",
                "base_sha": BASE_SHA,
                "head_ref": f"refs/heads/{queue}",
                "head_sha": MERGE_SHA,
            },
        },
    )


PULL_REQUESTS = [
    pytest.param(_pull_request(fork=False), id="same-repository pull request"),
    pytest.param(_pull_request(fork=True), id="fork pull request"),
    pytest.param(
        _pull_request(fork=False, base_ref="release-3.7"),
        id="pull request into a non-default branch",
    ),
]


@dataclass
class ScanJob:
    """One job, in a run the event starts, that calls run-ash-security-scan.yml."""

    workflow: ga.Workflow
    job_id: str
    job: dict[str, Any]
    check_names: list[str]
    inputs: dict[str, Any]
    sources: list[tuple[str, str, str, str]]  # (where, "git" or "raw", repo, ref)

    def label(self) -> str:
        return f"{self.workflow.name}: {self.job_id} ({', '.join(self.check_names)})"


def _rendered_values(called: ga.Workflow, context: dict[str, Any]):
    """(where, rendered string) for every env, with and run value of the called workflow."""
    workflow_env = ga.render_env(called.data.get("env"), {**context, "env": {}})
    for key, value in workflow_env.items():
        yield f"env.{key}", value
    for called_id, called_job in called.jobs.items():
        scoped = {**context, "env": workflow_env}
        job_env = ga.render_env(called_job.get("env"), scoped)
        for key, value in job_env.items():
            yield f"jobs.{called_id}.env.{key}", value
        scoped = {**context, "env": {**workflow_env, **job_env}}
        for step in called_job.get("steps") or []:
            name = step.get("name") or step.get("uses") or "?"
            for key, value in ga.render_env(step.get("env"), scoped).items():
                yield f"step {name!r} env.{key}", value
            for key, value in (step.get("with") or {}).items():
                yield (
                    f"step {name!r} with.{key}",
                    ga.to_string(ga.render(value, scoped)),
                )
            if "run" in step:
                yield f"step {name!r} run", ga.to_string(ga.render(step["run"], scoped))


def _sources(
    called: ga.Workflow, context: dict[str, Any]
) -> list[tuple[str, str, str, str]]:
    found = []
    for where, value in _rendered_values(called, context):
        for kind, pattern in (("git", _GIT_SOURCE), ("raw", _RAW_SOURCE)):
            for match in pattern.finditer(value):
                found.append((where, kind, match.group("repo"), match.group("ref")))
    return found


def _scan_jobs(context: dict[str, Any]) -> list[ScanJob]:
    jobs = []
    for workflow in ga.all_workflows():
        if not ga.triggers(workflow, context):
            continue
        scoped = dict(context)
        scoped["needs"] = {
            job_id: {"result": "success", "outputs": {}} for job_id in workflow.jobs
        }
        for job_id, job in workflow.jobs.items():
            called = ga.local_reusable_workflow(job)
            if called is None or called.path.resolve() != SCAN_WORKFLOW.resolve():
                continue
            if not ga.job_runs(job, scoped):
                continue
            inputs = ga.call_inputs(job, called, scoped)
            jobs.append(
                ScanJob(
                    workflow=workflow,
                    job_id=job_id,
                    job=job,
                    check_names=ga.check_names(job_id, job),
                    inputs=inputs,
                    sources=_sources(called, ga.with_inputs(scoped, inputs)),
                )
            )
    return jobs


def _required_scan(context: dict[str, Any]) -> ScanJob:
    matches = [s for s in _scan_jobs(context) if REQUIRED_SCAN_CHECK in s.check_names]
    assert len(matches) == 1, (
        f"expected exactly one job producing the required check {REQUIRED_SCAN_CHECK!r} "
        f"for this event, found {[m.label() for m in matches]}. Branch protection "
        "requires that exact name, so it must keep resolving to one job."
    )
    return matches[0]


def _base_refs(context: dict[str, Any]) -> set[str]:
    pull_request = context["github"]["event"]["pull_request"]
    base = pull_request["base"]["ref"]
    return {base, f"refs/heads/{base}", pull_request["base"]["sha"]}


def _names_pr_code(repo: str, ref: str, context: dict[str, Any]) -> bool:
    pull_request = context["github"]["event"]["pull_request"]
    head_repo = pull_request["head"]["repo"]["full_name"].lower()
    if repo.lower() == head_repo and ref in {
        pull_request["head"]["ref"],
        f"refs/heads/{pull_request['head']['ref']}",
        pull_request["head"]["sha"],
    }:
        return True
    # GitHub serves a pull request's commits from the base repository too (the
    # refs/pull/<n>/ refs), so the base repository at the head or merge commit is
    # also the pull request's own code.
    return repo.lower() == BASE_REPO.lower() and ref in {
        pull_request["head"]["sha"],
        MERGE_SHA,
        f"refs/pull/{PR_NUMBER}/merge",
        f"refs/pull/{PR_NUMBER}/head",
    }


def _pr_code_scans(context: dict[str, Any]) -> list[ScanJob]:
    """Scan jobs other than the required one that install the pull request's own ASH.

    The required job is excluded by name: before the fix it is the one installing
    the head, and counting it here would let the informational-job tests pass on
    the old install shape.
    """
    return [
        scan
        for scan in _scan_jobs(context)
        if REQUIRED_SCAN_CHECK not in scan.check_names
        and any(
            kind == "git" and _names_pr_code(repo, ref, context)
            for _, kind, repo, ref in scan.sources
        )
    ]


def _required_checks_from_development_md() -> list[str]:
    text = DEVELOPMENT_MD.read_text(encoding="utf-8")
    match = re.search(r"required checks \(([^)]*)\)", text)
    assert match, (
        "DEVELOPMENT.md no longer lists the release PR's required checks in the "
        "'required checks (...)' sentence this test reads"
    )
    names = re.findall(r"`([^`]+)`", match.group(1))
    assert REQUIRED_SCAN_CHECK in names, names
    return names


# --------------------------------------------------------------------------- 1 and 2


class TestTheRequiredCheckInstallsTheBaseBranchsAsh:
    @pytest.mark.parametrize("context", PULL_REQUESTS)
    def test_every_ash_source_of_the_required_check_names_the_base_branch(
        self, context
    ):
        scan = _required_scan(context)
        assert any(kind == "git" for _, kind, _, _ in scan.sources), (
            "no `git+https://github.com/...@ref` install source was found in the called "
            "workflow, so this test compared nothing"
        )
        base_refs = _base_refs(context)
        wrong = [
            f"  {where}: {repo}@{ref}"
            for where, _, repo, ref in scan.sources
            if repo.lower() != BASE_REPO.lower() or ref not in base_refs
        ]
        assert not wrong, (
            f"on this pull request the required check {REQUIRED_SCAN_CHECK!r} installs "
            "ASH (or its assets) from somewhere other than the base branch "
            f"{BASE_REPO}@{sorted(base_refs)}:\n" + "\n".join(wrong) + "\n"
            "A pull request must not be judged by the ASH it changes. Install from the "
            "base branch (github.base_ref or github.event.pull_request.base.sha) of "
            "github.repository."
        )

    def test_the_required_check_installs_from_the_default_branch_in_the_merge_queue(
        self,
    ):
        """Control: merge_group keeps the default branch, as the caller's comment explains."""
        scan = _required_scan(_merge_group())
        assert any(kind == "git" for _, kind, _, _ in scan.sources), (
            "no ASH install source was found in the called workflow"
        )
        wrong = [
            f"  {where}: {repo}@{ref}"
            for where, _, repo, ref in scan.sources
            if repo.lower() != BASE_REPO.lower()
            or ref not in {DEFAULT_BRANCH, f"refs/heads/{DEFAULT_BRANCH}"}
        ]
        assert not wrong, (
            "in the merge queue the required check must install from the default "
            "branch:\n" + "\n".join(wrong)
        )

    def test_the_locator_finds_both_kinds_of_ash_source(self):
        """Control on the locator: the uvx source and the cfn-nag assets URL are both seen."""
        scan = _required_scan(_merge_group())
        kinds = {kind for _, kind, _, _ in scan.sources}
        assert kinds == {"git", "raw"}, scan.sources


# --------------------------------------------------------------------------- 3


class TestThePullRequestsOwnAshRunsForInformationOnly:
    @pytest.mark.parametrize("context", PULL_REQUESTS[:2])
    def test_a_separate_job_scans_with_the_pull_requests_own_ash(self, context):
        scans = _pr_code_scans(context)
        assert scans, (
            "no job installs the pull request's own ASH. The required check now "
            "installs from the base branch, so add a separate job that runs the pull "
            "request's ASH for information (and that no ruleset requires)."
        )

    @pytest.mark.parametrize("context", PULL_REQUESTS[:2])
    def test_the_pull_requests_own_ash_runs_under_no_required_check_name(self, context):
        required = set(_required_checks_from_development_md())
        scans = _pr_code_scans(context)
        assert scans, "no job installs the pull request's own ASH"
        for scan in scans:
            clash = sorted(required.intersection(scan.check_names))
            assert not clash, (
                f"{scan.label()} runs the pull request's own ASH under the required "
                f"check name(s) {clash}"
            )
            gate = scan.workflow.jobs.get("required-checks") or {}
            needs = gate.get("needs") or []
            needs = [needs] if isinstance(needs, str) else list(needs)
            assert scan.job_id not in needs, (
                f"{scan.label()} is in the required-checks gate's needs, so it gates"
            )

    @pytest.mark.parametrize("context", PULL_REQUESTS[:2])
    def test_the_pull_requests_own_ash_says_in_its_check_name_that_it_does_not_gate(
        self, context
    ):
        scans = _pr_code_scans(context)
        assert scans, "no job installs the pull request's own ASH"
        for scan in scans:
            for name in scan.check_names:
                assert "informational" in name.lower(), (
                    f"check {name!r} runs the pull request's own ASH but its name does "
                    "not say it is informational; a green or red tick on it must not be "
                    "read as the required scan's verdict"
                )

    @pytest.mark.parametrize("context", PULL_REQUESTS[:2])
    def test_only_the_base_branch_scan_reports_to_the_pull_request(self, context):
        scans = _pr_code_scans(context)
        assert scans, "no job installs the pull request's own ASH"
        for scan in scans:
            reporting = [
                name
                for name in (
                    "post-pr-comment",
                    "collect-junit-xml-report",
                    "collect-sarif-report",
                )
                if ga.truthy(scan.inputs.get(name))
            ]
            assert not reporting, (
                f"{scan.label()} runs the pull request's own ASH and still has "
                f"{reporting} on. The PR comment is one comment that the last writer "
                "replaces, the JUnit check run reuses one name, and SARIF lands in code "
                "scanning under the same category, so each would show the "
                "pull request's own verdict where the required scan's belongs."
            )
        required = _required_scan(context)
        for workflow in {scan.workflow.path: scan.workflow for scan in scans}.values():
            for job_id, job in workflow.jobs.items():
                if job.get("uses") != UPLOAD_SARIF_WORKFLOW:
                    continue
                needs = job.get("needs") or []
                needs = [needs] if isinstance(needs, str) else list(needs)
                assert workflow.path == required.workflow.path and needs == [
                    required.job_id
                ], (
                    f"{workflow.name}: {job_id!r} uploads SARIF after {needs}; in a run "
                    "that also scans with the pull request's own ASH, only the required "
                    f"scan {required.job_id!r} may feed code scanning"
                )


# --------------------------------------------------------------------------- 4


class TestAnotherScanCannotBreakTheRequiredOne:
    """Guards. Both pass before the fix; they stop the new job from breaking the gate."""

    def test_every_caller_of_the_scan_workflow_grants_the_permissions_it_declares(self):
        called = ga.load_workflow(SCAN_WORKFLOW)
        declared = ga.normalize_permissions(called.data.get("permissions"))
        assert declared, "run-ash-security-scan.yml declares no permissions"
        rank = {"none": 0, "read": 1, "write": 2}
        callers = 0
        short = []
        for workflow in ga.all_workflows():
            for job_id, job in workflow.jobs.items():
                target = ga.local_reusable_workflow(job)
                if target is None or target.path.resolve() != SCAN_WORKFLOW.resolve():
                    continue
                callers += 1
                granted = ga.job_permissions(workflow, job) or {}
                for scope, level in declared.items():
                    if rank.get(granted.get(scope, "none"), 0) < rank[level]:
                        short.append(
                            f"  {workflow.name}: {job_id!r} grants {scope}: "
                            f"{granted.get(scope, 'none')}, the workflow declares {level}"
                        )
        assert callers, "no job calls run-ash-security-scan.yml"
        assert not short, (
            "GitHub checks a called workflow's declared permissions against the caller "
            "when the run starts and refuses the WHOLE run if one is missing, so the "
            "required check would never start:\n" + "\n".join(short)
        )

    @pytest.mark.parametrize("context", PULL_REQUESTS[:2])
    def test_scans_in_one_run_upload_distinct_artifact_names(self, context):
        called = ga.load_workflow(SCAN_WORKFLOW)
        by_run: dict[Path, list[tuple[str, str]]] = {}
        for scan in _scan_jobs(context):
            ctx = ga.with_inputs(context, scan.inputs)
            for called_job in called.jobs.values():
                for step in called_job.get("steps") or []:
                    if not str(step.get("uses", "")).startswith(
                        "actions/upload-artifact@"
                    ):
                        continue
                    name = ga.to_string(
                        ga.render((step.get("with") or {}).get("name"), ctx)
                    )
                    by_run.setdefault(scan.workflow.path, []).append(
                        (scan.job_id, name)
                    )
        assert by_run, "no scan job uploads an artifact; this guard compared nothing"
        for path, uploads in by_run.items():
            names = [name for _, name in uploads]
            assert len(names) == len(set(names)), (
                f"{path.name}: scan jobs in one run upload the same artifact name: "
                f"{uploads}. upload-artifact refuses a second artifact with a name the "
                "run already has, which fails whichever job uploads second."
            )


# --------------------------------------------------------------------------- 5

GEMFILE_FROM_CHECKOUT = "# the Gemfile in the checkout\n"


def _cfn_nag_step(called: ga.Workflow) -> tuple[dict[str, Any], dict[str, Any]]:
    found = [
        (job, step)
        for job in called.jobs.values()
        for step in job.get("steps") or []
        if "bundle" in str(step.get("run") or "")
        and "Gemfile" in str(step.get("run") or "")
    ]
    assert len(found) == 1, (
        f"expected one step that bundle-installs cfn-nag from a Gemfile, found {len(found)}"
    )
    return found[0]


def _run_cfn_nag_install(
    tmp_path: Path, *, checkout_has_gemfile: bool
) -> tuple[ga.StepSandbox, ga.StepRun]:
    context = _pull_request(fork=False)
    required = _required_scan(context)
    called = ga.load_workflow(SCAN_WORKFLOW)
    job, step = _cfn_nag_step(called)
    sandbox = ga.StepSandbox(tmp_path)
    if checkout_has_gemfile:
        gemfile = sandbox.workspace / "automated_security_helper" / "assets" / "Gemfile"
        gemfile.parent.mkdir(parents=True)
        gemfile.write_text(GEMFILE_FROM_CHECKOUT, encoding="utf-8")
        (gemfile.parent / "Gemfile.lock").write_text("# lock\n", encoding="utf-8")
    run = ga.run_step(
        sandbox, called, job, step, ga.with_inputs(context, required.inputs)
    )
    return sandbox, run


@_REQUIRES_BASH
class TestCfnNagComesFromTheInstalledAshRef:
    def test_cfn_nag_is_not_installed_from_the_checkouts_gemfile(self, tmp_path):
        sandbox, run = _run_cfn_nag_install(tmp_path, checkout_has_gemfile=True)
        installs = [c for c in run.calls_to("bundle") if c["argv"][:1] == ["install"]]
        assert installs, "the step never ran `bundle install`:\n" + run.describe()
        for call in installs:
            path = call.get("gemfile_realpath") or ""
            assert path and not sandbox.is_inside_workspace(path), (
                f"cfn-nag was bundle-installed from {path}, the Gemfile in the checkout. "
                "When ASH scans itself that is the pull request's Gemfile, so the pull "
                "request picks the cfn-nag the required check runs. Install from the "
                "Gemfile of the ASH ref being installed (ASH_ASSETS_URL).\n"
                + run.describe()
            )
            assert call.get("gemfile_content") != GEMFILE_FROM_CHECKOUT

    def test_cfn_nag_gemfile_is_fetched_when_the_checkout_has_none(self, tmp_path):
        """Control: an external caller's checkout has no Gemfile; the step fetches it."""
        _, run = _run_cfn_nag_install(tmp_path, checkout_has_gemfile=False)
        assert run.proc.returncode == 0, run.describe()
        fetched = [c["url"] for c in run.calls_to("curl")]
        assert any(url.endswith("/Gemfile") for url in fetched), run.describe()
        installs = [c for c in run.calls_to("bundle") if c["argv"][:1] == ["install"]]
        assert installs and all(
            str(c.get("gemfile_content", "")).startswith("# fetched from ")
            for c in installs
        ), run.describe()
