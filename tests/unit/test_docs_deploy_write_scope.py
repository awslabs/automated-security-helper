# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No tag push starts a job that can write to the repository; the docs deploy from main.

Why this file exists
--------------------
``deploy-docs`` in ``.github/workflows/ash-repo-docs.yml`` publishes the
documentation site with ``mkdocs gh-deploy --clean --force``, which needs
``contents: write``. The workflow's push trigger takes ``tags: ["*"]`` and the
job's ``if:`` admits a push to main or ``startsWith(github.ref, 'refs/tags/')``.
So pushing any tag at all, on any commit, runs the deploy job: it checks out that
commit, runs ``uv sync`` and mkdocs over it while holding a token that can write
to the repository, and publishes the site from it.

Release tags in this repository are ``v<major>.<minor>.<patch>``: the release
workflow creates ``TAG="v${VERSION}"`` (``ash-tag-on-merge.yml``). A tag of any
other shape is not a release and gets no write token.

What this asserts
-----------------
* A push of a tag that is not a release tag starts no job, in any workflow, that
  holds ``contents: write``. Every workflow is evaluated, so moving the deploy into
  a workflow of its own is covered the same way as narrowing this one.
* Controls, all passing before the fix: a push to main still runs the docs deploy
  job with ``contents: write``; a pull request and a push to a
  feature branch do not run it; inside any workflow that deploys the docs, the deploy
  job is the only one granted ``contents: write``.

Triggers and ``if:`` conditions are evaluated by ``tests/utils/github_actions.py``
(GitHub's filter-pattern rules and expression semantics), so the fix may narrow the
push trigger's ``tags:`` filter, the job's ``if:``, or both.

The docs deploy has no tag path at all. Release tags never needed one. ash-tag-on-merge.yml creates them
through the API with ``GITHUB_TOKEN``, which starts no workflow, and the release PR's
merge to main already publishes the site. A tag filter or a guard step would also
bind only commits that carry them, while a tag pushed on an older commit runs that
commit's workflow file. So no tag push of any shape (release, prerelease, the
floating ``v3``, anything else) starts a job holding ``contents: write``
(``TestNoTagPushDeploysTheDocs``, added with that change), and the deploy job's own
``if:`` admits only a push to main, so a tag trigger added back later still starts
no deploy. Tags pushed on commits from before this change are governed by a tag
ruleset, not by any workflow file (DEVELOPMENT.md, Releasing). The site is one
unversioned ``gh-deploy`` of gh-pages (no mike), so a prerelease deploy would have
replaced the released docs.

The control that a release tag push still deployed the docs now asserts the opposite
(``test_a_release_tag_push_deploys_nothing``).

What it does not cover
----------------------
A design that decides inside a gate job and
reads ``needs.<job>.outputs`` in the deploy job's ``if:`` is not modeled (outputs
are unknown here), so such a fix needs this file extended. Tags the release
workflow creates through the API with ``GITHUB_TOKEN`` do not start push workflows
at all, which is GitHub's behavior and not checked here.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.utils import github_actions as ga

REPO = "awslabs/automated-security-helper"

# Real or realistic tags that are not releases. `doctest-pre-rebase2-e85e438ba` is a
# tag that exists in this repository's history. `v3-docs-preview` starts with `v3`,
# so a filter that only checks for a leading `v` admits it.
NON_RELEASE_TAGS = [
    "docs-preview",
    "doctest-pre-rebase2-e85e438ba",
    "vanity",
    "v3-docs-preview",
]

RELEASE_TAGS = ["v3.8.0", "v3.10.12", "v4.0.0"]


def _push(ref: str) -> dict[str, Any]:
    name = ref.split("/", 2)[2]
    return ga.base_context(
        event_name="push",
        ref=ref,
        ref_name=name,
        ref_type="tag" if ref.startswith("refs/tags/") else "branch",
        repository=REPO,
        repository_owner=REPO.split("/")[0],
        event={"repository": {"default_branch": "main", "full_name": REPO}},
    )


def _pull_request() -> dict[str, Any]:
    return ga.base_context(
        event_name="pull_request",
        ref="refs/pull/812/merge",
        ref_name="812/merge",
        head_ref="feature-branch",
        base_ref="main",
        repository=REPO,
        repository_owner=REPO.split("/")[0],
        event={
            "repository": {"default_branch": "main", "full_name": REPO},
            "pull_request": {
                "head": {"ref": "feature-branch", "repo": {"full_name": REPO}},
                "base": {"ref": "main", "repo": {"full_name": REPO}},
            },
        },
    )


def _running_jobs(context: dict[str, Any]):
    """(workflow, job id, job) for every job the event starts."""
    for workflow in ga.all_workflows():
        if not ga.triggers(workflow, context):
            continue
        scoped = dict(context)
        scoped["needs"] = {
            job_id: {"result": "success", "outputs": {}} for job_id in workflow.jobs
        }
        for job_id, job in workflow.jobs.items():
            if ga.job_runs(job, scoped):
                yield workflow, job_id, job


def _can_write_contents(workflow: ga.Workflow, job: dict[str, Any]) -> bool:
    permissions = ga.job_permissions(workflow, job)
    # Nothing declared means the repository's default token, which may be write.
    return permissions is None or permissions.get("contents") == "write"


def _deploys_docs(job: dict[str, Any]) -> bool:
    runs = " ".join(str(step.get("run") or "") for step in job.get("steps") or [])
    return "gh-deploy" in runs or "mike deploy" in runs


def _docs_deploy_jobs():
    found = [
        (workflow, job_id, job)
        for workflow in ga.all_workflows()
        for job_id, job in workflow.jobs.items()
        if _deploys_docs(job)
    ]
    assert found, (
        "no job runs `mkdocs gh-deploy` or `mike deploy`; the docs deploy job was "
        "not found, so the controls below would compare nothing"
    )
    return found


class TestANonReleaseTagGetsNoWriteToken:
    @pytest.mark.parametrize("tag", NON_RELEASE_TAGS)
    def test_a_non_release_tag_push_starts_no_job_that_can_write_contents(self, tag):
        context = _push(f"refs/tags/{tag}")
        writers = [
            f"  {workflow.name}: job {job_id!r} permissions="
            f"{ga.job_permissions(workflow, job)}"
            for workflow, job_id, job in _running_jobs(context)
            if _can_write_contents(workflow, job)
        ]
        assert not writers, (
            f"pushing the tag {tag!r}, which is not a release tag, starts job(s) that "
            "hold contents: write:\n"
            + "\n".join(writers)
            + "\nNo tag push may start a job with a token that can write to the "
            "repository."
        )


class TestTheDocsStillDeploy:
    """Controls: the scoping must not stop the deploys that are meant to happen."""

    @pytest.mark.parametrize("tag", RELEASE_TAGS)
    def test_a_release_tag_push_deploys_nothing(self, tag):
        """Rewritten: release tags reach main first, and main's push deploys."""
        context = _push(f"refs/tags/{tag}")
        deploys = [
            f"{workflow.name}: {job_id}"
            for workflow, job_id, job in _running_jobs(context)
            if _deploys_docs(job) or _can_write_contents(workflow, job)
        ]
        assert not deploys, (
            f"pushing the release tag {tag!r} starts {deploys}; the docs deploy from "
            "the push to main that every release merge makes"
        )

    def test_a_push_to_main_runs_the_docs_deploy_with_contents_write(self):
        deploys = [
            (workflow, job_id, job)
            for workflow, job_id, job in _running_jobs(_push("refs/heads/main"))
            if _deploys_docs(job)
        ]
        assert deploys, "a push to main no longer deploys the docs"
        for workflow, job_id, job in deploys:
            assert (ga.job_permissions(workflow, job) or {}).get("contents") == "write"

    @pytest.mark.parametrize(
        "label,context",
        [
            pytest.param("pull request", _pull_request(), id="pull request"),
            pytest.param(
                "push to a feature branch",
                _push("refs/heads/feature-branch"),
                id="feature branch push",
            ),
        ],
    )
    def test_a_pull_request_or_feature_branch_push_does_not_deploy_the_docs(
        self, label, context
    ):
        deploys = [
            f"{workflow.name}: {job_id}"
            for workflow, job_id, job in _running_jobs(context)
            if _deploys_docs(job)
        ]
        assert not deploys, f"a {label} runs the docs deploy: {deploys}"

    def test_the_deploy_job_is_the_only_job_in_its_workflow_with_contents_write(self):
        for workflow, deploy_id, _ in _docs_deploy_jobs():
            workflow_level = ga.normalize_permissions(workflow.data.get("permissions"))
            assert workflow_level.get("contents") != "write", (
                f"{workflow.name} grants contents: write at workflow level, so every "
                "job in it holds it, not only the deploy job"
            )
            others = [
                job_id
                for job_id, job in workflow.jobs.items()
                if job_id != deploy_id and _can_write_contents(workflow, job)
            ]
            assert not others, (
                f"{workflow.name}: jobs other than {deploy_id!r} can write contents: "
                f"{others}"
            )


class TestPrereleaseAndFloatingTagsDoNotDeploy:
    @pytest.mark.parametrize(
        "tag", ["v3", "v4", "v3.0.0-beta-20250528", "v4.0.0rc1", "v3.8.0.post1"]
    )
    def test_the_tag_starts_no_job_that_can_write_contents(self, tag):
        context = _push(f"refs/tags/{tag}")
        writers = [
            f"  {workflow.name}: job {job_id!r}"
            for workflow, job_id, job in _running_jobs(context)
            if _can_write_contents(workflow, job)
        ]
        assert not writers, (
            f"pushing {tag!r} starts job(s) holding contents: write:\n"
            + "\n".join(writers)
        )


class TestNoTagPushDeploysTheDocs:
    @pytest.mark.parametrize(
        "tag",
        RELEASE_TAGS + NON_RELEASE_TAGS + ["v3", "v4.0.0rc1", "v3.0.0-beta-20250528"],
    )
    def test_no_tag_push_starts_a_job_that_can_write_contents(self, tag):
        context = _push(f"refs/tags/{tag}")
        writers = [
            f"  {workflow.name}: job {job_id!r}"
            for workflow, job_id, job in _running_jobs(context)
            if _can_write_contents(workflow, job)
        ]
        assert not writers, (
            f"pushing {tag!r} starts job(s) holding contents: write:\n"
            + "\n".join(writers)
        )

    @pytest.mark.parametrize("tag", RELEASE_TAGS + ["docs-preview"])
    def test_the_deploy_jobs_own_if_admits_no_tag(self, tag):
        """Even if a tag trigger comes back, the job that holds the token stays off."""
        context = _push(f"refs/tags/{tag}")
        scoped = dict(context)
        for workflow, job_id, job in _docs_deploy_jobs():
            scoped["needs"] = {
                j: {"result": "success", "outputs": {}} for j in workflow.jobs
            }
            assert not ga.job_runs(job, scoped), (
                f"{workflow.name}: {job_id!r} would run for a push of {tag!r} "
                "if the workflow were triggered by it"
            )
