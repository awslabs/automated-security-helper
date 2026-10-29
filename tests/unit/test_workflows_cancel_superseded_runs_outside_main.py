# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every workflow cancels a superseded run, except on main and on tags.

Why this file exists
--------------------
A workflow run on a pull request or a branch is a report on one head. When a newer
push arrives on the same ref, the run on the old head answers a question nobody is
asking any more, and it holds a runner that the new head's run is waiting for. The
rule for this repository is therefore: a newer run on any ref other than main or a
tag cancels the one in progress, and a run on main or on a tag is never cancelled,
because it is the only report that commit will ever get.

Before this file, the workflows said that in several dialects: most cancelled only
``pull_request`` runs, two also cancelled pushes to non-main branches, and two
cancelled unconditionally. A dispatch run on a branch was never superseded, and a
dispatch on main could be. One expression now carries the rule everywhere, and this
test pins it so a new workflow, or an edit to an old one, cannot quietly fall back
to one of the dialects.

The workflows left alone are listed with their reasons, and the list is closed: a
workflow file this test does not know fails ``test_every_workflow_is_classified``,
so the author decides which set it belongs to rather than inheriting nothing.

Known limits
------------
This reads the expression as text; nothing here evaluates GitHub's expression
language. The text pinned is the one the workflows carry, so a reformulation with
the same meaning (``startsWith(github.ref, 'refs/tags/') == false``, say) reads as
a drift. That is the point: one spelling, so a reviewer can grep for it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

#: The one expression every superseding workflow carries. ``github.ref`` is
#: ``refs/pull/<n>/merge`` on pull_request, the branch on push and workflow_dispatch,
#: and the per-entry queue branch on merge_group; only main and tags are excluded.
CANCEL_OUTSIDE_MAIN_AND_TAGS = (
    "${{ github.ref != 'refs/heads/main' && !startsWith(github.ref, 'refs/tags/') }}"
)

#: Workflows whose in-progress run a newer run on the same ref supersedes.
SUPERSEDING = {
    "ash-actions-pinned.yml",
    "ash-agent-plugins-drift.yml",
    "ash-cdk-extra-drift.yml",
    "ash-docs-ci-runners.yml",
    "ash-iac-drift.yml",
    "ash-install-methods.yml",
    "ash-package.yml",
    "ash-pr-title-check.yml",
    "ash-repo-scan-pr-head.yml",
    "ash-repo-scan.yml",
    "ash-typescript-ci.yml",
    "ash-unified-ci.yml",
    "ash-upgrade-paths.yml",
    "ash-workflow-boolean-inputs.yml",
    "dependency-review.yml",
}

#: Reusable workflows: ``on: workflow_call`` only. The caller's concurrency block
#: governs the run, so a block here would be dead text.
REUSABLE = {"run-ash-security-scan.yml", "upload-ash-sarif.yml"}

#: Workflows that queue instead of cancelling, each with the reason its own comment
#: gives. Their cancel-in-progress is a literal false, never an expression.
QUEUEING = {
    # workflow_dispatch only; a release run must finish once started.
    "ash-create-release.yml": "create-release",
    # Weekly schedule plus dispatch; one run at a time, none superseded.
    "ash-pinned-tool-versions.yml": "${{ github.workflow }}",
    # The docs publish. Keyed on what it publishes (main, or the release tag given as
    # the `ref` input), never on the caller's ref, and never cancelled: the job only
    # publishes main or a release tag, so the rule above has nothing to cancel here.
    "ash-repo-docs.yml": (
        "docs-deploy-${{ inputs.ref && format('refs/tags/{0}', inputs.ref) || github.ref }}"
    ),
}

#: Fires on the pull_request `closed` event and writes the release tags. Its
#: concurrency lives on the job (group ash-release-tag, never cancelled), which
#: test_floating_major_tag_workflow.py pins; a workflow-level block would add a
#: second, ref-keyed group on top of it.
TAGGING = {"ash-tag-on-merge.yml"}


def _workflow_files() -> list[Path]:
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(workflow: dict) -> dict:
    # PyYAML reads the bare key ``on`` as the boolean True.
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict), (
        "every workflow here spells its triggers as a map"
    )
    return triggers


def test_the_workflow_directory_was_read():
    names = {path.name for path in _workflow_files()}
    assert names, f"no workflow files under {WORKFLOWS}"
    assert "ash-unified-ci.yml" in names


def test_every_workflow_is_classified():
    names = {path.name for path in _workflow_files()}
    classified = SUPERSEDING | REUSABLE | set(QUEUEING) | TAGGING
    assert names == classified, (
        f"unclassified: {sorted(names - classified)}; "
        f"listed but absent: {sorted(classified - names)}"
    )
    assert not (SUPERSEDING & REUSABLE), "a workflow belongs to one set"
    assert not (SUPERSEDING & set(QUEUEING)), "a workflow belongs to one set"
    assert not (SUPERSEDING & TAGGING), "a workflow belongs to one set"


@pytest.mark.parametrize("name", sorted(SUPERSEDING))
def test_a_superseding_workflow_cancels_outside_main_and_tags(name: str):
    workflow = _load(WORKFLOWS / name)
    concurrency = workflow.get("concurrency")
    assert isinstance(concurrency, dict), f"{name} has no workflow-level concurrency"
    assert concurrency.get("cancel-in-progress") == CANCEL_OUTSIDE_MAIN_AND_TAGS, (
        f"{name} cancel-in-progress is {concurrency.get('cancel-in-progress')!r}"
    )
    group = concurrency.get("group")
    assert isinstance(group, str) and "${{ github.ref }}" in group, (
        f"{name} group {group!r} is not keyed on the ref, so a run on one branch "
        "could cancel a run on another"
    )


@pytest.mark.parametrize("name", sorted(SUPERSEDING))
def test_a_superseding_workflow_never_runs_on_tags_unguarded(name: str):
    """Only tag-aware triggers reach the expression's tag clause.

    The clause is harmless where no tag can trigger the workflow, and necessary where
    one can. This reads which workflows the tag clause protects, so a trigger added
    later shows up here rather than in a cancelled release run.
    """
    triggers = _triggers(_load(WORKFLOWS / name))
    push = triggers.get("push")
    tag_triggered = isinstance(push, dict) and "tags" in push
    if name in {
        "ash-agent-plugins-drift.yml",
        "ash-cdk-extra-drift.yml",
        "ash-typescript-ci.yml",
    }:
        assert tag_triggered, f"{name} used to run on tag pushes; its trigger changed"
    else:
        assert not tag_triggered, f"{name} now runs on tag pushes; read its group key"


@pytest.mark.parametrize("name", sorted(REUSABLE))
def test_a_reusable_workflow_has_no_concurrency_of_its_own(name: str):
    workflow = _load(WORKFLOWS / name)
    assert set(_triggers(workflow)) == {"workflow_call"}, (
        f"{name} is no longer call-only"
    )
    assert "concurrency" not in workflow, (
        f"{name} declares a concurrency block; the caller's block governs a reusable "
        "workflow's run, so this one would be dead text"
    )


@pytest.mark.parametrize("name", sorted(QUEUEING))
def test_a_queueing_workflow_never_cancels(name: str):
    concurrency = _load(WORKFLOWS / name).get("concurrency")
    assert isinstance(concurrency, dict), f"{name} has no workflow-level concurrency"
    assert concurrency.get("group") == QUEUEING[name]
    assert concurrency.get("cancel-in-progress") is False, (
        f"{name} cancel-in-progress is {concurrency.get('cancel-in-progress')!r}; a "
        "release or publish run must finish once started"
    )


@pytest.mark.parametrize("name", sorted(TAGGING))
def test_the_tagging_workflow_keeps_its_job_level_queue(name: str):
    workflow = _load(WORKFLOWS / name)
    assert "concurrency" not in workflow, (
        f"{name} gained a workflow-level concurrency block on top of the job's "
        "ash-release-tag group; two groups on one release run is not the shape "
        "test_floating_major_tag_workflow.py pins"
    )
    jobs = workflow["jobs"]
    job_groups = {
        job_id: (job.get("concurrency") or {}).get("cancel-in-progress")
        for job_id, job in jobs.items()
    }
    assert job_groups == {"tag-and-release": False}, job_groups


def test_the_pinned_expression_names_both_protected_refs():
    """A control on the constant itself: both clauses are present and spelled as the
    workflows spell them, so a future edit to the constant cannot drop one silently."""
    assert "github.ref != 'refs/heads/main'" in CANCEL_OUTSIDE_MAIN_AND_TAGS
    assert "!startsWith(github.ref, 'refs/tags/')" in CANCEL_OUTSIDE_MAIN_AND_TAGS
    assert CANCEL_OUTSIDE_MAIN_AND_TAGS.startswith("${{ ")
    assert CANCEL_OUTSIDE_MAIN_AND_TAGS.endswith(" }}")


def test_a_planted_dialect_is_refused():
    """The old pull_request-only dialect must not equal the pinned expression, and a
    literal true must not either, or the superseding test above would pass a file
    that fell back to one of them."""
    assert "${{ github.event_name == 'pull_request' }}" != CANCEL_OUTSIDE_MAIN_AND_TAGS
    assert yaml.safe_load("cancel-in-progress: true")["cancel-in-progress"] is True
    assert (
        yaml.safe_load(f"cancel-in-progress: {CANCEL_OUTSIDE_MAIN_AND_TAGS}")[
            "cancel-in-progress"
        ]
        == CANCEL_OUTSIDE_MAIN_AND_TAGS
    ), "PyYAML must read the expression back as the same string the file carries"
