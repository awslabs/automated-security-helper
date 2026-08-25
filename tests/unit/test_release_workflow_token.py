# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A release PR has to be able to trigger the checks that gate it.

Why this file exists
--------------------
GitHub deliberately does not start workflow runs for events authenticated with
``GITHUB_TOKEN``. The release workflow pushed the release branch and opened the
PR with that token, so the PR arrived with none of its required checks -- and the
required checks are what the branch ruleset waits for, so the PR could not merge
on its own.

This is not theoretical: it is why v3.6.0's release PR needed a manual push
before it would go green.

Two tokens, and the ordering matters
------------------------------------
``gh pr create`` reads ``GH_TOKEN``, but ``git push`` does not -- it uses the
credential ``actions/checkout`` persists. Fixing only ``GH_TOKEN`` leaves the
push authenticated as ``GITHUB_TOKEN``, and it is the push that the
``pull_request`` event hangs off. So the App token has to reach *checkout*, which
means minting it before the checkout step rather than next to the step that
creates the PR.

That ordering is the part a reasonable edit would get wrong, so it is asserted
directly.

Why a fallback
--------------
The App credentials are repository secrets that have to be created by hand. Until
they exist, ``steps.app-token.outputs.token`` is empty, and a workflow that
insisted on it would fail to release at all. A release that needs one manual
nudge is worse than the status quo; a release that cannot run is much worse. The
fallback keeps the workflow working before and after the App is set up.
"""

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-create-release.yml"

TOKEN_ACTION = "actions/create-github-app-token"


@pytest.fixture(scope="module")
def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def workflow(workflow_text):
    """Parsed workflow.

    Parsing matters on its own: GitHub rejects a malformed workflow by running
    zero jobs, with no annotation, which is a slow thing to notice.
    """
    return yaml.safe_load(workflow_text)


def _steps(workflow):
    jobs = workflow["jobs"]
    return jobs["create-release-pr"]["steps"]


def test_workflow_parses_and_has_the_release_job(workflow):
    assert "create-release-pr" in workflow["jobs"]
    assert _steps(workflow)


def test_an_app_token_is_minted(workflow_text):
    assert TOKEN_ACTION in workflow_text, (
        f"{TOKEN_ACTION} is not used, so the release PR is still created with "
        "GITHUB_TOKEN and will arrive with no checks."
    )


def test_the_token_action_is_pinned_to_a_major_version(workflow_text):
    """An unpinned action is a supply-chain risk in a release path."""
    assert f"{TOKEN_ACTION}@" in workflow_text, (
        f"{TOKEN_ACTION} is referenced without a version."
    )
    unpinned = f"{TOKEN_ACTION}@main"
    assert unpinned not in workflow_text, (
        "The token action is pinned to a moving branch in the workflow that cuts "
        "releases."
    )


def test_the_token_is_minted_before_checkout(workflow):
    """The push is what needs the App identity, and checkout supplies it.

    Minting after checkout would still fix `gh pr create` while leaving the push
    on GITHUB_TOKEN, so the PR would keep arriving without checks -- the same bug
    with more YAML.
    """
    steps = _steps(workflow)
    token_index = next(
        (i for i, s in enumerate(steps) if TOKEN_ACTION in str(s.get("uses", ""))),
        None,
    )
    checkout_index = next(
        (
            i
            for i, s in enumerate(steps)
            if "actions/checkout" in str(s.get("uses", ""))
        ),
        None,
    )

    assert token_index is not None, "No step mints an App token"
    assert checkout_index is not None, "No checkout step"
    assert token_index < checkout_index, (
        f"The App token is minted at step {token_index} but checkout is step "
        f"{checkout_index}. Checkout persists the credential that `git push` "
        "uses, so it has to receive the App token."
    )


def test_checkout_receives_a_token(workflow):
    steps = _steps(workflow)
    checkout = next(s for s in steps if "actions/checkout" in str(s.get("uses", "")))

    token = str((checkout.get("with") or {}).get("token", ""))
    assert token, (
        "actions/checkout has no `token`, so it persists GITHUB_TOKEN and the "
        "release branch push cannot trigger workflows."
    )
    assert "app-token" in token, (
        f"checkout's token does not come from the App token step: {token!r}"
    )


def test_the_pr_creation_step_prefers_the_app_token(workflow):
    steps = _steps(workflow)
    pr_steps = [s for s in steps if "gh pr create" in str(s.get("run", ""))]

    assert pr_steps, "No step runs `gh pr create`"
    for step in pr_steps:
        gh_token = str((step.get("env") or {}).get("GH_TOKEN", ""))
        assert "app-token" in gh_token, (
            f"`gh pr create` runs with {gh_token!r} rather than the App token, so "
            "the PR is attributed to GITHUB_TOKEN."
        )


@pytest.mark.parametrize("consumer", ["token", "GH_TOKEN"])
def test_there_is_a_fallback_to_github_token(workflow_text, consumer):
    """Releases must still work before the App secrets exist.

    Asserted as a `||` fallback rather than by naming a step, so the expression
    stays readable if the step names change.
    """
    assert "|| secrets.GITHUB_TOKEN" in workflow_text, (
        "There is no fallback to GITHUB_TOKEN. Until the App secrets are "
        "created, the release workflow would fail outright instead of falling "
        "back to today's behaviour."
    )
