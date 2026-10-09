# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every actions/checkout drops its credentials, except a frozen set inherited from main.

Why this exists
---------------
actions/checkout writes the job's token into the clone's .git/config unless
``persist-credentials: false`` is set, so any later step that uploads the workspace,
or any code a step runs, can read it. zizmor reports this as ``artipacked``. main
fixed the other zizmor classes in #764 and left 38 checkouts that still persist the
token; every checkout v4 added sets ``persist-credentials: false``, and none of
those jobs uses the checkout's git credentials afterwards (the one that calls ``gh``
passes GH_TOKEN to that step explicitly).

MAIN_BASELINE lists the 38 by file, job and position in the job. It may only
shrink: a checkout on it that now drops its credentials fails here until its entry
is removed, and a new checkout that keeps them fails unless it is justified by
editing this list in review.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from tests.utils.helpers import github_yaml_files

REPO = Path(__file__).resolve().parents[2]

# (file, job, n): the n-th checkout in that job; job "" is a composite action's steps.
MAIN_BASELINE: set[tuple[str, str, int]] = {
    (".github/workflows/ash-actions-pinned.yml", "actions-pinned", 1),
    (".github/workflows/ash-agent-plugins-drift.yml", "drift-and-validate", 1),
    (".github/workflows/ash-cdk-extra-drift.yml", "cdk-extra-matches-pyproject", 1),
    (".github/workflows/ash-create-release.yml", "create-release-pr", 1),
    (".github/workflows/ash-iac-drift.yml", "discover", 1),
    (".github/workflows/ash-iac-drift.yml", "cdk-template-drift", 1),
    (".github/workflows/ash-iac-drift.yml", "generated-buildspec-drift", 1),
    (".github/workflows/ash-iac-drift.yml", "terraform-hygiene", 1),
    (".github/workflows/ash-iac-drift.yml", "cdk-nag", 1),
    (".github/workflows/ash-install-methods.yml", "validate", 1),
    (".github/workflows/ash-package.yml", "build", 1),
    (".github/workflows/ash-pr-title-check.yml", "pr-title", 1),
    (".github/workflows/ash-repo-docs.yml", "build-docs", 1),
    (".github/workflows/ash-repo-docs.yml", "deploy-docs", 1),
    (".github/workflows/ash-repo-scan.yml", "grype-db-cache", 1),
    (".github/workflows/ash-repo-scan.yml", "opengrep-cache", 1),
    (".github/workflows/ash-tag-on-merge.yml", "tag-and-release", 1),
    (".github/workflows/ash-typescript-ci.yml", "typescript-tests", 1),
    (".github/workflows/ash-typescript-ci.yml", "coverage-completeness-outside", 1),
    (".github/workflows/ash-unified-ci.yml", "lint", 1),
    (".github/workflows/ash-unified-ci.yml", "actionlint", 1),
    (".github/workflows/ash-unified-ci.yml", "snapshot-trailers", 1),
    (".github/workflows/ash-unified-ci.yml", "unit-test", 1),
    (".github/workflows/ash-unified-ci.yml", "warm-image-layers", 1),
    (".github/workflows/ash-unified-ci.yml", "scan-validation", 1),
    (".github/workflows/ash-unified-ci.yml", "external-target-scan", 1),
    (".github/workflows/ash-unified-ci.yml", "multi-project-attribution", 1),
    (".github/workflows/ash-unified-ci.yml", "deploy-aws-helpers", 1),
    (".github/workflows/ash-unified-ci.yml", "integration-test", 1),
    (".github/workflows/ash-unified-ci.yml", "install-validation", 1),
    (".github/workflows/ash-unified-ci.yml", "required-checks", 1),
    (".github/workflows/ash-upgrade-paths.yml", "upgrade-path", 1),
    (".github/workflows/ash-workflow-boolean-inputs.yml", "workflow-boolean-inputs", 1),
    (".github/workflows/dependency-review.yml", "dependency-review", 1),
    (".github/workflows/run-ash-security-scan.yml", "ash", 1),
    ("ash-agent-plugins/.github/workflows/validate.yml", "drift-and-validate", 1),
    ("ash-agent-plugins/.github/workflows/validate.yml", "matrix-config", 1),
    ("ash-agent-plugins/.github/workflows/validate.yml", "smoke-test", 1),
}
FROZEN_SIZE = 38


def _files() -> list[Path]:
    # The listed .github roots only. A `**` glob from the repository root descends
    # into tests/pytest-temp, which other xdist workers create and delete under it.
    return github_yaml_files(REPO)


def checkouts() -> list[tuple[tuple[str, str, int], bool]]:
    """Every actions/checkout step, and whether it sets persist-credentials: false."""
    out = []
    for path in _files():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        rel = path.relative_to(REPO).as_posix()
        lists = [
            (name, (job or {}).get("steps") or [])
            for name, job in (data.get("jobs") or {}).items()
        ]
        lists.append(("", (data.get("runs") or {}).get("steps") or []))
        for job, steps in lists:
            n = 0
            for step in steps:
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    n += 1
                    value = (step.get("with") or {}).get("persist-credentials")
                    out.append(((rel, job, n), str(value).lower() == "false"))
    return out


def test_every_checkout_outside_the_baseline_drops_its_credentials() -> None:
    keeping = sorted(key for key, dropped in checkouts() if not dropped)
    unexpected = [key for key in keeping if key not in MAIN_BASELINE]
    assert unexpected == [], (
        "these checkouts leave the token in .git/config; set "
        f"persist-credentials: false: {unexpected}"
    )


def test_the_baseline_only_names_checkouts_that_still_keep_credentials() -> None:
    keeping = {key for key, dropped in checkouts() if not dropped}
    stale = sorted(MAIN_BASELINE - keeping)
    assert stale == [], (
        f"remove these from MAIN_BASELINE and lower FROZEN_SIZE: {stale}"
    )


def test_the_baseline_does_not_grow() -> None:
    assert len(MAIN_BASELINE) <= FROZEN_SIZE


def test_the_walk_sees_the_checkouts() -> None:
    # Non-vacuity: a walk that found nothing would satisfy the first test.
    found = checkouts()
    assert sum(dropped for _, dropped in found) >= 41
    assert len(found) >= len(MAIN_BASELINE) + 41
