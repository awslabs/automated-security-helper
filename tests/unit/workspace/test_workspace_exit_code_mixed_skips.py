# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace where nothing ran exits 0 unless nothing at all was examined.

Why this file exists
--------------------
``workspace_exit_code`` has a nothing-was-attempted branch: when no project
completed or failed, the skip reasons decide. A resolution-time ``ERROR`` skip
is a missing project that ``--allow-missing-projects`` tolerated, and a
tolerated skip never colours the status, whatever its siblings did: the project
is reported in the results payload, not in the exit code. So the branch sets
the ERROR skips aside and looks at what is left. An unchanged skip
(``NO_CHANGES``) is a successful no-op, so anything left means 0, and a clean
precommit hook run in a monorepo stays clean also when one optional folder is
absent. Nothing left (no project named, or every project missing) means 4,
because exiting 0 would report a clean result for code nothing examined.

The contract these cases pin:

- every project an unchanged skip: SUCCESS;
- one unchanged skip beside a tolerated ERROR skip: SUCCESS, like one completed
  project beside a tolerated ERROR skip;
- every project an ERROR skip: WORKSPACE_ERROR.

The middle case read WORKSPACE_ERROR between 2026-10-29 22:51Z and this change
("nothing was scanned at all"); that alternative is recorded for review, not
kept, because it made the same hook exit 4 on a commit touching no project and
0 on a commit touching a present one.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceExitCode,
    WorkspaceProjectResult,
    workspace_exit_code,
)

pytestmark = pytest.mark.unit


def _skipped(key: str, reason: SkippedProjectReason) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.SKIPPED,
        output_path=f"projects/{key}",
        skip_reason=reason,
    )


def test_every_project_unchanged_is_a_clean_no_op():
    entries = [
        _skipped("api", SkippedProjectReason.NO_CHANGES),
        _skipped("web", SkippedProjectReason.NO_CHANGES),
    ]
    assert workspace_exit_code(entries) is WorkspaceExitCode.SUCCESS


def test_a_tolerated_error_skip_beside_an_unchanged_skip_does_not_colour_the_status():
    entries = [
        _skipped("api", SkippedProjectReason.NO_CHANGES),
        _skipped("web", SkippedProjectReason.ERROR),
    ]
    assert workspace_exit_code(entries) is WorkspaceExitCode.SUCCESS


def test_every_project_an_error_skip_is_a_workspace_error():
    """Control: with the tolerated skips set aside nothing is left, as for no project at all."""
    entries = [
        _skipped("api", SkippedProjectReason.ERROR),
        _skipped("web", SkippedProjectReason.ERROR),
    ]
    assert workspace_exit_code(entries) is WorkspaceExitCode.WORKSPACE_ERROR
