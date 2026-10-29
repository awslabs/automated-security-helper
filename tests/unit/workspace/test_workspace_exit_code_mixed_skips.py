# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace where nothing ran exits 0 only when every project was an unchanged skip.

Why this file exists
--------------------
``workspace_exit_code`` has a nothing-was-attempted branch: when no project
completed or failed, the skip reasons decide. An unchanged skip (``NO_CHANGES``)
is a successful no-op, and a workspace of unchanged projects exits 0 so a clean
precommit hook run stays clean. A project skipped by ``ERROR`` was never looked
at. The branch returned SUCCESS when ANY project was an unchanged skip, so a
workspace that examined one project and never looked at the others reported a
clean result for code nothing examined.

The contract these cases pin:

- every project an unchanged skip: SUCCESS;
- one unchanged skip beside an ERROR skip: WORKSPACE_ERROR;
- every project an ERROR skip: WORKSPACE_ERROR (unchanged).
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


def test_one_unchanged_skip_does_not_excuse_an_error_skip():
    entries = [
        _skipped("api", SkippedProjectReason.NO_CHANGES),
        _skipped("web", SkippedProjectReason.ERROR),
    ]
    assert workspace_exit_code(entries) is WorkspaceExitCode.WORKSPACE_ERROR


def test_every_project_an_error_skip_is_unchanged():
    """Control: the all-ERROR answer the branch always gave."""
    entries = [
        _skipped("api", SkippedProjectReason.ERROR),
        _skipped("web", SkippedProjectReason.ERROR),
    ]
    assert workspace_exit_code(entries) is WorkspaceExitCode.WORKSPACE_ERROR
