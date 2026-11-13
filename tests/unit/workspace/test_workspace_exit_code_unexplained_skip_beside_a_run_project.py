# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A skipped project that records no reason does not pass beside a clean one.

``workspace_exit_code`` read an unexplained skip (``SKIPPED`` with no
``skip_reason``) only when no project completed or failed, so
``[completed, skipped(None)]`` exited 0 while ``[skipped(NO_CHANGES),
skipped(None)]`` exited 4. A project whose skip nothing explains may be code
nothing examined, whatever its siblings did. It now exits 4 when nothing else
decides the status; a failure, an incomplete scan or an actionable finding
still outranks it, because each of those says something about the code that
was scanned.
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


def _project(
    key: str,
    status: ProjectRunStatus,
    reason: SkippedProjectReason | None = None,
    **fields,
) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=status,
        output_path=f"projects/{key}",
        skip_reason=reason,
        **fields,
    )


def _completed(key: str, **fields) -> WorkspaceProjectResult:
    return _project(key, ProjectRunStatus.COMPLETED, **fields)


def _skipped(key: str, reason: SkippedProjectReason | None) -> WorkspaceProjectResult:
    return _project(key, ProjectRunStatus.SKIPPED, reason)


def test_an_unexplained_skip_beside_a_completed_project_is_a_workspace_error():
    entries = [_completed("api"), _skipped("web", None)]

    assert workspace_exit_code(entries) is WorkspaceExitCode.WORKSPACE_ERROR


def test_an_unexplained_skip_beside_a_completed_and_an_unchanged_project_exits_4():
    entries = [
        _completed("api"),
        _skipped("web", SkippedProjectReason.NO_CHANGES),
        _skipped("lib", None),
    ]

    assert workspace_exit_code(entries) is WorkspaceExitCode.WORKSPACE_ERROR


def test_an_actionable_finding_outranks_an_unexplained_skip():
    entries = [_completed("api", exceeds_threshold=True), _skipped("web", None)]

    assert workspace_exit_code(entries) is WorkspaceExitCode.ACTIONABLE_FINDINGS


def test_a_failed_project_outranks_an_unexplained_skip():
    entries = [_project("api", ProjectRunStatus.FAILED), _skipped("web", None)]

    assert workspace_exit_code(entries) is WorkspaceExitCode.INTERNAL_ERROR


def test_a_completed_project_beside_an_explained_skip_still_passes():
    """Control, green on both sides: a skip with a reason colours nothing."""
    for reason in (SkippedProjectReason.NO_CHANGES, SkippedProjectReason.ERROR):
        entries = [_completed("api"), _skipped("web", reason)]

        assert workspace_exit_code(entries) is WorkspaceExitCode.SUCCESS


def test_a_completed_project_alone_passes():
    """Control, green on both sides."""
    assert workspace_exit_code([_completed("api")]) is WorkspaceExitCode.SUCCESS
