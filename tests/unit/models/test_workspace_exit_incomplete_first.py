# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace with an incomplete project exits 1 even when another has findings.

A workspace exits 1 (incomplete) ahead of 2 (findings), the same as a
single-directory scan, whose ``_compute_exit_code`` runs the completeness pass
before the threshold count. Before, a workspace answered 2 whenever any project
had findings, so a CI gate that clears 2 by fixing findings was told the scan
was otherwise whole while a project's scanner had examined nothing (an offline
npm-audit, a missing tool) or a project had not run at all.

3 (a project's invalid configuration) stays above both.
"""

from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceExitCode,
    WorkspaceProjectResult,
    workspace_exit_code,
)


def _completed(
    key: str, *, exceeds: bool = False, incomplete: bool = False
) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        finding_count=1 if exceeds else 0,
        actionable_finding_count=1 if exceeds else 0,
        exceeds_threshold=exceeds,
        incomplete_scanners=["npm-audit"] if incomplete else [],
        scan_incomplete=incomplete,
        output_path=f"projects/{key}",
    )


def _failed(key: str, *, invalid: bool = False) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.FAILED,
        output_path=f"projects/{key}",
        error="the scan raised",
        invalid_config=invalid,
    )


def test_an_incomplete_project_outranks_another_project_s_findings():
    assert (
        workspace_exit_code(
            [_completed("web", exceeds=True), _completed("api", incomplete=True)]
        )
        == WorkspaceExitCode.INTERNAL_ERROR
    )


def test_one_project_incomplete_and_over_threshold_exits_1_like_a_single_scan():
    assert (
        workspace_exit_code([_completed("web", exceeds=True, incomplete=True)])
        == WorkspaceExitCode.INTERNAL_ERROR
    )


def test_a_failed_project_outranks_findings():
    """A project that did not run is the same news as one that ran incompletely."""
    assert (
        workspace_exit_code([_completed("web", exceeds=True), _failed("api")])
        == WorkspaceExitCode.INTERNAL_ERROR
    )


def test_an_invalid_project_config_still_outranks_both():
    assert (
        workspace_exit_code(
            [
                _completed("web", exceeds=True),
                _completed("api", incomplete=True),
                _failed("cli", invalid=True),
            ]
        )
        == WorkspaceExitCode.INVALID_PROJECT_CONFIG
    )


def test_control_findings_alone_are_still_2():
    assert (
        workspace_exit_code([_completed("web", exceeds=True), _completed("api")])
        == WorkspaceExitCode.ACTIONABLE_FINDINGS
    )


def test_control_an_incomplete_project_alone_is_1():
    assert (
        workspace_exit_code([_completed("web"), _completed("api", incomplete=True)])
        == WorkspaceExitCode.INTERNAL_ERROR
    )
