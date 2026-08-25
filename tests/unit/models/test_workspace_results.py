# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace results payload, and the exit code derived from it.

These tests pin the discriminator that makes exit code 2 usable. Phase 0 recorded
that workspace mode's "definition or policy error" (2) collides with ASH's
long-standing "actionable findings above threshold" (2). Phase 2a does not
renumber a published contract, so the collision stays -- which means something
else has to tell the two apart. ``WorkspaceResults.status`` is that something,
and a consumer that cannot read it still has the stronger signal that a refused
workspace writes no results file at all.
"""

import pytest

from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceExitCode,
    WorkspaceProjectResult,
    WorkspaceResults,
    workspace_exit_code,
)


def _completed(key: str, *, exceeds: bool = False) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        finding_count=1 if exceeds else 0,
        actionable_finding_count=1 if exceeds else 0,
        exceeds_threshold=exceeds,
        output_path=f"projects/{key}",
    )


def _failed(key: str, error: str = "boom") -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.FAILED,
        output_path=f"projects/{key}",
        error=error,
    )


def _skipped(key: str, reason: SkippedProjectReason) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.SKIPPED,
        output_path=f"projects/{key}",
        skip_reason=reason,
    )


class TestWorkspaceExitCode:
    def test_all_projects_clean_is_success(self):
        assert (
            workspace_exit_code([_completed("a"), _completed("b")])
            == WorkspaceExitCode.SUCCESS
        )

    def test_a_project_over_its_threshold_is_not_success(self):
        assert (
            workspace_exit_code([_completed("a"), _completed("b", exceeds=True)]) != 0
        )

    def test_a_failed_project_is_an_internal_error(self):
        assert (
            workspace_exit_code([_completed("a"), _failed("b")])
            == WorkspaceExitCode.INTERNAL_ERROR
        )

    def test_an_invalid_project_config_outranks_an_internal_error(self):
        """3 names the misconfigured project; 1 only says "something broke"."""
        invalid = _failed("b")
        invalid.invalid_config = True
        assert (
            workspace_exit_code([_failed("a"), invalid])
            == WorkspaceExitCode.INVALID_PROJECT_CONFIG
        )

    def test_a_failed_project_outranks_findings(self):
        """A project with no verdict is worse news than a project with a verdict."""
        assert (
            workspace_exit_code([_completed("a", exceeds=True), _failed("b")])
            == WorkspaceExitCode.INTERNAL_ERROR
        )

    def test_a_no_changes_skip_does_not_colour_the_exit_code(self):
        assert (
            workspace_exit_code(
                [_completed("a"), _skipped("b", SkippedProjectReason.NO_CHANGES)]
            )
            == WorkspaceExitCode.SUCCESS
        )

    def test_a_resolution_error_skip_does_not_colour_the_exit_code(self):
        """--allow-missing-projects is an explicit opt-out of failing.

        Resolution records a missing project as an ERROR skip. Failing here would
        make the flag mean nothing, so an error recorded *by resolution* is
        tolerated. An error raised *during execution* is a FAILED project and
        does fail -- that is the case above.
        """
        assert (
            workspace_exit_code(
                [_completed("a"), _skipped("b", SkippedProjectReason.ERROR)]
            )
            == WorkspaceExitCode.SUCCESS
        )

    def test_no_projects_at_all_is_a_workspace_error(self):
        """Exiting 0 for an empty run reports a clean result for nothing scanned."""
        assert workspace_exit_code([]) == WorkspaceExitCode.WORKSPACE_ERROR

    def test_every_project_skipped_is_a_workspace_error(self):
        assert (
            workspace_exit_code([_skipped("a", SkippedProjectReason.NO_CHANGES)])
            == WorkspaceExitCode.WORKSPACE_ERROR
        )


class TestWorkspaceResultsPayload:
    def test_skipped_projects_is_derived_from_the_project_entries(self):
        results = WorkspaceResults(
            workspace_file="/w/x.code-workspace",
            workspace_root="/w",
            exit_code=0,
            projects=[
                _completed("a"),
                _skipped("b", SkippedProjectReason.NO_CHANGES),
            ],
        )
        payload = results.skipped_projects
        assert [entry.project for entry in payload] == ["b"]
        assert payload[0].reason is SkippedProjectReason.NO_CHANGES

    def test_skipped_projects_serialises(self):
        """A skip has to reach a downstream consumer; stderr does not count."""
        results = WorkspaceResults(
            workspace_file="/w/x.code-workspace",
            workspace_root="/w",
            exit_code=0,
            projects=[_skipped("b", SkippedProjectReason.NO_CHANGES), _completed("a")],
        )
        assert "skipped_projects" in results.model_dump(mode="json")

    def test_status_discriminates_a_refusal_from_a_completed_scan(self):
        """The whole point: exit 2 alone cannot tell these apart."""
        refused = WorkspaceResults(
            workspace_file="/w/x.code-workspace",
            workspace_root="/w",
            exit_code=WorkspaceExitCode.WORKSPACE_ERROR,
            status="refused",
        )
        found = WorkspaceResults(
            workspace_file="/w/x.code-workspace",
            workspace_root="/w",
            exit_code=2,
            status="completed",
            projects=[_completed("a", exceeds=True)],
        )
        assert refused.exit_code == found.exit_code
        assert refused.status != found.status

    def test_status_defaults_to_completed(self):
        results = WorkspaceResults(
            workspace_file="/w/x.code-workspace",
            workspace_root="/w",
            exit_code=0,
        )
        assert results.status == "completed"

    @pytest.mark.parametrize("status", list(ProjectRunStatus))
    def test_every_project_status_round_trips(self, status):
        entry = WorkspaceProjectResult(
            project="a",
            relative_path="a",
            display_label="a",
            status=status,
            output_path="projects/a",
        )
        reparsed = WorkspaceProjectResult.model_validate_json(entry.model_dump_json())
        assert reparsed.status is status
