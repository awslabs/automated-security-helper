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

    def test_a_project_over_its_threshold_is_actionable_findings(self):
        """ASH's own code 2, with the same meaning as in single-project mode."""
        assert (
            workspace_exit_code([_completed("a"), _completed("b", exceeds=True)])
            == WorkspaceExitCode.ACTIONABLE_FINDINGS
        )

    def test_findings_are_not_reported_as_a_workspace_error(self):
        """The two must never converge. A malformed workspace file scanned
        nothing; a project over threshold was scanned and failed."""
        assert (
            workspace_exit_code([_completed("b", exceeds=True)])
            != WorkspaceExitCode.WORKSPACE_ERROR
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

    def test_findings_outrank_a_failed_project(self):
        """Reverses an earlier ordering, deliberately.

        This used to assert INTERNAL_ERROR, on the reasoning that "we do not know
        whether this project is clean" is worse news than "this project is not
        clean". Sound about severity, wrong about consequence: a CI gate that
        treats 1 as retryable infrastructure trouble and 2 as blocking would
        retry a workspace with real findings and never block on them. A finding
        is a certainty and a failed project is an unknown; an unknown must not
        suppress a certainty.
        """
        assert (
            workspace_exit_code([_completed("a", exceeds=True), _failed("b")])
            == WorkspaceExitCode.ACTIONABLE_FINDINGS
        )

    def test_a_failed_project_still_shows_when_nothing_exceeded(self):
        """Reordering must not make a failure invisible when there are no findings."""
        assert (
            workspace_exit_code([_completed("a"), _failed("b")])
            == WorkspaceExitCode.INTERNAL_ERROR
        )

    def test_an_invalid_project_config_still_outranks_findings(self):
        """3 stays on top: both are blocking, and 3 names the project to fix.

        No CI gate retries "invalid configuration", so promoting findings past it
        would buy nothing that the reversal above buys.
        """
        invalid = _failed("b")
        invalid.invalid_config = True
        assert (
            workspace_exit_code([_completed("a", exceeds=True), invalid])
            == WorkspaceExitCode.INVALID_PROJECT_CONFIG
        )

    def test_the_failed_project_is_still_disclosed_in_the_payload(self):
        """The reordering hides the failure from the exit code, not from the file."""
        results = WorkspaceResults(
            workspace_file="/w/x.code-workspace",
            workspace_root="/w",
            exit_code=WorkspaceExitCode.ACTIONABLE_FINDINGS,
            projects=[_completed("a", exceeds=True), _failed("b", "scanner blew up")],
        )
        payload = results.model_dump(mode="json")
        failed = [p for p in payload["projects"] if p["status"] == "failed"]
        assert len(failed) == 1
        assert failed[0]["error"] == "scanner blew up"

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

    def test_every_project_unchanged_is_success(self):
        """Reverses an earlier expectation, deliberately.

        This used to assert WORKSPACE_ERROR for any all-skipped workspace, which
        made a precommit hook fail on a clean no-op: in a monorepo the common case
        is an edit outside every project directory, so every project skips
        no-changes. Single-project mode exits 0 for exactly that, and three
        docstrings in this feature already promised a no-changes skip would not
        colour the status.
        """
        assert (
            workspace_exit_code(
                [
                    _skipped("a", SkippedProjectReason.NO_CHANGES),
                    _skipped("b", SkippedProjectReason.NO_CHANGES),
                ]
            )
            == WorkspaceExitCode.SUCCESS
        )

    def test_every_project_skipped_by_error_is_a_workspace_error(self):
        """Nothing was looked at, whatever tolerated it."""
        assert (
            workspace_exit_code([_skipped("a", SkippedProjectReason.ERROR)])
            == WorkspaceExitCode.WORKSPACE_ERROR
        )

    def test_a_mix_of_unchanged_and_tolerated_errors_is_success(self):
        """At least one project was examined and had nothing to do."""
        assert (
            workspace_exit_code(
                [
                    _skipped("a", SkippedProjectReason.NO_CHANGES),
                    _skipped("b", SkippedProjectReason.ERROR),
                ]
            )
            == WorkspaceExitCode.SUCCESS
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

    def test_a_refusal_and_a_findings_verdict_differ_in_code_and_in_status(self):
        """Both, independently.

        The exit code alone is now sufficient -- 4 for a refusal, 2 for findings
        -- which is the point of giving the definition error its own number. The
        status field still says the same thing in the payload, for a consumer
        that has the file open. This asserts both so a regression that collapses
        the codes back together cannot hide behind the status field.
        """
        refused = WorkspaceResults(
            workspace_file="/w/x.code-workspace",
            workspace_root="/w",
            exit_code=WorkspaceExitCode.WORKSPACE_ERROR,
            status="refused",
            refusal_detail="folders list is empty",
        )
        found = WorkspaceResults(
            workspace_file="/w/x.code-workspace",
            workspace_root="/w",
            exit_code=WorkspaceExitCode.ACTIONABLE_FINDINGS,
            status="completed",
            projects=[_completed("a", exceeds=True)],
        )
        assert refused.exit_code != found.exit_code
        assert refused.status != found.status
        assert refused.refusal_detail and found.refusal_detail is None

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
