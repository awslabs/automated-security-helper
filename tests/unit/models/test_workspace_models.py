# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the workspace exit-code contract and skipped-project payload.

One test class here is unusual: TestCollisionWithAshExitCodes asserts that a
known contradiction EXISTS. Code 2 means "actionable findings above threshold"
in the shipped ASH contract and "workspace definition or policy error" in the
workspace contract. Pinning it in a test keeps it from being rediscovered as a
surprise, and makes the test suite fail loudly if someone changes one side
without the other.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.models.workspace import (
    WORKSPACE_EXIT_CODES,
    SkippedProject,
    SkippedProjectReason,
    WorkspaceExitCode,
)


# ---------------------------------------------------------------------------
# Tests: the exit-code contract
# ---------------------------------------------------------------------------


class TestWorkspaceExitCode:
    """The four codes, pinned by value."""

    @pytest.mark.parametrize(
        "member,value",
        [
            (WorkspaceExitCode.SUCCESS, 0),
            (WorkspaceExitCode.INTERNAL_ERROR, 1),
            (WorkspaceExitCode.ACTIONABLE_FINDINGS, 2),
            (WorkspaceExitCode.INVALID_PROJECT_CONFIG, 3),
            (WorkspaceExitCode.WORKSPACE_ERROR, 4),
        ],
    )
    def test_values(self, member, value):
        assert member.value == value

    def test_is_an_int_so_it_can_be_returned_directly(self):
        """typer.Exit and sys.exit take an int; no conversion at the call site."""
        assert isinstance(WorkspaceExitCode.WORKSPACE_ERROR, int)
        assert WorkspaceExitCode.WORKSPACE_ERROR == 4

    def test_exactly_five_codes(self):
        assert len(WorkspaceExitCode) == 5

    def test_every_code_has_a_description(self):
        assert set(WORKSPACE_EXIT_CODES) == {c.value for c in WorkspaceExitCode}
        for description in WORKSPACE_EXIT_CODES.values():
            assert description and description.strip()

    def test_description_table_shape_matches_ash_exit_codes(self):
        """Same int -> str shape, so the MCP resource can serialise it alike."""
        assert all(isinstance(k, int) for k in WORKSPACE_EXIT_CODES)
        assert all(isinstance(v, str) for v in WORKSPACE_EXIT_CODES.values())

    def test_success_is_falsy_zero(self):
        assert WorkspaceExitCode.SUCCESS == 0

    def test_non_success_codes_are_truthy(self):
        for code in WorkspaceExitCode:
            if code is not WorkspaceExitCode.SUCCESS:
                assert code != 0


class TestNoCollisionWithAshExitCodes:
    """The workspace contract EXTENDS ASH_EXIT_CODES; it reinterprets nothing.

    An earlier revision assigned WORKSPACE_ERROR to 2, per the RFC's table, and
    this class asserted the resulting collision EXISTED so it could not be
    forgotten. The decision was to extend the contract with an unused code
    instead, so these tests now assert the opposite: every workspace code agrees
    semantically with the published map. Changing either side fails the suite.
    """

    # Every WorkspaceExitCode paired with the ASH_EXIT_CODES wording it must
    # agree with. There is no "absent from ASH_EXIT_CODES" case left: code 4 was
    # added to the published map, which is the point -- one source of truth.
    SEMANTIC_ALIGNMENT = [
        (WorkspaceExitCode.SUCCESS, "success"),
        (WorkspaceExitCode.INTERNAL_ERROR, "scan errors / scanner failures"),
        (WorkspaceExitCode.ACTIONABLE_FINDINGS, "actionable findings above threshold"),
        (WorkspaceExitCode.INVALID_PROJECT_CONFIG, "invalid config"),
        (WorkspaceExitCode.WORKSPACE_ERROR, "workspace definition or policy error"),
    ]

    @pytest.mark.parametrize("code,published", SEMANTIC_ALIGNMENT)
    def test_every_workspace_code_agrees_with_the_published_map(self, code, published):
        assert code.value in ASH_EXIT_CODES, (
            f"{code.name} is not in ASH_EXIT_CODES, so the published map is no "
            f"longer the single source of truth"
        )
        assert ASH_EXIT_CODES[code.value] == published
        assert WORKSPACE_EXIT_CODES[code.value] == published

    def test_the_two_tables_are_identical(self):
        """Same codes, same wording -- WORKSPACE_EXIT_CODES adds no vocabulary."""
        for value, description in WORKSPACE_EXIT_CODES.items():
            assert ASH_EXIT_CODES[value] == description

    def test_code_two_is_findings_not_a_workspace_error(self):
        """The specific regression this decision guards against.

        A malformed workspace file means nothing was scanned; 2 means a scan
        completed and found things. Collapsing them would let a CI job read a
        workspace that never ran as a successful scan with issues.
        """
        assert ASH_EXIT_CODES[2] == "actionable findings above threshold"
        assert WorkspaceExitCode.WORKSPACE_ERROR.value != 2
        assert WorkspaceExitCode.WORKSPACE_ERROR.value == 4
        assert "workspace" in ASH_EXIT_CODES[4].lower()

    def test_workspace_error_is_the_only_code_ash_did_not_already_have(self):
        """Extending by exactly one code is what makes this non-breaking."""
        preexisting = {0, 1, 2, 3}
        added = {c.value for c in WorkspaceExitCode} - preexisting
        assert added == {WorkspaceExitCode.WORKSPACE_ERROR.value}

    def test_the_deviation_from_the_rfc_is_documented(self):
        """A reader must find out why 4, not 2, without digging through git."""
        from automated_security_helper.models import workspace

        assert workspace.__doc__ is not None
        assert "ASH_EXIT_CODES" in workspace.__doc__
        assert "RFC" in workspace.__doc__


# ---------------------------------------------------------------------------
# Tests: skipped-project reasons
# ---------------------------------------------------------------------------


class TestSkippedProjectReason:
    """An error skip must be distinguishable from a no-changes skip."""

    def test_values_are_stable_strings(self):
        assert SkippedProjectReason.NO_CHANGES.value == "no-changes"
        assert SkippedProjectReason.ERROR.value == "error"

    def test_no_changes_is_not_an_error(self):
        assert SkippedProjectReason.NO_CHANGES.is_error is False

    def test_error_is_an_error(self):
        assert SkippedProjectReason.ERROR.is_error is True

    def test_exactly_two_reasons(self):
        assert len(SkippedProjectReason) == 2


# ---------------------------------------------------------------------------
# Tests: the payload entry
# ---------------------------------------------------------------------------


class TestSkippedProject:
    """Each entry carries the project key and why it was skipped."""

    def test_minimal_entry(self):
        entry = SkippedProject(
            project="project-a", reason=SkippedProjectReason.NO_CHANGES
        )
        assert entry.project == "project-a"
        assert entry.reason is SkippedProjectReason.NO_CHANGES
        assert entry.detail is None

    def test_entry_with_detail(self):
        entry = SkippedProject(
            project="project-b",
            reason=SkippedProjectReason.ERROR,
            detail="'..' is not allowed in a project path",
        )
        assert entry.detail == "'..' is not allowed in a project path"

    def test_is_error_delegates_to_the_reason(self):
        assert (
            SkippedProject(project="a", reason=SkippedProjectReason.ERROR).is_error
            is True
        )
        assert (
            SkippedProject(project="a", reason=SkippedProjectReason.NO_CHANGES).is_error
            is False
        )

    def test_project_is_required(self):
        with pytest.raises(ValidationError):
            SkippedProject(reason=SkippedProjectReason.ERROR)

    def test_reason_is_required(self):
        with pytest.raises(ValidationError):
            SkippedProject(project="project-a")

    def test_an_empty_project_key_is_rejected(self):
        """An unattributable skip is worse than no entry at all."""
        with pytest.raises(ValidationError):
            SkippedProject(project="", reason=SkippedProjectReason.ERROR)

    def test_an_unknown_reason_is_rejected(self):
        with pytest.raises(ValidationError):
            SkippedProject(project="project-a", reason="because-i-said-so")

    def test_reason_accepts_its_string_value(self):
        """Round-trips from JSON, where the reason arrives as a plain string."""
        entry = SkippedProject(project="project-a", reason="no-changes")
        assert entry.reason is SkippedProjectReason.NO_CHANGES

    def test_serialises_the_reason_as_its_string_value(self):
        entry = SkippedProject(
            project="project-a", reason=SkippedProjectReason.NO_CHANGES
        )
        assert entry.model_dump(mode="json") == {
            "project": "project-a",
            "reason": "no-changes",
            "detail": None,
        }

    def test_round_trips_through_json(self):
        original = SkippedProject(
            project="apps/web",
            reason=SkippedProjectReason.ERROR,
            detail="scanner crashed",
        )
        assert (
            SkippedProject.model_validate_json(original.model_dump_json()) == original
        )

    def test_a_payload_is_a_list_of_entries(self):
        """The shape that goes under the workspace.skipped_projects key."""
        payload = [
            SkippedProject(project="a", reason=SkippedProjectReason.NO_CHANGES),
            SkippedProject(
                project="b", reason=SkippedProjectReason.ERROR, detail="bad config"
            ),
        ]
        errors = [entry for entry in payload if entry.is_error]
        assert len(errors) == 1
        assert errors[0].project == "b"
