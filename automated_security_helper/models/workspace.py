# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace-mode exit-code contract and the skipped-projects payload.

Why this module exists
----------------------
A workspace scan can fail in ways a single-directory scan cannot: the workspace
definition itself can be malformed, one project's config can be invalid while
the others are fine, and a project can be skipped without that being a failure
at all. Callers -- CI jobs above all -- need to tell those apart from the
process exit status alone, before they have any output to parse. Modelling the
contract in one place means the CLI, the MCP server and the aggregator cannot
each invent their own numbering.

The contract
------------
Workspace mode EXTENDS the published ``ASH_EXIT_CODES`` rather than
reinterpreting any of it, so a caller that understands single-project ASH does
not have to relearn the first four codes:

* ``0`` success.
* ``1`` scan errors / scanner failures. A workspace-mode internal error -- ASH
  itself failed and reached no verdict -- is a case of this.
* ``2`` actionable findings above threshold. Workspace mode uses this for
  exactly that: a project exceeded its effective threshold, consistently with
  single-project mode.
* ``3`` invalid config. A project's own config being unusable is a case of this.
* ``4`` workspace definition or policy error -- the workspace file, a project
  path, or a workspace-level policy is not usable. NOTHING WAS SCANNED.

Codes 3 and 4 are both configuration problems and the split is deliberate: 4
means the operator's workspace file is wrong and no project could run, 3 means
one project is misconfigured. They route to different people.

Why 4, when the RFC's table said 2
----------------------------------
This is a deliberate deviation from the RFC, not a transcription error.

The RFC assigned "workspace definition or policy error" to exit code 2. But 2
was already published, in
``automated_security_helper.core.constants.ASH_EXIT_CODES``, as "actionable
findings above threshold" -- exposed as an MCP resource and pinned by
``tests/unit/cli/mcp/test_exit_codes_resource.py``. It is also the ordinary,
expected result of a scan that worked: ``_compute_exit_code`` in
``run_ash_scan`` returns 2 whenever there are actionable findings.

Overloading it would make two opposite outcomes indistinguishable. A malformed
workspace file means NOTHING WAS SCANNED; exit 2 means a scan completed and
found things worth reviewing. A CI job treating 2 as "review the findings"
would read a workspace that never ran as a successful scan with issues -- a
fail-open failure, and precisely the mode the RFC's own failure-semantics
section exists to reject, by the same argument it uses against "warn and skip"
for a missing project.

Extending the contract with an unused code keeps both meanings unambiguous and
breaks no existing consumer. Code 4 was confirmed unused across the package,
the scripts, the tests and the CI workflows before it was chosen.

``tests/unit/models/test_workspace_models.py`` asserts there is NO collision --
every value here agrees semantically with ``ASH_EXIT_CODES`` -- so changing
either side fails the suite.

Note that ASH_EXIT_CODES' own code 1 is partly aspirational: a scanner at ERROR
does not produce exit 1 today, because ``_compute_exit_code`` returns 1 only
when ``results is None``. That happens to make it a good match for a
workspace-mode internal error.

The skipped-projects payload
----------------------------
``SkippedProject`` is one entry of ``workspace.skipped_projects``; the payload
is a list of them. The reason distinguishes an error skip from a ``no-changes``
skip, which matters because they mean opposite things: ``no-changes`` is a
successful optimisation and must not colour the exit status, while ``error``
means a project the operator asked for was not scanned. Collapsing the two
would let a broken project masquerade as an unchanged one -- a silent
false-negative in a security tool, which is the failure mode most worth
designing against.

The results payload, and living with the collision at code 2
------------------------------------------------------------
``WorkspaceResults`` is what a workspace scan writes into
``ash_aggregated_results.json`` under the ``workspace`` key, and
``workspace_exit_code`` derives the process status from it. Phase 2a does not
resolve the code-2 collision described above -- renumbering a published contract
is not a decision to make silently -- so it supplies a discriminator instead.
Two independent ones, in fact, because they fail in different directions:

1. ``WorkspaceResults.status`` is ``"refused"`` when the workspace definition or
   a workspace-level policy was rejected and nothing ran, and ``"completed"``
   when projects were scanned. A consumer reading the results file can always
   tell the two apart, whatever the exit code says.
2. A refused workspace writes no results file at all. So a caller that only has
   the exit status still has a reliable test: exit 2 with a results file means
   findings, exit 2 without one means the workspace was rejected. This is the
   same discriminator ``scripts/verify_external_target_scan.py`` already relies
   on for Typer's UsageError, which is also 2.

Neither is as good as distinct numbers. Both are better than an ambiguity with
no way out, and both survive the eventual renumbering.

Precedence in ``workspace_exit_code``, and why it runs in this order
-------------------------------------------------------------------
``INVALID_PROJECT_CONFIG`` (3) > ``INTERNAL_ERROR`` (1) > findings (2) > success
(0). The order is by how specific the diagnosis is, not by how bad the outcome
is:

* 3 names a misconfigured project, which is actionable by one person.
* 1 says a project reached no verdict at all. That outranks findings because
  "we do not know whether this project is clean" is worse news than "this
  project is not clean" -- the second is a result, the first is the absence of
  one.
* 2 means every project reached a verdict and at least one project exceeded its
  own effective threshold.

A skip recorded by *resolution* -- a missing project tolerated under
``--allow-missing-projects``, or a project with no changed files -- does not
affect the status. Failing on the former would make the flag mean nothing, and
failing on the latter would make the optimisation useless. A project that fails
during *execution* is ``FAILED``, not skipped, and does affect the status.
"""

from __future__ import annotations

from enum import Enum, IntEnum
from typing import Annotated, Dict, Iterable, List, Literal, Optional

from pydantic import BaseModel, Field, computed_field


class WorkspaceExitCode(IntEnum):
    """Process exit statuses for a workspace-mode scan.

    An IntEnum so members can be handed straight to ``typer.Exit`` or
    ``sys.exit`` without conversion at the call site.

    Every value agrees with ``ASH_EXIT_CODES``; only ``WORKSPACE_ERROR`` is new.
    ``ACTIONABLE_FINDINGS`` is modelled here rather than left as a bare literal
    because workspace mode really does return it -- a project over its
    effective threshold -- and a call site should not have to hardcode 2.

    See the module docstring for why WORKSPACE_ERROR is 4 and not the 2 the RFC
    table assigned.
    """

    SUCCESS = 0
    INTERNAL_ERROR = 1
    ACTIONABLE_FINDINGS = 2
    INVALID_PROJECT_CONFIG = 3
    WORKSPACE_ERROR = 4


# Descriptions keyed by code, mirroring the shape of ASH_EXIT_CODES so the MCP
# resource can serialise either table the same way. The wording matches
# ASH_EXIT_CODES for the four shared codes, because they are the same codes --
# not a parallel vocabulary for them.
WORKSPACE_EXIT_CODES: Dict[int, str] = {
    WorkspaceExitCode.SUCCESS.value: "success",
    WorkspaceExitCode.INTERNAL_ERROR.value: "scan errors / scanner failures",
    WorkspaceExitCode.ACTIONABLE_FINDINGS.value: "actionable findings above threshold",
    WorkspaceExitCode.INVALID_PROJECT_CONFIG.value: "invalid config",
    WorkspaceExitCode.WORKSPACE_ERROR.value: "workspace definition or policy error",
}


class SkippedProjectReason(str, Enum):
    """Why a project in the workspace was not scanned.

    The distinction is load-bearing: ``NO_CHANGES`` is a successful
    optimisation, ``ERROR`` is a project the operator asked for that did not
    run. Only the latter should affect the exit status.
    """

    NO_CHANGES = "no-changes"
    ERROR = "error"

    @property
    def is_error(self) -> bool:
        """True when the skip represents a failure rather than an optimisation."""
        return self is SkippedProjectReason.ERROR


class SkippedProject(BaseModel):
    """One entry of the ``workspace.skipped_projects`` payload."""

    project: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "Workspace-relative path of the skipped project, which is also "
                "the key it is attributed under elsewhere in the results."
            ),
        ),
    ]
    reason: Annotated[
        SkippedProjectReason,
        Field(
            ..., description="Whether the project was skipped by error or as unchanged"
        ),
    ]
    detail: Annotated[
        Optional[str],
        Field(
            None,
            description="(Optional) Human-readable explanation of the skip",
        ),
    ] = None

    @property
    def is_error(self) -> bool:
        """True when this skip represents a failure rather than an optimisation."""
        return self.reason.is_error


class ProjectRunStatus(str, Enum):
    """What became of one project once execution started.

    ``SKIPPED`` covers both skip reasons and carries ``skip_reason`` to say
    which; ``FAILED`` is reserved for a project that was attempted and produced
    no verdict, which is the only one of the three that fails the workspace.
    """

    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class WorkspaceProjectResult(BaseModel):
    """One project's outcome, as it appears in the aggregated results."""

    model_config = {"extra": "allow"}

    project: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "The project key -- its workspace-relative path with separators "
                "replaced by dashes. Every other attribution in the results "
                "joins on this."
            ),
        ),
    ]
    relative_path: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "The project's workspace-relative path, forward-slash separated. "
                "The coordinate system workspace-relative finding paths live in."
            ),
        ),
    ]
    display_label: Annotated[
        str,
        Field(..., min_length=1, description="What a human reads. Not unique."),
    ]
    status: Annotated[
        ProjectRunStatus,
        Field(
            ..., description="Whether the project completed, was skipped, or failed."
        ),
    ]
    severity_threshold: Annotated[
        Optional[str],
        Field(
            None,
            description=(
                "The threshold this project's verdict was judged against. Null "
                "for a project that never ran."
            ),
        ),
    ] = None
    finding_count: Annotated[
        int,
        Field(0, ge=0, description="Unsuppressed findings reported for the project."),
    ] = 0
    actionable_finding_count: Annotated[
        int,
        Field(
            0,
            ge=0,
            description=(
                "Findings at or above this project's own effective threshold."
            ),
        ),
    ] = 0
    exceeds_threshold: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether this project's own verdict is a failure. Stored rather "
                "than derived from actionable_finding_count because "
                "fail_on_findings can be off, in which case a project has "
                "actionable findings and still passes."
            ),
        ),
    ] = False
    duration_seconds: Annotated[
        float, Field(0.0, ge=0.0, description="Wall clock spent on this project.")
    ] = 0.0
    output_path: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "Where this project's own subtree lives, relative to the "
                "workspace output directory."
            ),
        ),
    ]
    sarif_run_index: Annotated[
        Optional[int],
        Field(
            None,
            ge=0,
            description=(
                "Index of this project's run in the aggregated SARIF, so a "
                "consumer can extract one project by selecting a run. Null when "
                "the project contributed no run."
            ),
        ),
    ] = None
    scanners: Annotated[
        Dict[str, str],
        Field(
            default_factory=dict,
            description="Final status per scanner name, for this project alone.",
        ),
    ]
    skip_reason: Annotated[
        Optional[SkippedProjectReason],
        Field(None, description="Why the project was skipped, when it was."),
    ] = None
    skip_detail: Annotated[
        Optional[str],
        Field(None, description="Human-readable explanation of the skip."),
    ] = None
    error: Annotated[
        Optional[str],
        Field(None, description="What went wrong, for a FAILED project."),
    ] = None
    invalid_config: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether the failure was this project's own configuration. "
                "Separated from a general failure because it selects exit code "
                "3 rather than 1, and those route to different people."
            ),
        ),
    ] = False

    def as_skipped_project(self) -> Optional[SkippedProject]:
        """This project as a ``skipped_projects`` payload entry, or None."""
        if self.status is not ProjectRunStatus.SKIPPED or self.skip_reason is None:
            return None
        return SkippedProject(
            project=self.project,
            reason=self.skip_reason,
            detail=self.skip_detail,
        )


class WorkspaceResults(BaseModel):
    """Everything a workspace scan concluded, keyed under ``workspace``."""

    model_config = {"extra": "allow"}

    workspace_file: Annotated[
        str,
        Field(
            ..., min_length=1, description="Absolute path of the workspace definition."
        ),
    ]
    workspace_root: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "Absolute path of the directory holding it. Every "
                "workspace-relative finding path is relative to this, and in "
                "container mode this is what was mounted at /src."
            ),
        ),
    ]
    status: Annotated[
        Literal["completed", "refused"],
        Field(
            "completed",
            description=(
                "Whether projects were scanned at all. The discriminator for the "
                "code-2 collision -- see the module docstring."
            ),
        ),
    ] = "completed"
    exit_code: Annotated[
        int, Field(..., description="The process status this run exited with.")
    ]
    projects: Annotated[
        List[WorkspaceProjectResult],
        Field(
            default_factory=list,
            description="Every project in workspace-file order, skipped ones included.",
        ),
    ]
    max_parallel_projects: Annotated[
        Optional[int],
        Field(None, ge=1, description="The outer concurrency bound this run used."),
    ] = None
    project_timeout: Annotated[
        Optional[float],
        Field(None, gt=0, description="The per-project time budget, when one was set."),
    ] = None
    wall_clock_seconds: Annotated[
        float, Field(0.0, ge=0.0, description="Wall clock for the whole workspace.")
    ] = 0.0
    unconvertible_finding_paths: Annotated[
        int,
        Field(
            0,
            ge=0,
            description=(
                "Findings whose path could not be expressed in workspace-relative "
                "coordinates. Counted rather than dropped: dropping a finding "
                "because its path is awkward is a silent false negative."
            ),
        ),
    ] = 0

    refusal_detail: Annotated[
        Optional[str],
        Field(
            None,
            description=(
                "Why the workspace was refused, for status='refused'. Null for a "
                "run that scanned anything."
            ),
        ),
    ] = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def skipped_projects(self) -> List[SkippedProject]:
        """The Phase 0 ``skipped_projects`` payload, derived from the projects.

        Derived rather than stored so the two cannot disagree, and a
        ``computed_field`` so it serialises -- a downstream consumer must be able
        to see that a project was dropped, and cannot read stderr.
        """
        entries = (project.as_skipped_project() for project in self.projects)
        return [entry for entry in entries if entry is not None]


def workspace_exit_code(
    projects: Iterable[WorkspaceProjectResult],
) -> WorkspaceExitCode:
    """Derive the process status from the per-project outcomes.

    See "Precedence" in the module docstring for the ordering and its rationale.

    Args:
        projects: Every project in the run, skipped ones included.

    Returns:
        The contract code. Note that findings above threshold return the integer
        2, which is ``WORKSPACE_ERROR``'s value -- the collision Phase 0
        recorded. ``WorkspaceResults.status`` distinguishes them.
    """
    entries = list(projects)

    completed = [
        entry for entry in entries if entry.status is ProjectRunStatus.COMPLETED
    ]
    failed = [entry for entry in entries if entry.status is ProjectRunStatus.FAILED]

    if not completed and not failed:
        # Nothing was attempted. Exiting 0 would report a clean result for a
        # workspace nothing examined, which in CI reads as a passing scan.
        return WorkspaceExitCode.WORKSPACE_ERROR

    if any(entry.invalid_config for entry in failed):
        return WorkspaceExitCode.INVALID_PROJECT_CONFIG
    if failed:
        return WorkspaceExitCode.INTERNAL_ERROR
    if any(entry.exceeds_threshold for entry in completed):
        # ASH's long-standing "actionable findings" status. Deliberately the same
        # integer as WORKSPACE_ERROR; the payload's `status` field is what tells
        # a consumer which of the two this is.
        return WorkspaceExitCode(2)
    return WorkspaceExitCode.SUCCESS
