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
"""

from __future__ import annotations

from enum import Enum, IntEnum
from typing import Annotated, Dict, Optional

from pydantic import BaseModel, Field


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
