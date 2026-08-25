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
* ``0`` success.
* ``1`` internal error -- ASH itself failed; no verdict was reached.
* ``2`` workspace definition or policy error -- the workspace file, a project
  path, or a workspace-level policy is not usable. Nothing was scanned.
* ``3`` invalid project configuration -- the workspace is fine but a project's
  own config is not.

Codes 2 and 3 are both configuration problems and the split is deliberate: 2
means the operator's workspace file is wrong and no project could run, 3 means
one project is misconfigured. They route to different people.

UNRESOLVED: code 2 contradicts the shipped ASH_EXIT_CODES
---------------------------------------------------------
``automated_security_helper.core.constants.ASH_EXIT_CODES`` already publishes a
contract, exposed as an MCP resource and covered by
``tests/unit/cli/mcp/test_exit_codes_resource.py``::

    0 success
    1 scan errors / scanner failures
    2 actionable findings above threshold
    3 invalid config

Codes 0, 1 and 3 line up. Code 2 does not, and it fails in the unsafe
direction. Today code 2 is the ordinary, expected result of a scan that worked
and found something; ``_compute_exit_code`` in ``run_ash_scan`` returns it
whenever there are actionable findings. A CI job that reads 2 as "scan
completed, review the findings" would read a malformed workspace file exactly
the same way -- reporting a scan that never ran as a scan with findings.

This module implements the workspace contract as specified rather than quietly
renumbering it, because the numbering is a published interface and the choice
of how to reconcile the two is not one to make silently. The options, none of
which is taken here:

1. Give workspace-definition errors their own unused code (4 or above). Keeps
   both contracts unambiguous; costs a change to the RFC's stated numbering.
2. Redefine 2 as "definition or policy error" everywhere and move
   findings-above-threshold to a new code. Cleanest end state, but a breaking
   change for every existing consumer of ASH's exit status.
3. Leave the collision. Workspace mode is opt-in behind a flag, so a caller
   that never passes ``--workspace`` cannot observe the ambiguity -- but a
   caller that adopts workspace mode inherits it silently, which is the worst
   of the three.

``tests/unit/models/test_workspace_models.py`` asserts the collision exists, so
it surfaces on any change to either side rather than being rediscovered later.

Note that ASH_EXIT_CODES' own code 1 is partly aspirational: a scanner at ERROR
does not produce exit 1 today, because ``_compute_exit_code`` returns 1 only
when ``results is None``. That happens to make it a good match for "internal
error" here.

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

    See the module docstring for the unresolved collision at code 2.
    """

    SUCCESS = 0
    INTERNAL_ERROR = 1
    WORKSPACE_ERROR = 2
    INVALID_PROJECT_CONFIG = 3


# Descriptions keyed by code, mirroring the shape of ASH_EXIT_CODES so the MCP
# resource can serialise either table the same way.
WORKSPACE_EXIT_CODES: Dict[int, str] = {
    WorkspaceExitCode.SUCCESS.value: "success",
    WorkspaceExitCode.INTERNAL_ERROR.value: "internal error",
    WorkspaceExitCode.WORKSPACE_ERROR.value: "workspace definition or policy error",
    WorkspaceExitCode.INVALID_PROJECT_CONFIG.value: "invalid project configuration",
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
