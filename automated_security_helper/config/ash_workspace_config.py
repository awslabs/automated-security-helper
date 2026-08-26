# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The schema of the workspace-level policy file.

Why this module exists
----------------------
Workspace mode scans N projects as N independently scoped executions, each
judged against its own config. That leaves no place for a statement an operator
needs to make about the workspace as a whole -- "no project here may be laxer
than MEDIUM", "this vendored directory is not ours in any project". Putting such
a statement in a project's config would make one project's file govern its
siblings; putting it in the ``.code-workspace`` file would put ASH policy in a
file owned by an editor, whose schema ASH does not control (see
``workspace/workspace_file.py``, which ignores that file's ``settings`` block
for exactly this reason).

So workspace policy gets its own file with its own schema, and this is that
schema. ``workspace/policy.py`` finds and loads it and pushes it down into each
project; nothing here reads the filesystem.

Why this is a DISTINCT file from any project config
---------------------------------------------------
A workspace root is frequently also a project. When it is, ``.ash/ash.yaml`` at
the root is that project's config and must keep meaning exactly that. If policy
could also be read from it, one project's severity threshold would silently
become its siblings' ceiling -- and the operator would have written a
project-scoped file expecting project scope.

``workspace/policy.py`` therefore looks only for ``ash-workspace.*`` names,
which are disjoint from ``ASH_CONFIG_FILE_NAMES``, and refuses when it is
pointed at a file that is some project's config. That disjointness is asserted
by ``tests/unit/workspace/test_workspace_policy.py`` so the two name sets cannot
drift into overlap.

Why the top-level key is ``workspace``
--------------------------------------
It mirrors ``AshConfig.workspace``, so an operator who knows where
``max_parallel_projects`` goes knows where the ceiling goes. The two blocks are
deliberately in different FILES rather than merged: ``WorkspaceExecutionConfig``
holds scheduling knobs that cannot change any project's verdict, and everything
here can. Its docstring records that split, and this file is the other half of
it.

Why the ceiling defaults to None rather than to MEDIUM
------------------------------------------------------
``None`` means "no ceiling", and it has to be distinguishable from a configured
one. ASH's own default threshold is MEDIUM, so defaulting this field to MEDIUM
would mean an operator who created a policy file to add one suppression had
thereby imposed a MEDIUM ceiling on every project in the workspace -- tightening
projects they never mentioned, in a file that says nothing about severity. The
absence of a ceiling is a value in the domain, so it is a value in the schema.

The ceiling is case-SENSITIVE, and that is load-bearing
-------------------------------------------------------
``Literal["ALL", ...]`` rejects ``"medium"``. This matches
``utils.severity_ladder``, which is case-sensitive for the reason recorded
there: it gates an *unrecognised* threshold like ``CRITICAL``, the loosest
setting. Accepting ``"medium"`` here and passing it through would therefore turn
a ceiling the operator meant as MEDIUM into no effective ceiling at all -- the
one direction a ceiling must never fail in. Refusing the file is the honest
outcome.

No ``!ENV`` substitution, unlike the project config
---------------------------------------------------
``AshConfig.from_file`` resolves ``${VAR}`` in its YAML. The policy loader uses
plain ``yaml.safe_load`` and does not. A ceiling an environment variable can
loosen is not a ceiling, and CI is precisely where an unset variable is easy to
arrange and hard to notice. The failure mode is safe rather than silent: an
unsubstituted ``${THRESH}`` stays a literal string and fails the ``Literal``
above, so the workspace is refused with exit 4 instead of scanning with the gate
quietly off.

Failure modes and known limitations
-----------------------------------
* ``extra="forbid"`` on both models, so ``max_severity_threshhold`` is an error
  rather than an ignored key. A silently-ignored policy key is the worst
  outcome available here: the operator believes a ceiling is in force and no
  output contradicts them.
* ``additional_scanners`` is a list of names, not per-scanner config. A scanner
  added by policy alone runs with ASH's default config for it, because the
  workspace has no legitimate source for that project's tuning of a scanner the
  project never enabled. Operators wanting tuned settings must enable the
  scanner in the project.
* ``max_severity_threshold`` tightens the gate only for findings that carry a
  severity. A finding carrying only a SARIF ``error`` level is treated as
  CRITICAL and stays actionable at every threshold, so no ceiling excludes it.
  That is not specific to workspace mode -- single-project ``severity_threshold``
  behaves identically, and the two paths were verified to agree over all 120
  level/severity/threshold combinations -- but it means the ceiling cannot
  quieten a scanner that omits ``properties.issue_severity``, checkov being the
  one ASH ships. See ``utils/severity_ladder.py``.
* This schema does not validate that a suppression's ``path`` can be rewritten
  for any project; that depends on the project list and is
  ``workspace/policy.py``'s job.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.models.core import (
    AshSuppression,
    IgnorePathWithReason,
)


class WorkspacePolicyConfig(BaseModel):
    """Workspace-wide policy: the ``workspace`` block of the policy file.

    Every field here can change a project's verdict, which is why they live in
    their own file rather than beside the execution knobs in
    ``AshConfig.workspace``.
    """

    model_config = ConfigDict(extra="forbid")

    max_severity_threshold: Annotated[
        # A real Literal, not a str with an advertised enum: the enum has to be
        # ENFORCED, not merely documented, for the case-sensitivity reason in the
        # module docstring. A value pydantic lets through reaches the ladder,
        # which reads an unrecognised threshold as CRITICAL -- no ceiling at all.
        Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None,
        Field(
            None,
            description=(
                "The LOOSEST severity threshold any project may use. A project "
                "configuring something stricter keeps it; a project configuring "
                "something looser is tightened to this value. 'max' refers to "
                "permissiveness, not to severity: the strictness order is "
                "ALL < LOW < MEDIUM < HIGH < CRITICAL, so raising this value "
                "LOOSENS the ceiling. Unset means no ceiling. Case-sensitive."
            ),
        ),
    ] = None

    suppressions: Annotated[
        list[AshSuppression],
        Field(
            description=(
                "Suppressions that apply across the workspace. Paths are "
                "WORKSPACE-relative (e.g. 'api/src/legacy.py') and are rewritten "
                "into each project's own coordinates before being applied. A "
                "suppression that cannot match inside a project is not passed to "
                "it; one that cannot be rewritten soundly refuses the workspace."
            )
        ),
    ] = []

    ignore_paths: Annotated[
        list[IgnorePathWithReason],
        Field(
            description=(
                "Paths excluded across the workspace. Workspace-relative and "
                "pushed down per project, exactly as 'suppressions' are."
            )
        ),
    ] = []

    additional_scanners: Annotated[
        list[str],
        Field(
            description=(
                "Scanners every project must run, in addition to whatever it "
                "enables itself. Additive only -- this cannot disable a scanner "
                "a project enabled. A scanner the project already declares runs "
                "under the project's own config and its findings are the "
                "project's; a scanner added only by this policy runs with "
                "default config and its findings are tagged "
                "'origin: workspace-policy' and reported separately."
            )
        ),
    ] = []

    policy_scanners_gate: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether findings from policy-added scanners affect a project's "
                "exit code. Default false: a workspace that adds a scanner to "
                "gather visibility should not thereby fail projects that never "
                "opted into it, and turning it on is the operator saying they "
                "have triaged what the new scanner reports."
            ),
        ),
    ] = False


class AshWorkspaceConfig(BaseModel):
    """The whole workspace policy file.

    A thin wrapper over one block, kept as its own model so the file has a
    versionable top-level schema and so ``workspace:`` reads the same here as it
    does in a project config.
    """

    model_config = ConfigDict(extra="forbid")

    workspace: Annotated[
        WorkspacePolicyConfig,
        Field(
            description=(
                "Workspace-wide policy. Distinct from AshConfig.workspace, which "
                "holds execution scheduling knobs in a project config; nothing "
                "here can be set from a project's own file."
            ),
        ),
    ] = WorkspacePolicyConfig()
