# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace execution plan: what would be scanned, and how it was decided.

Why this module exists
----------------------
Workspace resolution makes a series of decisions an operator cannot otherwise
see: which directories became projects, what key each was given, which config
file was found for it, which scanners that config enables, and which projects
were dropped and why. ``--dry-run`` exists so those decisions can be inspected
before a scan runs, and this module is the artifact it prints. Phase 2 executes
from the same object, so what an operator inspects is what will run rather than a
separate description of it that can drift.

Naming, and why three names are not two
---------------------------------------
Each project carries three strings, and conflating any pair of them causes a real
defect:

* ``relative_path`` -- the project's path below the workspace root
  (``services/api``). The coordinate system aggregated findings live in.
* ``key`` -- that path with separators replaced by dashes (``services-api``).
  The only thing used for output paths and for uniqueness. It is a path
  *derived* value, not a path: it never goes back through the filesystem.
* ``label`` and ``display_label`` -- what a human reads. Never a uniqueness key,
  because two projects may legitimately carry the same ``project_name``, and
  never a path.

``display_label`` is stored rather than computed on demand because it depends on
the whole sibling set: a label is decorated with its key only when another
project in the same workspace shares it. The resolver settles it once, when it
has that set in hand.

The skipped-projects payload
----------------------------
``skipped_projects`` is derived from the per-project skip fields rather than
stored alongside them, so the two cannot disagree. It is a
``@computed_field``, which means it appears in ``model_dump()``: a skip has to
reach downstream consumers, and a log line does not, because nothing downstream
reads stderr.

One deliberate divergence from Phase 0. ``SkippedProject.project`` is documented
in :mod:`automated_security_helper.models.workspace` as the workspace-relative
*path*, and is populated here with the *key*. The field's stated purpose is to be
"the key it is attributed under elsewhere in the results", and the key is what
attribution actually uses, so populating the path would produce a payload that
does not join to anything. The two coincide for a top-level project and differ
for a nested one.

Failure modes and known limitations
-----------------------------------
* Paths are POSIX strings, not ``Path`` objects, so the plan serialises to JSON
  without a custom encoder and reads identically on every platform. Anything
  that needs a real path must reconstruct it.
* A skipped project still occupies an entry in ``projects``, with no config and
  no scanners. Dropping it would make the plan silently shorter than the
  workspace file it came from, which is the disclosure problem this phase exists
  to avoid.
* ``render()`` is for humans and its layout is not a contract. Consumers that
  need structure should read ``model_dump()``.
* Nothing here validates. A plan is only ever built by
  :func:`automated_security_helper.workspace.resolver.resolve_workspace`, which
  has already refused anything unusable; a plan constructed by hand can hold
  states resolution would never produce.
"""

from __future__ import annotations

from typing import Annotated, Dict, List, Optional

from pydantic import BaseModel, Field, computed_field

from automated_security_helper.models.workspace import (
    SkippedProject,
    SkippedProjectReason,
)

# Rendering widths, chosen so the longest label below lines up.
_FIELD_WIDTH = 12
_INDENT = "      "


class ProjectPlan(BaseModel):
    """One project's resolved place in the workspace."""

    key: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "Workspace-relative path with separators replaced by dashes. "
                "The only value used for output paths and uniqueness."
            ),
        ),
    ]
    relative_path: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "Workspace-relative path, forward-slash separated, as findings "
                "are attributed."
            ),
        ),
    ]
    path: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description="Canonical absolute path of the project directory, POSIX-shaped.",
        ),
    ]
    label: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "AshConfig.project_name when the project's config declares one, "
                "otherwise the project key. Not unique."
            ),
        ),
    ]
    display_label: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "The label, suffixed with the key when another project in the "
                "same workspace shares the label."
            ),
        ),
    ]
    config_source: Annotated[
        Optional[str],
        Field(
            None,
            description=(
                "Path of the config file resolved for this project, or null when "
                "the project has none and took ASH's default config."
            ),
        ),
    ] = None
    scanners: Annotated[
        List[str],
        Field(
            default_factory=list,
            description="Scanner names this project's config enables, sorted.",
        ),
    ]
    severity_threshold: Annotated[
        Optional[str],
        Field(
            None,
            description=(
                "The project's own global_settings.severity_threshold. A "
                "workspace-level ceiling is a later phase; when one exists the "
                "effective value becomes severity_ladder.stricter_of(this, "
                "ceiling)."
            ),
        ),
    ] = None
    scanner_pins: Annotated[
        Dict[str, str],
        Field(
            default_factory=dict,
            description=(
                "Effective tool_version constraint per scanner, including those "
                "inherited from a scanner's built-in default."
            ),
        ),
    ]
    skipped: Annotated[
        bool,
        Field(
            False,
            description="True when this project will not be scanned.",
        ),
    ] = False
    skip_reason: Annotated[
        Optional[SkippedProjectReason],
        Field(None, description="Why the project was skipped, when it was."),
    ] = None
    skip_detail: Annotated[
        Optional[str],
        Field(None, description="Human-readable explanation of the skip."),
    ] = None

    def as_skipped_project(self) -> Optional[SkippedProject]:
        """This project as a ``skipped_projects`` payload entry, or None.

        Returns None for a project that will be scanned, so callers can build
        the payload by filtering.
        """
        if not self.skipped or self.skip_reason is None:
            return None
        return SkippedProject(
            project=self.key,
            reason=self.skip_reason,
            detail=self.skip_detail,
        )


class WorkspacePlan(BaseModel):
    """Everything resolution decided about one workspace.

    This is the whole output of Phase 1. It describes work; it does not perform
    any.
    """

    workspace_file: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description="Canonical absolute path of the .code-workspace file.",
        ),
    ]
    workspace_root: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "Canonical absolute path of the directory holding the workspace "
                "file. This is the scan's source_dir, and in container mode it "
                "is what gets mounted at /src, so every project path has to sit "
                "below it."
            ),
        ),
    ]
    projects: Annotated[
        List[ProjectPlan],
        Field(
            default_factory=list,
            description=(
                "Every folder entry that passed containment, in workspace-file "
                "order, including skipped ones."
            ),
        ),
    ]
    allow_missing_projects: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether the operator opted out of failing on a missing or "
                "unreadable project."
            ),
        ),
    ] = False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def skipped_projects(self) -> List[SkippedProject]:
        """The Phase 0 ``skipped_projects`` payload, derived from the projects.

        A computed field so it serialises: a downstream consumer reading the plan
        must be able to see that a project was dropped, and cannot read stderr.
        """
        entries = (project.as_skipped_project() for project in self.projects)
        return [entry for entry in entries if entry is not None]

    @property
    def active_projects(self) -> List[ProjectPlan]:
        """The projects that would actually be scanned."""
        return [project for project in self.projects if not project.skipped]

    def render(self) -> str:
        """Render the plan for a human reading ``--dry-run`` output.

        Layout is not a contract; consumers wanting structure should use
        ``model_dump()``.
        """
        skipped = self.skipped_projects
        lines: List[str] = [
            "Workspace execution plan",
            f"{_INDENT}{'file:':<{_FIELD_WIDTH}}{self.workspace_file}",
            f"{_INDENT}{'root:':<{_FIELD_WIDTH}}{self.workspace_root}",
            f"{_INDENT}{'projects:':<{_FIELD_WIDTH}}"
            f"{len(self.active_projects)} to scan, {len(skipped)} skipped",
            f"{_INDENT}{'missing ok:':<{_FIELD_WIDTH}}"
            f"{'yes' if self.allow_missing_projects else 'no'}",
            "",
        ]

        for position, project in enumerate(self.projects, start=1):
            suffix = ""
            if project.skipped:
                reason = (
                    project.skip_reason.value if project.skip_reason else "unspecified"
                )
                suffix = f"  [skipped: {reason}]"
            lines.append(f"  {position}. {project.key}{suffix}")
            lines.append(f"{_INDENT}{'label:':<{_FIELD_WIDTH}}{project.display_label}")
            lines.append(f"{_INDENT}{'path:':<{_FIELD_WIDTH}}{project.path}")
            lines.append(
                f"{_INDENT}{'relative:':<{_FIELD_WIDTH}}{project.relative_path}"
            )
            if project.skipped:
                lines.append(
                    f"{_INDENT}{'reason:':<{_FIELD_WIDTH}}"
                    f"{project.skip_detail or 'not stated'}"
                )
                lines.append("")
                continue
            lines.append(
                f"{_INDENT}{'config:':<{_FIELD_WIDTH}}"
                f"{project.config_source or 'ASH default config'}"
            )
            lines.append(
                f"{_INDENT}{'threshold:':<{_FIELD_WIDTH}}"
                f"{project.severity_threshold or 'none'}"
            )
            lines.append(
                f"{_INDENT}{'scanners:':<{_FIELD_WIDTH}}"
                f"{', '.join(project.scanners) or 'none enabled'}"
            )
            if project.scanner_pins:
                pins = ", ".join(
                    f"{scanner} {pin}"
                    for scanner, pin in sorted(project.scanner_pins.items())
                )
                lines.append(f"{_INDENT}{'pins:':<{_FIELD_WIDTH}}{pins}")
            lines.append("")

        lines.append(
            "Nothing has been scanned. This is a resolution and validation pass only."
        )
        return "\n".join(lines)
