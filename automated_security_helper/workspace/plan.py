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

from automated_security_helper.models.core import (
    AshSuppression,
    IgnorePathWithReason,
)
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
                "The project's own global_settings.severity_threshold, exactly as "
                "its config declared it. Kept alongside "
                "effective_severity_threshold rather than being overwritten, so "
                "an operator can see what a workspace ceiling changed instead of "
                "only its result."
            ),
        ),
    ] = None
    effective_severity_threshold: Annotated[
        Optional[str],
        Field(
            None,
            description=(
                "The threshold this project is actually judged against: "
                "severity_ladder.stricter_of(severity_threshold, the workspace "
                "ceiling). Equal to severity_threshold when there is no policy, "
                "or when the project was already stricter than the ceiling."
            ),
        ),
    ] = None
    threshold_tightened_by_policy: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether the workspace ceiling actually moved this project's "
                "threshold. Recorded rather than left to be re-derived, so "
                "--dry-run and the reporters can state where policy took effect "
                "without comparing two fields and reaching their own conclusion."
            ),
        ),
    ] = False
    policy_suppressions: Annotated[
        List[AshSuppression],
        Field(
            default_factory=list,
            description=(
                "Workspace-level suppressions rewritten into THIS project's "
                "coordinates. Only those whose pattern can match inside it; a "
                "workspace suppression naming a sibling is absent here rather "
                "than present and inert."
            ),
        ),
    ]
    policy_ignore_paths: Annotated[
        List[IgnorePathWithReason],
        Field(
            default_factory=list,
            description=(
                "Workspace-level ignore paths, rewritten for this project on the "
                "same terms as policy_suppressions."
            ),
        ),
    ]
    policy_scanners: Annotated[
        List[str],
        Field(
            default_factory=list,
            description=(
                "Scanners the workspace policy adds that this project does not "
                "itself enable. These run with ASH's default config and their "
                "findings are tagged 'origin: workspace-policy'. A scanner the "
                "project already declares is absent here, because it runs under "
                "the project's own config and its findings are the project's."
            ),
        ),
    ]
    policy_scanners_gate: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether findings from policy_scanners affect this project's exit "
                "code. Carried per project so no consumer has to reach back into "
                "the policy to interpret policy_scanners."
            ),
        ),
    ] = False
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
    ash_plugin_modules: Annotated[
        List[str],
        Field(
            default_factory=list,
            description=(
                "Python modules this project's config asks ASH to import for "
                "extra plugins, sorted. Carried on the plan because plugin "
                "registration is process-global: two projects wanting different "
                "sets cannot both be honoured in one run, so the resolver has to "
                "compare them before anything is scanned."
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

    @property
    def gate_threshold(self) -> Optional[str]:
        """The threshold this project's verdict must actually be judged against.

        One accessor rather than each call site choosing, because a call site
        that reads ``severity_threshold`` directly silently ignores the workspace
        ceiling -- the ceiling would appear in the plan and in ``--dry-run`` while
        changing no verdict, which is worse than not having it.

        Falls back to ``severity_threshold`` when the effective value was never
        computed. That happens for plans not built by ``resolve_workspace`` --
        which this module's docstring says can exist -- and for skipped projects.
        The fallback is not a silent default: when policy HAS been applied the
        effective value is always set, equal to the declared one where the
        ceiling did not bite. Returning ``None`` instead would turn the gate off
        for those plans, which is the one failure direction that must not happen.
        """
        if self.effective_severity_threshold is not None:
            return self.effective_severity_threshold
        return self.severity_threshold

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
    workspace_config_source: Annotated[
        Optional[str],
        Field(
            None,
            description=(
                "Path of the workspace policy file that was applied, or null when "
                "the workspace declares no policy. Recorded because a ceiling "
                "changes verdicts, so which file imposed it has to be answerable "
                "from the output rather than by re-running discovery."
            ),
        ),
    ] = None

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
        ]
        # Only shown when there is policy. A "policy: none" line on every plan
        # would train the reader to skip the line that matters.
        if self.workspace_config_source:
            lines.append(
                f"{_INDENT}{'policy:':<{_FIELD_WIDTH}}{self.workspace_config_source}"
            )
        lines.append("")

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
            # Both values when policy moved the threshold, so the reader can see
            # what was declared and what will be enforced. One value otherwise:
            # printing "CRITICAL -> CRITICAL" everywhere would bury the real cases.
            declared = project.severity_threshold or "none"
            if project.threshold_tightened_by_policy:
                effective = project.effective_severity_threshold or "none"
                lines.append(
                    f"{_INDENT}{'threshold:':<{_FIELD_WIDTH}}"
                    f"{effective}  (workspace policy tightened {declared})"
                )
            else:
                lines.append(f"{_INDENT}{'threshold:':<{_FIELD_WIDTH}}{declared}")
            lines.append(
                f"{_INDENT}{'scanners:':<{_FIELD_WIDTH}}"
                f"{', '.join(project.scanners) or 'none enabled'}"
            )
            if project.policy_scanners:
                gating = "gating" if project.policy_scanners_gate else "not gating"
                lines.append(
                    f"{_INDENT}{'+policy:':<{_FIELD_WIDTH}}"
                    f"{', '.join(project.policy_scanners)} ({gating})"
                )
            if project.policy_suppressions or project.policy_ignore_paths:
                lines.append(
                    f"{_INDENT}{'policy:':<{_FIELD_WIDTH}}"
                    f"{len(project.policy_suppressions)} suppression(s), "
                    f"{len(project.policy_ignore_paths)} ignore path(s)"
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
