# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Turn a workspace definition into a validated execution plan, or refuse it.

Why this module exists
----------------------
Between "the operator named a workspace file" and "N scans run" sits a set of
decisions that can each go wrong quietly: which directories are really projects,
whether any of them escapes the tree the operator authorised, whether two of them
are the same directory under different names, what each one is called in output,
and whether their configs demand tool versions that cannot coexist. Making those
decisions in one pass, before anything executes, is what lets ``--dry-run``
exist and what keeps the failure modes in one place instead of spread across the
execution path.

Fail-closed, and why that is not the obvious choice
--------------------------------------------------
An earlier draft of this design had a missing project warn and skip. That is
fail-OPEN, and it fails in the worst available direction for a security tool: a
typo in the workspace file, or a repository that was never cloned on this runner,
means a project is not scanned, ASH exits 0, and CI goes green. Worse, the other
projects' passing results supply the reassurance -- the output looks like a
successful multi-project scan, just with one fewer project than the operator
believes. Nobody reads a warning in a green build.

So the default is refusal, and it is refusal for the whole workspace rather than
for the offending project, because a partial scan is exactly the outcome above.
``--allow-missing-projects`` exists for the legitimate case (a workspace shared
between developers who clone different subsets), and when it is used the skip is
recorded in the plan payload rather than only logged: a downstream consumer
reading results cannot see stderr.

The opt-out is deliberately narrow. It covers a project that is absent or
unreadable -- facts about this machine. It does not cover a path that escapes the
workspace root, is a symlink, overlaps another entry, or collides on its key,
because those are facts about the definition and are wrong on every machine.

Order of checks, which is load-bearing
--------------------------------------
1. Parse the definition. A malformed file has no entries to check.
2. Containment, via :mod:`automated_security_helper.utils.path_containment`. No
   opt-out.
3. Reject an entry naming the workspace root itself.
4. Overlap, on canonicalised real paths. No opt-out.
5. Key uniqueness. No opt-out.
6. Existence and readability. This is the opt-out-able step, and it comes last of
   the path checks so that a symlinked or escaping entry is reported as such
   rather than as merely missing.
7. Refuse if nothing is left to scan.
8. Resolve each project's config independently.
9. Compare scanner pins across the projects that will actually run.

Steps 2 to 6 each collect every offending entry before raising, so an operator
with three bad entries fixes three in one pass instead of one per run.

Why an entry naming the workspace root is refused
-------------------------------------------------
The spec settles the case where ``.`` appears alongside another entry -- it
overlaps everything below it -- but not the case where it is the only entry. Two
readings were available. Taking the relative path literally makes the project key
``.``, which then appears in output paths; inventing a key from the root
directory's name invents a name the definition never stated. Neither is
defensible, and the case is degenerate anyway: a workspace whose only project is
the workspace root is a single-directory scan, which ``--source-dir`` already
does. So it is refused, with a message that says so.

Why overlaps are refused rather than de-duplicated
--------------------------------------------------
Two entries resolving to one real directory would have that directory's findings
attributed twice and its suppressions applied twice, and would produce two
projects with the same key writing to the same output path. De-duplicating would
silently change what the operator asked for. Note that overlap is judged on
resolved real paths, which is what catches an alias: Phase 0's containment check
accepts ``alias/sub`` when only ``alias`` is a symlink, and comparing real paths
is the only thing that notices it is the same directory as ``api/sub``. A nested
git repository or submodule inside a project is not an overlap unless it is also
listed as its own entry.

Why key collisions are refused
------------------------------
Replacing separators with dashes is not injective. ``a/b`` and a directory
literally named ``a-b`` both key to ``a-b``, so "unique by construction" does not
hold once overlaps are excluded. Two projects sharing a key would share an output
path, so the collision is refused, naming both paths.

Nothing may escape as anything but a workspace error
----------------------------------------------------
Folder entries are untrusted text from a file, handed to pathlib. Which inputs
pathlib refuses, and with which exception type, has changed across the Python
versions this project supports (3.10 through 3.13) -- a null byte, for instance,
raised ``ValueError`` straight out of ``os.lstat``, escaped uncaught, and turned
a malformed workspace file into a traceback and exit 1 rather than exit 4. So the
containment call is wrapped, and any ``OSError`` or ``ValueError`` from it becomes
a named entry in the exit-4 list. Only the exception's type is reported, never its
message, because the message is the platform's wording and differs by version.

The wrap is a net, not the mechanism: inputs known to be unusable are rejected
from their raw text in
:mod:`automated_security_helper.workspace.workspace_file`, where the verdict does
not depend on the interpreter at all.

Failure modes and known limitations
-----------------------------------
* Validation is point-in-time. Every path is checked here and used later; a
  directory can be replaced by a symlink in between. This module cannot close
  that window, and does not pretend to.
* An unreadable project is detected with ``os.access``, which consults the real
  uid rather than the effective one and which a root user always satisfies. A
  process that can read the directory but not its contents is reported as
  readable, and the failure surfaces during the scan instead.
* Scanner pins are compared as *effective* values, including the constraint a
  scanner plugin declares as its own default. That is deliberate: bandit's
  built-in ``>=1.7.0,<2.0.0`` really does constrain a project that never
  mentioned bandit, so a sibling pinning ``>=2.0.0`` really is a conflict. Since
  the default is identical for every project it can never manufacture one.
* Pins are compared pairwise. With three projects the message names the pairs
  that clash, not a minimal explanation of the whole clash.
* A project's config is loaded to read its scanner set and threshold. That runs
  the ordinary config-resolution path, so a config that emits resolution warnings
  emits them here too, during what the operator asked to be a dry run.
"""

from __future__ import annotations

import os
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import (
    find_config_file,
    resolve_config,
)
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    WorkspaceDefinitionError,
)
from automated_security_helper.models.workspace import SkippedProjectReason
from automated_security_helper.utils.path_containment import validate_contained_path
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from automated_security_helper.workspace.policy import (
    policy_for_project,
    resolve_workspace_policy,
)
from automated_security_helper.workspace.scanner_pins import PinVerdict, compare_pins
from automated_security_helper.workspace.workspace_file import (
    WorkspaceDefinition,
    load_workspace_file,
)

PathLike = Union[str, Path]

#: Separator used to turn a workspace-relative path into a project key.
KEY_SEPARATOR = "-"


class _Candidate:
    """A folder entry part-way through resolution.

    Mutable and internal: resolution fills fields in as each check passes, and
    the immutable :class:`ProjectPlan` is built from it at the end.
    """

    __slots__ = ("entry", "resolved", "relative", "key", "skip_reason", "skip_detail")

    def __init__(self, entry: str, resolved: Path, relative: Path, key: str) -> None:
        self.entry = entry
        self.resolved = resolved
        self.relative = relative
        self.key = key
        self.skip_reason: Optional[SkippedProjectReason] = None
        self.skip_detail: Optional[str] = None

    @property
    def skipped(self) -> bool:
        return self.skip_reason is not None


def _refuse(headline: str, problems: List[str]) -> WorkspaceDefinitionError:
    """Build a refusal naming every problem, not just the first."""
    joined = "\n  - ".join(problems)
    return WorkspaceDefinitionError(f"{headline}\n  - {joined}")


def _field(container: Any, name: str, default: Any = None) -> Any:
    """Read *name* from a pydantic model or from a plain dict.

    Scanner entries arrive either as typed config models or, for a
    plugin-provided scanner, as whatever landed in ``__pydantic_extra__`` -- which
    is a dict. Both shapes have to be readable without the caller caring which it
    got.
    """
    if isinstance(container, dict):
        return container.get(name, default)
    return getattr(container, name, default)


def _scanner_display_name(field_name: str, config: AshConfig) -> str:
    """The name an operator would type for a scanner config field.

    Prefers the field's declared alias (``cdk-nag``) over the Python field name
    (``cdk_nag``), because the alias is what ``--scanners`` and the config file
    accept.
    """
    field_info = type(config.scanners).model_fields.get(field_name)
    if field_info is not None and field_info.alias:
        return field_info.alias
    return field_name.replace("_", "-")


def _scanner_state(config: AshConfig) -> Tuple[List[str], Dict[str, str]]:
    """Return the project's enabled scanner names and its effective pins.

    Walks the declared fields and then anything a plugin contributed via
    ``extra="allow"``, so a scanner ASH does not ship is still accounted for.
    """
    segment = config.scanners
    declared = list(type(segment).model_fields.keys())
    extra = list(getattr(segment, "__pydantic_extra__", None) or {})

    enabled: List[str] = []
    pins: Dict[str, str] = {}

    for field_name in declared + [name for name in extra if name not in declared]:
        entry = _field(segment, field_name)
        if entry is None:
            continue
        name = (
            _scanner_display_name(field_name, config)
            if field_name in declared
            else field_name
        )
        if _field(entry, "enabled", True):
            enabled.append(name)
        pin = _field(_field(entry, "options"), "tool_version")
        if isinstance(pin, str) and pin.strip():
            pins[name] = pin
    return sorted(enabled), pins


def _project_label(config: AshConfig, key: str) -> str:
    """The project's display label.

    ``AshConfig.project_name`` is never absent -- it defaults to ``ash-scan``, or
    to ``ASH_PROJECT_NAME`` when that is set -- so "when present" cannot mean
    "the field is set". It has to mean "the project's config declared one", which
    is decided by comparing against the field's own default rather than against a
    hardcoded string, so the comparison follows the environment variable.

    A project that genuinely sets ``project_name`` to the default value is
    treated as not having declared one. The consequence is that its label is its
    key, which is what it would have been anyway.
    """
    default = AshConfig.model_fields["project_name"].default
    declared = getattr(config, "project_name", None)
    if isinstance(declared, str) and declared.strip() and declared != default:
        return declared
    return key


def _validate_containment(
    definition: WorkspaceDefinition,
) -> List[_Candidate]:
    """Run Phase 0's containment check over every entry, collecting rejections."""
    problems: List[str] = []
    candidates: List[_Candidate] = []

    for folder in definition.folders:
        try:
            result = validate_contained_path(folder.path, definition.root)
        except (OSError, ValueError) as exc:
            # Folder entries are untrusted text handed to pathlib, and which
            # inputs pathlib refuses -- and with what exception type -- has
            # changed between the Python versions this project supports. Any
            # surprise has to land on exit 4 naming the entry rather than as a
            # traceback and exit 1. Only the exception's type is reported: its
            # message is the platform's wording and differs across versions.
            problems.append(
                f"'{folder.path}' could not be resolved as a path "
                f"({type(exc).__name__} from the filesystem layer)"
            )
            continue
        if not result.ok:
            # Parentheses, not brackets: these messages are echoed by callers
            # that may render Rich markup, where '[outside-root]' would be read
            # as a style name and fail at render time.
            problems.append(f"{result.error.message} ({result.error.violation.value})")
            continue
        resolved = result.resolved
        relative = resolved.relative_to(definition.root)
        if not relative.parts:
            # The entry names the workspace root. See the module docstring.
            problems.append(
                f"'{folder.path}' names the workspace root itself. A workspace "
                f"project must be a directory below the root; to scan a single "
                f"directory use '--source-dir' instead of '--workspace'."
            )
            continue
        candidates.append(
            _Candidate(
                entry=folder.path,
                resolved=resolved,
                relative=relative,
                key=KEY_SEPARATOR.join(relative.parts),
            )
        )

    if problems:
        raise _refuse(
            f"Workspace '{definition.path.as_posix()}' lists folder entries that "
            f"cannot be used:",
            problems,
        )
    return candidates


def _validate_no_overlap(
    definition: WorkspaceDefinition, candidates: List[_Candidate]
) -> None:
    """Reject entries that are the same directory, or nested one inside another.

    Compares canonicalised real paths, which is what catches a symlink alias that
    containment validation accepts.
    """
    problems: List[str] = []
    for first, second in combinations(candidates, 2):
        if first.resolved == second.resolved:
            problems.append(
                f"'{first.entry}' and '{second.entry}' resolve to the same "
                f"directory '{first.resolved.as_posix()}'; findings would be "
                f"attributed twice and suppressions applied twice"
            )
        elif second.resolved.is_relative_to(first.resolved):
            problems.append(
                f"'{second.entry}' is inside '{first.entry}' "
                f"('{second.resolved.as_posix()}' is below "
                f"'{first.resolved.as_posix()}'); overlapping projects would be "
                f"scanned twice"
            )
        elif first.resolved.is_relative_to(second.resolved):
            problems.append(
                f"'{first.entry}' is inside '{second.entry}' "
                f"('{first.resolved.as_posix()}' is below "
                f"'{second.resolved.as_posix()}'); overlapping projects would be "
                f"scanned twice"
            )

    if problems:
        raise _refuse(
            f"Workspace '{definition.path.as_posix()}' has overlapping folder entries:",
            problems,
        )


def _validate_unique_keys(
    definition: WorkspaceDefinition, candidates: List[_Candidate]
) -> None:
    """Reject two distinct projects that would share a project key."""
    by_key: Dict[str, List[_Candidate]] = {}
    for candidate in candidates:
        by_key.setdefault(candidate.key, []).append(candidate)

    problems: List[str] = []
    for key, group in by_key.items():
        if len(group) < 2:
            continue
        listed = ", ".join(f"'{member.relative.as_posix()}'" for member in group)
        problems.append(
            f"{listed} all reduce to the same project key '{key}', so they "
            f"would share an output path"
        )

    if problems:
        raise _refuse(
            f"Workspace '{definition.path.as_posix()}' has colliding project keys:",
            problems,
        )


def _apply_existence_checks(
    definition: WorkspaceDefinition,
    candidates: List[_Candidate],
    allow_missing_projects: bool,
) -> None:
    """Mark or reject entries that do not exist or cannot be read.

    This is the only check ``--allow-missing-projects`` opts out of, and the opt
    out marks the project skipped rather than dropping it, so the plan still
    accounts for every entry in the definition.
    """
    problems: List[str] = []
    for candidate in candidates:
        if not candidate.resolved.is_dir():
            detail = (
                f"'{candidate.entry}' does not exist as a directory at "
                f"'{candidate.resolved.as_posix()}'"
            )
        elif not os.access(candidate.resolved, os.R_OK | os.X_OK):
            detail = (
                f"'{candidate.entry}' at '{candidate.resolved.as_posix()}' is "
                f"not readable by this process"
            )
        else:
            continue

        if allow_missing_projects:
            candidate.skip_reason = SkippedProjectReason.ERROR
            candidate.skip_detail = detail
        else:
            problems.append(detail)

    if problems:
        raise _refuse(
            f"Workspace '{definition.path.as_posix()}' names projects that "
            f"cannot be scanned. Nothing was scanned, because scanning the rest "
            f"and exiting 0 would report a clean result for code that was never "
            f"examined. Pass '--allow-missing-projects' to skip them instead:",
            problems,
        )


def _resolve_project_config(
    candidate: _Candidate,
    config_overrides: Tuple[str, ...] = (),
) -> Tuple[AshConfig, Optional[Path]]:
    """Load one project's config through ASH's ordinary resolution path.

    The config file is located once and passed back in, rather than letting
    resolution search again, so the file the plan reports is definitionally the
    file that was loaded and the two cannot disagree.

    Why the CLI overrides are applied HERE
    -------------------------------------
    They decide what the project *declares*. Under the settled precedence rule
    ``declared(P)`` is the override value when one is present and the project's
    own config value otherwise, and ``effective(P)`` is
    ``stricter_of(declared(P), ceiling)``. Both ``severity_threshold`` and the
    policy composition that reads it are computed at resolution time, so an
    override arriving only at execution time would leave the plan -- and
    therefore ``--dry-run`` -- reporting a threshold that is not the one enforced.

    Returns:
        The resolved config, and the config file it came from -- ``None`` when the
        project has none and took ASH's default config.

    Raises:
        ASHConfigValidationError: When the project's own config is invalid, or an
            override cannot be applied to it. An unusable override is fatal here
            rather than dropped, which is what ``apply_config_overrides`` raising
            now makes possible. Left
            as this type, not wrapped as a workspace error, because it maps to a
            different exit code (3, not 2) and routes to a different person. The
            message is re-issued with the project key so the operator knows which
            of N projects to look at.
    """
    config_path = find_config_file(candidate.resolved)
    try:
        config = resolve_config(
            config_path=config_path,
            source_dir=candidate.resolved,
            fallback_to_default=True,
            config_overrides=list(config_overrides),
        )
        return config, config_path
    except ASHConfigValidationError as exc:
        raise ASHConfigValidationError(
            f"Project '{candidate.key}' at '{candidate.resolved.as_posix()}' has "
            f"an invalid configuration: {exc}"
        ) from exc


def _validate_scanner_pins(
    definition: WorkspaceDefinition, projects: List[ProjectPlan]
) -> None:
    """Refuse a workspace whose projects demand irreconcilable tool versions.

    Only projects that will actually be scanned are compared: a skipped project
    cannot conflict with one that runs.

    An undecidable comparison is refused alongside an incompatible one. Assuming
    compatibility would mean a project could be scanned by a tool version it
    excluded, and the exclusion is usually there because that version was known
    to miss something.
    """
    by_scanner: Dict[str, Dict[str, List[str]]] = {}
    for project in projects:
        for scanner, pin in project.scanner_pins.items():
            by_scanner.setdefault(scanner, {}).setdefault(pin, []).append(project.key)

    problems: List[str] = []
    for scanner, by_pin in sorted(by_scanner.items()):
        for first_pin, second_pin in combinations(sorted(by_pin), 2):
            verdict = compare_pins(first_pin, second_pin)
            if verdict is PinVerdict.COMPATIBLE:
                continue
            explanation = (
                "no version satisfies both"
                if verdict is PinVerdict.INCOMPATIBLE
                else "ASH cannot prove any version satisfies both"
            )
            problems.append(
                f"scanner '{scanner}': "
                f"'{first_pin}' (required by "
                f"{', '.join(sorted(by_pin[first_pin]))}) and "
                f"'{second_pin}' (required by "
                f"{', '.join(sorted(by_pin[second_pin]))}) -- {explanation}"
            )

    if problems:
        raise _refuse(
            f"Workspace '{definition.path.as_posix()}' cannot be scanned: its "
            f"projects pin incompatible scanner tool versions. One ASH run "
            f"installs one version of each tool, and per-project tool isolation "
            f"is not supported, so scanning would silently ignore one project's "
            f"constraint. Reconcile the pins, or scan the projects separately:",
            problems,
        )


def _project_plugin_modules(config: AshConfig) -> List[str]:
    """The plugin modules a project's config asks for, split and normalised.

    Split on commas because ``ScanExecutionEngine`` does the same before loading
    them, so ``["a,b"]`` and ``["a", "b"]`` are the same request and must not
    read as a conflict. Sorted and de-duplicated for the same reason: order and
    repetition do not change which plugins get registered.
    """
    declared = getattr(config, "ash_plugin_modules", None) or []
    return sorted(
        {
            part.strip()
            for entry in declared
            if entry is not None
            for part in str(entry).split(",")
            if part.strip()
        }
    )


def _validate_plugin_modules(
    definition: WorkspaceDefinition, projects: List[ProjectPlan]
) -> None:
    """Refuse a workspace whose projects ask for different plugin module sets.

    Why this is a refusal and not a merge
    -------------------------------------
    Plugin registration is process-global.
    ``ScanExecutionEngine.__init__`` reads *the project's own*
    ``ash_plugin_modules`` and registers them into the module-level
    ``plugin_library``, then reads the scanner set back through
    ``ash_plugin_manager.plugin_modules()``, which memoises into
    ``_resolved_plugins``. So the first project to build its engine decides the
    scanner set for every project in the run, and measured on two real projects
    neither ordering is correct:

    * project-without-the-plugin first -- the project that DECLARED it loses it.
      A silent false negative: fewer findings than ``ash --source-dir`` would
      report, with no warning anywhere.
    * project-with-the-plugin first -- the other project gains a scanner it never
      declared.

    Merging the sets would make the second case the defined behaviour for
    everyone, which is the wrong direction for a security tool: a project would
    be scanned by plugins its operator did not choose, and an operator who
    deliberately keeps a noisy or slow plugin out of one project has that
    decision silently reversed. Refusing costs an error message they can act on.

    This is the same call the RFC already makes for irreconcilable scanner
    version pins, and for the same reason, so the two refusals are shaped alike.

    Per-execution scoping of the registry is the real fix and is deliberately not
    attempted here: ``plugin_library`` and ``_resolved_plugins`` predate this
    feature and every single-directory scan depends on them.

    Only projects that will actually be scanned are compared; a skipped project
    cannot conflict with one that runs.
    """
    by_modules: Dict[Tuple[str, ...], List[str]] = {}
    for project in projects:
        by_modules.setdefault(tuple(project.ash_plugin_modules), []).append(project.key)

    if len(by_modules) <= 1:
        return

    problems = [
        f"{', '.join(sorted(keys))}: "
        + (", ".join(modules) if modules else "no plugin modules")
        for modules, keys in sorted(by_modules.items())
    ]
    raise _refuse(
        f"Workspace '{definition.path.as_posix()}' cannot be scanned: its "
        f"projects ask for different 'ash_plugin_modules'. Plugin registration "
        f"is process-global, so one run registers one set -- whichever project "
        f"resolves first would decide it for all of them, either dropping a "
        f"plugin a project declared or applying one it did not. Give every "
        f"project the same list, or scan them separately:",
        problems,
    )


def _assign_display_labels(projects: List[ProjectPlan]) -> None:
    """Decorate a label with its project key when a sibling shares the label.

    Two projects may legitimately carry the same ``project_name``, so the label
    is never a uniqueness key. Decorating only the ambiguous ones keeps the
    common case readable.
    """
    counts: Dict[str, int] = {}
    for project in projects:
        counts[project.label] = counts.get(project.label, 0) + 1
    for project in projects:
        project.display_label = (
            f"{project.label} ({project.key})"
            if counts[project.label] > 1
            else project.label
        )


def _apply_workspace_policy(
    definition: WorkspaceDefinition,
    projects: List[ProjectPlan],
    workspace_config: Optional[PathLike],
) -> Optional[Path]:
    """Resolve the workspace policy and fold it into every active project.

    Runs AFTER the per-project configs are resolved, because the ceiling needs
    each project's own threshold to combine with and the scanner classification
    needs each project's scanner set. It runs after ``_validate_scanner_pins``
    and ``_validate_plugin_modules`` too: a workspace that cannot be scanned at
    all should say so rather than first complaining about a policy pattern.

    Skipped projects are left alone. Applying a ceiling to a project that will
    not be scanned would put a threshold in the plan for work that never
    happens, and pushing a pattern into it could refuse the whole workspace over
    a project nobody is looking at.

    Returns:
        The policy file that was applied, or ``None`` when there is no policy.

    Raises:
        WorkspaceDefinitionError: Exit code 4, for an unusable policy file or a
            pattern with no sound rewrite for some project. The message names the
            project as well as the pattern, because a workspace-level pattern is
            legal in itself and only fails in combination with one project.
    """
    policy, source = resolve_workspace_policy(
        definition.root,
        explicit=workspace_config,
        project_config_paths=[
            Path(project.config_source) for project in projects if project.config_source
        ],
    )

    for project in projects:
        if project.skipped:
            continue
        resolved = policy_for_project(
            policy.workspace if policy else None,
            project_prefix=project.relative_path,
            project_threshold=project.severity_threshold,
            project_scanners=project.scanners,
        )
        project.effective_severity_threshold = resolved.effective_threshold
        project.threshold_tightened_by_policy = resolved.threshold_tightened
        project.policy_suppressions = list(resolved.suppressions)
        project.policy_ignore_paths = list(resolved.ignore_paths)
        project.policy_scanners = list(resolved.policy_scanners)
        project.policy_scanners_gate = resolved.policy_scanners_gate

    return source


def resolve_workspace(
    workspace_file: PathLike,
    *,
    allow_missing_projects: bool = False,
    workspace_config: Optional[PathLike] = None,
    config_overrides: Tuple[str, ...] = (),
) -> WorkspacePlan:
    """Resolve and validate a workspace, returning an inspectable plan.

    Scans nothing. Reads the workspace definition and each project's config, and
    either returns a plan describing what would run or raises.

    Args:
        workspace_file: Path to the ``.code-workspace`` definition.
        allow_missing_projects: Opt out of failing when a project directory is
            absent or unreadable. Those projects are marked skipped and recorded
            in the plan's ``skipped_projects`` payload. Does not opt out of any
            other check -- see "Fail-closed" in the module docstring.
        config_overrides: ``--config-overrides`` values, including any the CLI
            synthesised. Applied to each project's config here, so a threshold
            override changes what the project DECLARES and the workspace ceiling
            is then applied to that. Passing these only to execution would leave
            the plan, and therefore ``--dry-run``, reporting a threshold
            different from the one enforced -- and the RFC's carve-out for a
            workspace overriding a project is conditioned on that override being
            visible.
        workspace_config: ``--workspace-config``: the workspace policy file to
            apply. When omitted the workspace root is searched for one, and
            having none is not an error. When given it must exist; ASH does not
            fall back to searching, because that would apply different policy
            than the one named. It may not be any project's own config.

    Returns:
        A :class:`~automated_security_helper.workspace.plan.WorkspacePlan` with
        one entry per folder in the definition, skipped ones included.

    Raises:
        WorkspaceDefinitionError: Exit code 4. The definition is malformed, or an
            entry escapes the workspace root, is a symlink, names the root, does
            not exist, is unreadable, overlaps another entry, collides on its
            key, or pins a scanner version irreconcilable with another project's.
            The message names every offending entry.
        ASHConfigValidationError: Exit code 3. The workspace is fine but one
            project's own config is invalid. The message names the project.
    """
    definition = load_workspace_file(workspace_file)

    candidates = _validate_containment(definition)
    _validate_no_overlap(definition, candidates)
    _validate_unique_keys(definition, candidates)
    _apply_existence_checks(definition, candidates, allow_missing_projects)

    if all(candidate.skipped for candidate in candidates):
        raise WorkspaceDefinitionError(
            f"Workspace '{definition.path.as_posix()}' has no project left to "
            f"scan: every folder it lists was skipped. Exiting 0 here would "
            f"report a clean result for a workspace nothing examined."
        )

    projects: List[ProjectPlan] = []
    for candidate in candidates:
        if candidate.skipped:
            projects.append(
                ProjectPlan(
                    key=candidate.key,
                    relative_path=candidate.relative.as_posix(),
                    path=candidate.resolved.as_posix(),
                    label=candidate.key,
                    display_label=candidate.key,
                    skipped=True,
                    skip_reason=candidate.skip_reason,
                    skip_detail=candidate.skip_detail,
                )
            )
            continue

        config, config_path = _resolve_project_config(candidate, config_overrides)
        scanners, pins = _scanner_state(config)
        label = _project_label(config, candidate.key)
        projects.append(
            ProjectPlan(
                key=candidate.key,
                relative_path=candidate.relative.as_posix(),
                path=candidate.resolved.as_posix(),
                label=label,
                # Settled below by _assign_display_labels, which needs the whole
                # sibling set to know whether this label is ambiguous.
                display_label=label,
                config_source=config_path.resolve().as_posix() if config_path else None,
                scanners=scanners,
                severity_threshold=config.global_settings.severity_threshold,
                scanner_pins=pins,
                ash_plugin_modules=_project_plugin_modules(config),
            )
        )

    active = [project for project in projects if not project.skipped]
    _validate_scanner_pins(definition, active)
    _validate_plugin_modules(definition, active)
    _assign_display_labels(projects)
    policy_source = _apply_workspace_policy(definition, projects, workspace_config)

    return WorkspacePlan(
        workspace_file=definition.path.as_posix(),
        workspace_root=definition.root.as_posix(),
        workspace_config_source=(
            policy_source.as_posix() if policy_source is not None else None
        ),
        projects=projects,
        allow_missing_projects=allow_missing_projects,
    )
