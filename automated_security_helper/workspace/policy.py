# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Find the workspace policy file, and push its policy down into one project.

Why this module exists
----------------------
``config/ash_workspace_config.py`` says what workspace policy IS; this module
decides which file carries it and what it means for a given project. Those are
separate jobs because the second one needs the project list and the filesystem,
and because every judgement here can change a project's verdict and so wants its
reasoning written down next to it.

Two things happen here, and they fail in opposite directions
------------------------------------------------------------
1. **Resolution** -- locate and parse the policy file. Everything is refused
   with :class:`WorkspaceDefinitionError` (exit 4), because a policy file that
   cannot be read is a policy that cannot be applied, and applying no policy
   while the operator believes a ceiling is in force is a fail-open outcome.
   The one non-refusal is a policy file that is simply absent: workspace policy
   is opt-in, so its absence is the Phase 2b behaviour and not an error.
2. **Push-down** -- rewrite the policy for one project. Here a pattern that
   cannot match inside the project is DROPPED for that project rather than
   refused, because it is legitimately about a different project. A pattern that
   has no sound rewrite is refused, because silently dropping it would leave the
   operator's stated suppression unapplied with nothing in the output to say so.

Why the policy file cannot be a project's config
------------------------------------------------
A workspace root is often also a project, and then ``.ash/ash.yaml`` there is
that project's config. Reading it as workspace policy would promote one
project's ``severity_threshold`` into its siblings' ceiling, silently, from a
file whose author expected project scope.

Two mechanisms keep that from happening, and the second exists because the first
is not sufficient:

* ``WORKSPACE_POLICY_FILE_NAMES`` is disjoint from ``ASH_CONFIG_FILE_NAMES``, so
  *discovery* can never land on a project config. A test asserts the
  disjointness rather than trusting it to stay true.
* ``--workspace-config`` can name any path, so discovery's guarantee does not
  cover it. An explicit file is checked by RESOLVED IDENTITY against each
  project's config path, not by filename, so a symlink or a ``./`` -prefixed
  spelling of the same file is caught too. This mirrors the resolver's overlap
  check, which compares real paths for the same reason.

Ambiguity is refused, never ranked
----------------------------------
Two candidate policy files in one workspace is an error listing both. Picking by
sort order or mtime would mean the effective ceiling changes when an operator
adds a file they thought was inert -- and a ceiling that moves on its own is
worse than no ceiling, because it is believed.

What the ceiling can and cannot reach
-------------------------------------
``effective_threshold`` is ``stricter_of(project, ceiling)``, so a stricter
project is untouched and a looser one is tightened. That composition is correct
for every finding that carries ``properties.issue_severity``.

It cannot tighten a finding that carries only a SARIF ``error`` level. Both
ASH threshold gates map ``error`` to CRITICAL -- ``severity_ladder`` and
``run_ash_scan``'s ``_THRESHOLD_QUALIFYING_LEVELS``, which agree over all 120
level/severity/threshold combinations -- and CRITICAL is actionable at every
threshold, including CRITICAL. So for such findings no threshold has ever
changed anything, in workspace mode or single-project mode. checkov is the
scanner ASH ships that omits ``issue_severity``.

That was left as-is rather than remapped, deliberately. Remapping ``error`` to
HIGH in ``severity_ladder`` alone was measured to break the central invariant at
exactly one cell -- a level-only ``error`` at a CRITICAL threshold, which
single-project mode calls actionable and workspace mode would not -- and it
breaks it in the loosening direction, which is the one that hides findings.
Remapping both gates instead keeps them consistent but silently stops failing
CRITICAL-threshold single-project scans on ``error`` findings, a change to
published exit-code behaviour well outside a workspace feature. Deriving
``issue_severity`` for checkov has no source data: ASH reads checkov's SARIF
verbatim and checkov does not emit severity.

``threshold_tightened`` records whether the ceiling actually moved this project,
so a reporter can say where policy took effect instead of leaving the operator
to diff two numbers.

Failure modes and known limitations
-----------------------------------
* Resolution is a point-in-time read; the file can change before the scan.
* ``policy_scanners`` is computed by comparing normalised scanner names
  (lower-cased, ``-`` and ``_`` folded together), because ``--scanners`` and the
  config accept ``cdk-nag`` while the Python field is ``cdk_nag``. Treating
  those as two scanners would run a second copy under default config and report
  its findings as policy-origin duplicates of the project's own.
* A policy suppression is pushed down per project, so one workspace-level entry
  can become N project-level entries. Each is a copy: mutating in place would
  leave the second project rewriting the first project's already-rewritten path.
* ``additional_scanners`` is not validated against the set of scanners ASH knows
  about. A typo therefore surfaces when execution cannot find the scanner rather
  than at policy-resolution time. Validating here would need the plugin registry,
  which is not loaded at resolution and whose contents depend on each project's
  ``ash_plugin_modules``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from automated_security_helper.config.ash_workspace_config import (
    AshWorkspaceConfig,
    WorkspacePolicyConfig,
)
from automated_security_helper.core.exceptions import (
    WorkspaceDefinitionError,
    WorkspacePatternError,
)
from automated_security_helper.models.core import (
    AshSuppression,
    IgnorePathWithReason,
)
from automated_security_helper.utils.severity_ladder import stricter_of
from automated_security_helper.utils.workspace_paths import to_project_pattern

# Written as `str | Path` rather than `Union[...]` -- evaluated eagerly at import,
# and PEP 604 unions are runtime-valid from 3.10, this project's floor.
PathLike = str | Path

#: Names a workspace policy file may take. Deliberately disjoint from
#: ``ASH_CONFIG_FILE_NAMES`` -- see "Why the policy file cannot be a project's
#: config" in the module docstring.
WORKSPACE_POLICY_FILE_NAMES: list[str] = [
    ".ash-workspace.yml",
    ".ash-workspace.yaml",
    ".ash-workspace.json",
    "ash-workspace.yml",
    "ash-workspace.yaml",
    "ash-workspace.json",
]

#: Subdirectory of the workspace root also searched, matching where project
#: configs may live so an operator keeps one habit for both.
_POLICY_SUBDIR = ".ash"


@dataclass(frozen=True)
class ProjectPolicy:
    """Workspace policy as it applies to ONE project.

    Attributes:
        effective_threshold: ``stricter_of(project, ceiling)``. ``None`` when
            neither side configures a threshold, which means the gate is off --
            not a synonym for CRITICAL. See ``severity_ladder``.
        threshold_tightened: Whether the ceiling changed this project's
            threshold. Recorded rather than re-derived so a reporter can state
            where policy took effect without comparing two values itself.
        suppressions: Workspace suppressions rewritten into this project's
            coordinates. Only those that can match inside it.
        ignore_paths: The same, for ``ignore_paths``.
        policy_scanners: Scanners this policy adds that the project does not
            already declare. These run with default config and their findings
            are tagged ``origin: workspace-policy``.
        policy_scanners_gate: Whether those findings affect the project's exit
            code. Carried per project so a caller never has to reach back into
            the policy to interpret ``policy_scanners``.
    """

    effective_threshold: str | None
    threshold_tightened: bool
    suppressions: tuple[AshSuppression, ...]
    ignore_paths: tuple[IgnorePathWithReason, ...]
    policy_scanners: tuple[str, ...]
    policy_scanners_gate: bool


def _refuse(message: str) -> WorkspaceDefinitionError:
    return WorkspaceDefinitionError(message)


def _normalise_scanner_name(name: str) -> str:
    """Fold a scanner name to the form used for comparison.

    ``cdk-nag`` and ``cdk_nag`` are one scanner: the former is what
    ``--scanners`` and the config file accept, the latter is the Python field
    name. Comparing raw strings would make policy add a duplicate.
    """
    return name.strip().lower().replace("-", "_")


def _read_policy_document(path: Path) -> object:
    """Parse the policy file, refusing anything unreadable.

    Uses ``yaml.safe_load`` rather than ``AshConfig``'s ``!ENV``-aware loader.
    See "No ``!ENV`` substitution" in ``config/ash_workspace_config.py``: a
    ceiling an environment variable can loosen is not a ceiling.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise _refuse(
            f"workspace policy file '{path.as_posix()}' could not be read: {exc}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise _refuse(
            f"workspace policy file '{path.as_posix()}' is not valid UTF-8: {exc}"
        ) from exc

    try:
        if path.suffix.lower() == ".json":
            return json.loads(raw)
        return yaml.safe_load(raw)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise _refuse(
            f"workspace policy file '{path.as_posix()}' could not be parsed: {exc}"
        ) from exc


def load_workspace_policy(path: PathLike) -> AshWorkspaceConfig:
    """Parse and validate the policy file at *path*.

    Args:
        path: The policy file. Must exist.

    Returns:
        The validated policy.

    Raises:
        WorkspaceDefinitionError: Exit code 4, for every unusable file -- absent,
            unreadable, unparseable, not a mapping, or failing the schema. The
            message names the file, because a workspace may have several config
            files and "validation error" alone does not say which to open.
    """
    resolved = Path(path)
    if not resolved.exists():
        raise _refuse(f"workspace policy file '{resolved.as_posix()}' does not exist")
    if not resolved.is_file():
        raise _refuse(f"workspace policy file '{resolved.as_posix()}' is not a file")

    resolved = resolved.resolve()
    document = _read_policy_document(resolved)

    # An empty file parses to None. Treated as "declares no policy" rather than
    # refused: a commented-out policy file is a reasonable thing to keep in a
    # repository, and it states no policy, which is representable.
    if document is None:
        return AshWorkspaceConfig()

    if not isinstance(document, dict):
        raise _refuse(
            f"workspace policy file '{resolved.as_posix()}' must contain a "
            f"mapping at the top level, found {type(document).__name__}"
        )

    try:
        return AshWorkspaceConfig.model_validate(document)
    except ValidationError as exc:
        raise _refuse(
            f"workspace policy file '{resolved.as_posix()}' is not valid: {exc}"
        ) from exc


def discover_workspace_policy_file(root: PathLike) -> Path | None:
    """Find the one policy file for the workspace rooted at *root*.

    Looks in *root* itself and in ``root/.ash``, non-recursively. Recursing would
    let a vendored checkout supply workspace policy.

    Returns:
        The canonical path, or ``None`` when there is none.

    Raises:
        WorkspaceDefinitionError: When more than one candidate exists. Listed,
            not ranked -- see the module docstring.
    """
    directory = Path(root)
    candidates: list[Path] = []
    for parent in (directory, directory / _POLICY_SUBDIR):
        for name in WORKSPACE_POLICY_FILE_NAMES:
            candidate = parent / name
            if candidate.is_file():
                candidates.append(candidate)

    if not candidates:
        return None

    if len(candidates) > 1:
        listed = "\n  - ".join(candidate.as_posix() for candidate in sorted(candidates))
        raise _refuse(
            f"Found {len(candidates)} workspace policy files under "
            f"'{directory.as_posix()}'; there must be exactly one. Remove the "
            f"extras or name one with '--workspace-config':\n  - {listed}"
        )

    return candidates[0].resolve()


def _refuse_project_config_as_policy(
    policy_path: Path, project_config_paths: Sequence[Path]
) -> None:
    """Refuse a policy file that is actually some project's config.

    Compared by resolved path rather than by name, so a symlink to a project's
    config, or a differently-spelled path to it, is caught as well.
    """
    from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES

    for project_config in project_config_paths:
        try:
            same = policy_path.resolve() == Path(project_config).resolve()
        except OSError:  # pragma: no cover - unresolvable path
            same = False
        if same:
            raise _refuse(
                f"'{policy_path.as_posix()}' is a project's own ASH config, so it "
                f"cannot also be the workspace policy file. A project config "
                f"governs one project; workspace policy governs all of them, and "
                f"reading one as the other would apply a single project's "
                f"settings to its siblings. Put workspace policy in "
                f"'{_POLICY_SUBDIR}/ash-workspace.yaml' instead."
            )

    # Also refuse by name. This catches the workspace root's own config even when
    # the caller passed no project list -- the common CLI shape, since the root
    # project's config path is not known to argument parsing.
    if policy_path.name in ASH_CONFIG_FILE_NAMES:
        raise _refuse(
            f"'{policy_path.as_posix()}' is named like an ASH project config "
            f"('{policy_path.name}'), so it cannot be the workspace policy file. "
            f"Workspace policy must live in a distinct file -- "
            f"'{_POLICY_SUBDIR}/ash-workspace.yaml', or any name passed to "
            f"'--workspace-config' that is not a project config name."
        )


def resolve_workspace_policy(
    root: PathLike,
    *,
    explicit: PathLike | None = None,
    project_config_paths: Iterable[PathLike] = (),
) -> tuple[AshWorkspaceConfig | None, Path | None]:
    """Locate and load the workspace policy, if there is one.

    Args:
        root: The workspace root -- the directory holding the ``.code-workspace``
            file. Policy is looked for here and in ``root/.ash``.
        explicit: The value of ``--workspace-config``. When given, it is used
            instead of discovery and must exist: silently falling back to
            discovery would run with different policy than the operator named.
        project_config_paths: Each project's own config file, where it has one.
            Used to refuse a policy file that is one of them.

    Returns:
        ``(policy, source)``. Both are ``None`` when the workspace declares no
        policy, which is not an error -- workspace policy is opt-in.

    Raises:
        WorkspaceDefinitionError: Exit code 4. The named file is absent, the
            workspace has two candidates, the file is unusable, or it is a
            project's config. The message names the file in every case.
    """
    if explicit is not None:
        policy_path = Path(explicit)
        if not policy_path.exists():
            raise _refuse(
                f"workspace policy file '{policy_path.as_posix()}' does not "
                f"exist. '--workspace-config' names the file to use; ASH does "
                f"not fall back to searching, because that would apply different "
                f"policy than the one asked for."
            )
    else:
        discovered = discover_workspace_policy_file(root)
        if discovered is None:
            return None, None
        policy_path = discovered

    _refuse_project_config_as_policy(
        policy_path, [Path(p) for p in project_config_paths]
    )

    return load_workspace_policy(policy_path), policy_path.resolve()


def _push_down(
    entries: Sequence[IgnorePathWithReason], project_prefix: PathLike
) -> tuple[IgnorePathWithReason, ...]:
    """Rewrite each entry's path into *project_prefix*'s coordinates.

    Entries whose pattern cannot match inside the project are dropped -- they are
    about a different project. Entries with no sound rewrite are refused, because
    dropping one would leave a stated suppression unapplied and invisible.

    Each surviving entry is a COPY, so the shared policy object is not mutated
    as it is pushed into successive projects.
    """
    pushed: list[IgnorePathWithReason] = []
    for entry in entries:
        try:
            rewritten = to_project_pattern(entry.path, project_prefix)
        except WorkspacePatternError as exc:
            raise _refuse(
                f"workspace policy pattern '{entry.path}' cannot be applied to "
                f"project '{Path(project_prefix).as_posix()}': {exc}"
            ) from exc
        if rewritten is None:
            continue
        # model_copy rather than reconstruction, so every field the model gains
        # later is carried over without this call site needing to learn about it.
        pushed.append(entry.model_copy(update={"path": rewritten}))
    return tuple(pushed)


def policy_for_project(
    policy: WorkspacePolicyConfig | None,
    *,
    project_prefix: PathLike,
    project_threshold: str | None,
    project_scanners: Iterable[str],
) -> ProjectPolicy:
    """Apply workspace *policy* to one project.

    Args:
        policy: The workspace policy block, or ``None`` for no policy.
        project_prefix: The project's workspace-relative path, e.g. ``api`` or
            ``services/worker``. The coordinate system the patterns are rewritten
            into.
        project_threshold: The threshold the project's own config resolved to.
            ``None`` or ``""`` means the project turned its gate off, which is
            LOOSER than any ceiling and so is tightened by one.
        project_scanners: The scanners the project already enables. Used to tell
            a scanner the project owns from one this policy adds.

    Returns:
        The policy as it applies to this project.

    Raises:
        WorkspaceDefinitionError: Exit code 4, when a policy pattern has no sound
            rewrite for this project.
    """
    if policy is None:
        return ProjectPolicy(
            effective_threshold=project_threshold,
            threshold_tightened=False,
            suppressions=(),
            ignore_paths=(),
            policy_scanners=(),
            policy_scanners_gate=False,
        )

    ceiling = policy.max_severity_threshold
    # Argument order is not arbitrary: stricter_of is commutative, so this is
    # safe either way, but the ceiling is passed second to read as "the project
    # asked for X, capped by Y".
    effective = stricter_of(project_threshold, ceiling)

    declared = {_normalise_scanner_name(name) for name in project_scanners}
    policy_scanners = tuple(
        name
        for name in policy.additional_scanners
        if _normalise_scanner_name(name) not in declared
    )

    return ProjectPolicy(
        effective_threshold=effective,
        threshold_tightened=effective != project_threshold,
        suppressions=tuple(
            # _push_down returns the base type; suppressions keep their own type
            # because model_copy preserves the class it was called on.
            entry  # type: ignore[misc]
            for entry in _push_down(policy.suppressions, project_prefix)
        ),
        ignore_paths=_push_down(policy.ignore_paths, project_prefix),
        policy_scanners=policy_scanners,
        policy_scanners_gate=policy.policy_scanners_gate,
    )
