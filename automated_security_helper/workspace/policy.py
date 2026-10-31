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

A policy file is named by the path it was reached by
----------------------------------------------------
Discovery and ``--workspace-config`` give the path the file was found or named
at, made absolute but not resolved. The policy beside a definition an MCP client
delivered may be a link to a file elsewhere, and a file is judged by every path
it was reached by (``config/config_sources.py``, "Base paths"), so the caller
judges that path: a link the client delivered makes the file the client's
wherever it points. A caller's ``permit_base`` covers the file the path reaches
before anything reads it, and for a client's file (``client_supplied``) an error
says where each problem is, not what the file holds.

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
  its findings as policy-origin duplicates of the project's own. The same fold
  decides which of the policy's own entries are one scanner: ``cdk-nag`` and
  ``cdk_nag`` listed together, or a name listed twice, are carried once, as
  the first spelling.
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
import os
import stat
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from automated_security_helper.config.ash_config import (
    load_config_yaml,
    reduced_plugin_name,
)
from automated_security_helper.config.ash_workspace_config import (
    AshWorkspaceConfig,
    WorkspacePolicyConfig,
)
from automated_security_helper.config.config_sources import (
    _is_a_link,
    parse_error_kind,
)
from automated_security_helper.config.plugin_section_names import ascii_lower
from automated_security_helper.core.exceptions import (
    ASHConfigInputNotPermittedError,
    WorkspaceDefinitionError,
    WorkspacePatternError,
)
from automated_security_helper.models.core import (
    AshSuppression,
    IgnorePathWithReason,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.severity_ladder import (
    SEVERITIES,
    sarif_level_fails_threshold,
    stricter_of,
)
from automated_security_helper.utils.workspace_paths import (
    IGNORE_PATH,
    SUPPRESSION,
    PatternKind,
    to_project_pattern,
)

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
        package_paths_applied: The 1-based positions of the policy's
            suppressions whose ``path`` reaches this project and whose
            ``package_path`` named a package copy inside it.
        package_paths_dropped: The same positions for a ``package_path`` that
            named no copy inside this project, so the entry was dropped here.
            The resolver reads both across every project
            (:func:`refuse_package_paths_naming_no_project`).
        project_prefix: The project's workspace-relative path, as the policy was
            pushed down into it, forward-slash separated. Carried so the
            cross-project read can tell the projects this run scanned from the
            plan's skipped ones without a second argument naming them.
    """

    effective_threshold: str | None
    threshold_tightened: bool
    suppressions: tuple[AshSuppression, ...]
    ignore_paths: tuple[IgnorePathWithReason, ...]
    policy_scanners: tuple[str, ...]
    policy_scanners_gate: bool
    package_paths_applied: tuple[int, ...] = ()
    package_paths_dropped: tuple[int, ...] = ()
    project_prefix: str = ""


def _refuse(message: str) -> WorkspaceDefinitionError:
    return WorkspaceDefinitionError(message)


def _prefix_text(project_prefix: PathLike) -> str:
    """A project's workspace-relative path as the one text the policy compares.

    Forward-slash separated on every host: ``Path(...).as_posix()`` keeps a
    backslash on POSIX, where it is a name character, so a prefix written with
    backslashes would be one text here and another once the pattern converters
    (which read a backslash as a separator everywhere) had used it. The
    per-project policy records this form and the cross-project read compares the
    plan's prefixes in the same form, so like compares with like.
    """
    return Path(str(project_prefix).replace("\\", "/")).as_posix()


def _as_named(path: PathLike) -> Path:
    """*path* made absolute as it was named: no link followed, no ``..`` collapsed.

    Not ``os.path.abspath``, which collapses ``..`` as text. With ``L`` a link to
    a directory elsewhere, ``ws/L/../pol.yaml`` names ``<L's target>/../pol.yaml``
    to the filesystem, while the collapsed ``ws/pol.yaml`` is another file: the
    file whose existence was checked and the file then read would differ. The
    name is kept as written, and ``resolve()`` on it reaches the file it names.
    """
    named = Path(path)
    return named if named.is_absolute() else Path(os.getcwd()) / named


def _refuse_unless_a_file(candidate: Path) -> None:
    """Refuse a policy candidate that exists as an entry but is not a regular file.

    A dangling link, a link loop and a directory at a policy file name used to
    read as "no policy", and the workspace then ran with no ceiling, no
    suppressions and no required scanners: the fail-open outcome the module
    docstring refuses. Each is named for what it is, so the operator knows what
    to remove or replace.
    """
    label = f"workspace policy file '{candidate.as_posix()}'"
    try:
        mode = os.stat(candidate).st_mode
    except FileNotFoundError as exc:
        raise _refuse(
            f"{label} is a link to a file that is not there; a policy file that "
            f"cannot be read is not treated as no policy"
        ) from exc
    except OSError as exc:
        raise _refuse(
            f"{label} could not be examined ({exc.strerror or type(exc).__name__}); "
            f"a policy file that cannot be read is not treated as no policy"
        ) from exc
    if stat.S_ISDIR(mode):
        raise _refuse(f"{label} is a directory, not a file")
    if not stat.S_ISREG(mode):
        raise _refuse(f"{label} is not a regular file")


def ceiling_unreachable_counts(
    results: Iterable[Mapping[str, Any]],
    declared_threshold: str | None,
    effective_threshold: str | None,
    *,
    non_gating_scanners: Iterable[str] = (),
) -> dict[str, int]:
    """Per scanner, how many findings the severity ceiling could not affect.

    This is the mechanised form of the limitation described in the module
    docstring. Rather than documenting "the ceiling does not apply to checkov",
    which goes stale the moment checkov starts emitting severity, it counts the
    findings actually present for which tightening the threshold changed nothing,
    and lets a reporter state that as an observation about those findings.

    A finding counts when BOTH hold:

    * It carries no usable ``properties.issue_severity``, so it is judged from
      the SARIF ``level``. This is the discriminator, and it is why a genuinely
      CRITICAL severity-carrying finding is NOT counted: that finding is
      actionable at both thresholds too, but correctly so, and reporting it would
      tell the operator the ceiling failed at something it never claimed.
    * Its actionable verdict is identical at both thresholds, so the tightening
      did not reach it. A level-only ``note`` under a CRITICAL-to-LOW tightening
      IS reached, and so is not counted.

    Suppressed findings are skipped: they are not actionable at any threshold, so
    the ceiling is irrelevant to them. So are the findings of a scanner in
    ``non_gating_scanners``: a policy scanner whose findings do not reach the
    project's exit code (``policy_scanners_gate`` off) is actionable at no
    threshold either, and counting its level-only findings told the operator the
    ceiling could not reach findings the gate never judged.

    ``issue_severity`` is read as the gate reads it (``severity_ladder``):
    stripped of surrounding whitespace and upper-cased, so a padded severity the
    gate honors is not counted here as a level-only finding.

    Args:
        results: The project's SARIF results.
        declared_threshold: The threshold the project's own config asked for.
        effective_threshold: The threshold after the workspace ceiling.
        non_gating_scanners: Scanner names whose findings the project's exit
            code does not count, compared by :func:`normalise_scanner_name`.

    Returns:
        Scanner name to count, for scanners with at least one such finding.
        Empty when the two thresholds are equal -- no tightening means there is
        no claim to qualify, which is what keeps this disclosure load-bearing
        rather than printed on every scan.
    """
    if declared_threshold == effective_threshold:
        return {}

    not_gating = {normalise_scanner_name(str(name)) for name in non_gating_scanners}
    counts: dict[str, int] = {}
    for result in results:
        if not isinstance(result, Mapping):
            continue
        if result.get("suppressions"):
            continue

        properties = result.get("properties")
        issue_severity = ""
        if isinstance(properties, Mapping):
            issue_severity = str(properties.get("issue_severity") or "").strip().upper()
        if issue_severity in SEVERITIES:
            # The ceiling reaches severity-carrying findings; nothing to disclose.
            continue
        if not_gating and isinstance(properties, Mapping):
            scanner_name = properties.get("scanner_name")
            if scanner_name and normalise_scanner_name(str(scanner_name)) in not_gating:
                # Judged at no threshold, so the ceiling never claimed it.
                continue

        level = result.get("level")
        if sarif_level_fails_threshold(
            level, declared_threshold
        ) != sarif_level_fails_threshold(level, effective_threshold):
            # The tightening changed this finding's verdict, so it was reached.
            continue
        if not sarif_level_fails_threshold(level, effective_threshold):
            # Not actionable either way -- below both thresholds, not beyond reach.
            continue

        scanner = None
        if isinstance(properties, Mapping):
            scanner = properties.get("scanner_name")
        # "unattributed" matches the name the aggregator uses for a finding with
        # no scanner_name, so the two payloads agree on what to call it.
        name = str(scanner) if scanner else "unattributed"
        counts[name] = counts.get(name, 0) + 1

    return counts


def normalise_scanner_name(name: str) -> str:
    """Fold a scanner name to the form used for comparison.

    ``cdk-nag`` and ``cdk_nag`` are one scanner: the former is what
    ``--scanners`` and the config file accept, the latter is the Python field
    name. Comparing raw strings would make policy add a duplicate.

    Public rather than private because ``workspace/execution.py`` has to fold
    the same two spellings when it enables a policy scanner and when it decides
    which findings that scanner produced. A second copy of this rule is a
    correctness hazard, not a style one: the two would agree on every name until
    one of them met an aliased scanner, and the disagreement would show up as a
    policy that enables nothing while the plan says it enabled something.

    The fold is the one ``AshConfig.get_plugin_config`` reads a section under
    (``ash_config.reduced_plugin_name``): the Converter, Scanner or Reporter word
    dropped, every character outside ``[a-z0-9+]`` dropped, and the rest lowered
    with ``ascii_lower``. So the project keys the lookup reads as one scanner
    (``Snyk_Code``, ``snyk.code``, ``snykcode``) are one name here. Folded any
    other way, the policy and the lookup disagreed about which project keys are a
    scanner's. A name the reduction leaves empty falls back to the name itself,
    lowered the same way, so two such names stay two names.
    """
    stripped = name.strip()
    return reduced_plugin_name(stripped) or ascii_lower(stripped).replace("-", "_")


def _read_policy_document(path: Path, named: Path, quote_values: bool) -> object:
    """Parse the policy file at ``path``, refusing anything unreadable.

    Uses ``load_config_yaml`` rather than ``AshConfig``'s ``!ENV``-aware loader.
    See "No ``!ENV`` substitution" in ``config/ash_workspace_config.py``: a
    ceiling an environment variable can loosen is not a ceiling. YAML aliases are
    refused, as in every ASH config file.

    A refusal names ``named``, the path the file was reached by. A file that is
    not UTF-8 or does not parse is refused with the error's type and where it
    stopped (parse_error_kind), never the decoder's or the parser's own message,
    whatever ``quote_values`` says: the decoder's prints the undecodable byte's
    value and the parser's quotes the file (a snippet of the line, since this
    parse is of a str) or, for a constructor's ValueError (``!!int``), the
    value itself (config_sources.unparsed_config_reason). ``quote_values``
    governs the schema problems only (_load_policy), where the operator's own
    file shows the value it wrote.

    The format is the one ``named`` says, as the JSON project configs are read
    (``config_sources._read_config_file`` goes by the path it was given): a
    ``.yaml`` name that links to a ``.json`` file is read as YAML. A leading
    byte order mark is dropped (``utf-8-sig``), as the JSON config reader drops
    it; YAML and TOML drop their own. A document nested past the interpreter's
    recursion limit raises ``RecursionError`` from either parser, which is
    refused like any other parse failure rather than escaping as a traceback.
    """
    label = f"workspace policy file '{named.as_posix()}'"
    undecoded = ""
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        reason = f": {exc}" if quote_values else f" ({exc.strerror or 'OSError'})"
        raise _refuse(f"{label} could not be read{reason}") from exc
    except UnicodeDecodeError as exc:
        # The decoder's message prints the byte's value; parse_error_kind gives
        # its offset and nothing from the file.
        undecoded = parse_error_kind(exc)
    if undecoded:
        # Outside the handler, so the decoder's error is not its context.
        raise _refuse(f"{label} could not be parsed {undecoded}")

    kind = ""
    try:
        if named.suffix.lower() == ".json":
            return json.loads(raw)
        return load_config_yaml(raw)
    except (yaml.YAMLError, ValueError, RecursionError) as exc:
        # json.JSONDecodeError and a constructor's ValueError (!!int) are
        # ValueErrors. The type and place only: the parser's message quotes the
        # file, a snippet of the line included, since this parse is of a str,
        # and the constructor's quotes the value (unparsed_config_reason).
        kind = parse_error_kind(exc)
    # Outside the handler, so the parser's error is not its context.
    raise _refuse(f"{label} could not be parsed {kind}")


def _where(error: Exception) -> str:
    """Where a YAML or JSON parser stopped, as line and column, or ""."""
    mark = getattr(error, "problem_mark", None)
    if mark is not None:
        return f" at line {mark.line + 1}, column {mark.column + 1}"
    if isinstance(error, json.JSONDecodeError):
        return f" at line {error.lineno}, column {error.colno}"
    return ""


def load_workspace_policy(
    path: PathLike, *, quote_values: bool = True
) -> AshWorkspaceConfig:
    """Parse and validate the policy file at *path*.

    Args:
        path: The policy file. Must exist.
        quote_values: False for a client's file: a refusal then gives where
            each problem is and what kind it is, without the file's text.

    Returns:
        The validated policy.

    Raises:
        WorkspaceDefinitionError: Exit code 4, for every unusable file -- absent,
            unreadable, unparseable, not a mapping, or failing the schema. The
            message names the file, by the path it was reached by, because a
            workspace may have several config files and "validation error" alone
            does not say which to open.
    """
    named = _as_named(path)
    return _load_policy(_resolved(named), named, quote_values)


def _resolved(named: Path) -> Path:
    """The file *named* reaches, or the refusal for a path that reaches none.

    ``Path.resolve`` raises ``RuntimeError`` for a symlink loop on CPython 3.10
    to 3.12 and ``OSError`` for a few unreadable shapes; 3.13 and later return
    the path as far as it goes. Either way the policy cannot be read, and the
    module docstring says that is a refusal (exit 4), never a traceback.
    """
    try:
        return named.resolve()
    except (RuntimeError, OSError) as exc:
        raise _refuse(
            f"workspace policy file '{named.as_posix()}' cannot be resolved: a "
            f"component on the way to it is a symlink loop or cannot be read "
            f"({type(exc).__name__}); a policy file that cannot be read is not "
            f"treated as no policy"
        ) from exc


def _policy_problems(error: ValidationError) -> str:
    """Each problem of a policy file, with the value the file wrote.

    The model hides inputs in its errors, since a config value can be a secret
    read from the environment. This loader substitutes nothing from the
    environment, so each value is the file's own text, and an operator whose CI
    templating left ``${THRESH}`` unexpanded has to see it. ``repr`` shows a
    control character in it as an escape.
    """
    return "; ".join(
        f"{'.'.join(str(part) for part in item['loc']) or '(top level)'}: "
        f"{item['msg']} (the file has {item.get('input')!r})"
        for item in error.errors()
    )


def _load_policy(path: Path, named: Path, quote_values: bool) -> AshWorkspaceConfig:
    """``load_workspace_policy`` for the file ``path``, reached by ``named``."""
    label = f"workspace policy file '{named.as_posix()}'"
    # os.stat with the error kept, not Path.exists()/is_file(): those raised a
    # bare PermissionError for an unsearchable parent on Python 3.10-3.13 and
    # read the file as absent on 3.14.
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError as exc:
        raise _refuse(f"{label} does not exist") from exc
    except OSError as exc:
        raise _refuse(
            f"{label} could not be examined ({exc.strerror or type(exc).__name__}); "
            f"a policy file that cannot be read is not treated as no policy"
        ) from exc
    if not stat.S_ISREG(mode):
        raise _refuse(f"{label} is not a file")

    document = _read_policy_document(path, named, quote_values)

    # An empty file parses to None. Treated as "declares no policy" rather than
    # refused: a commented-out policy file is a reasonable thing to keep in a
    # repository, and it states no policy, which is representable.
    if document is None:
        return AshWorkspaceConfig()

    if not isinstance(document, dict):
        raise _refuse(
            f"{label} must contain a mapping at the top level, found "
            f"{type(document).__name__}"
        )

    try:
        return AshWorkspaceConfig.model_validate(document)
    except ValidationError as exc:
        if quote_values:
            raise _refuse(f"{label} is not valid: {_policy_problems(exc)}") from exc
        from automated_security_helper.config.resolve_config import (
            unquoted_validation_problems,
        )

        problems = unquoted_validation_problems(exc, AshWorkspaceConfig)
        raise _refuse(
            f"{label} is not valid: {len(problems)} problem(s): "
            f"{'; '.join(problems)}. The values are not shown because an MCP "
            "client supplied the file."
        ) from None


def _policy_not_permitted(candidate: Path, root: Path) -> WorkspaceDefinitionError:
    """The refusal of a policy file *permit* refused: its name in *root*, and nothing
    the file holds or its resolved path, which may be outside what the caller may
    read. Raised from an ``ASHConfigInputNotPermittedError``, so a caller reports it
    as the other confinement refusals of a config input.

    A candidate below *root* is named relative to it. One elsewhere, an explicit
    ``--workspace-config`` outside the root, is named as the caller gave it: the
    caller's own spelling says nothing the caller does not know, and saying it
    was "in" the root named a directory it was never in.
    """
    try:
        where = f"'{candidate.relative_to(root).as_posix()}' in '{root.as_posix()}'"
    except ValueError:
        where = f"'{candidate.as_posix()}'"
    if candidate == root / _POLICY_SUBDIR:
        # A linked .ash, refused before anything in it is looked at.
        message = (
            f"The workspace policy directory {where} is outside the directories "
            f"this caller may read config from, so nothing in it was read."
        )
    else:
        message = (
            f"The workspace policy file {where} is outside the directories this "
            f"caller may read config from, so it was not read."
        )
    refusal = _refuse(message)
    refusal.__cause__ = ASHConfigInputNotPermittedError(message)
    return refusal


def discover_workspace_policy_file(
    root: PathLike, permit: Callable[[Path], bool] | None = None
) -> Path | None:
    """Find the one policy file for the workspace rooted at *root*.

    Looks in *root* itself and in ``root/.ash``, non-recursively. Recursing would
    let a vendored checkout supply workspace policy.

    *permit* is the caller's gate on config it may read (an MCP session's
    ``config_base_gate``). Every candidate name that exists as an entry, a link to
    a file that is not there included, must pass it before anything is read, as
    config discovery checks its candidates, and so must the file the name
    reaches, before the entry's kind is read: a link to a missing file outside is
    refused as one to a present file, a directory or a FIFO, so the answer says
    nothing about the outside path. A ``.ash`` that is a link must pass it too,
    before any name in it is looked at, so the answer says nothing about what the
    directory it leads to holds.

    Returns:
        The path the file was found at, made absolute but not resolved (see "A
        policy file is named by the path it was reached by"), or ``None`` when
        there is none.

    Raises:
        WorkspaceDefinitionError: When more than one candidate exists. Listed,
            not ranked -- see the module docstring. Also when *permit* refuses a
            candidate, raised from an ``ASHConfigInputNotPermittedError``.
    """
    directory = Path(root)
    candidates: list[Path] = []
    for parent in (directory, directory / _POLICY_SUBDIR):
        # A linked .ash first, before any name in it: asking whether a name is
        # there follows the link, so the answer would say whether the directory
        # it leads to holds the name. A junction is a link here too, which
        # Path.is_symlink() does not say.
        if (
            permit is not None
            and parent != directory
            and _is_a_link(parent)
            and not permit(parent)
        ):
            raise _policy_not_permitted(parent, directory)
        for name in WORKSPACE_POLICY_FILE_NAMES:
            candidate = parent / name
            # The entry itself, link or not, with the error kept: Path.is_file()
            # raised a bare PermissionError for an unsearchable .ash on Python
            # 3.10-3.13 and read it as no policy on 3.14, and lexists() reads
            # every failure as absence.
            try:
                os.lstat(candidate)
            except (FileNotFoundError, NotADirectoryError):
                continue
            except OSError as exc:
                raise _refuse(
                    f"workspace policy file '{candidate.as_posix()}' could not be "
                    f"examined ({exc.strerror or type(exc).__name__}); a policy "
                    f"file that cannot be read is not treated as no policy"
                ) from exc
            if permit is not None:
                if not permit(candidate):
                    raise _policy_not_permitted(candidate, directory)
                # The file the name reaches too, before its kind is read: the
                # kind check follows a link, and its refusals (not there, a
                # directory, not a regular file, unreadable) would each say
                # what sits at a target outside the permitted directories,
                # the probe resolve_workspace_policy closes for an explicit
                # path. One refusal for every kind of outside target.
                if not permit(_resolved(candidate)):
                    raise _policy_not_permitted(candidate, directory)
            _refuse_unless_a_file(candidate)
            candidates.append(candidate)

    if not candidates:
        return None

    if len(candidates) > 1:
        raise WorkspaceDefinitionError.listing(
            f"Found {len(candidates)} workspace policy files under "
            f"'{directory.as_posix()}'; there must be exactly one. Remove the "
            f"extras or name one with '--workspace-config':",
            [candidate.as_posix() for candidate in sorted(candidates)],
        )

    return _as_named(candidates[0])


def named_workspace_policy_path(
    root: PathLike, explicit: PathLike | None = None
) -> Path | None:
    """The policy file's path as it was named, made absolute, with no link
    followed and no ``..`` collapsed.

    ``--workspace-config`` as given, or else the one candidate discovery finds in
    *root* or ``root/.ash``. :func:`discover_workspace_policy_file` and
    :func:`resolve_workspace_policy` return the resolved path, which is the file
    read; container mode needs the name too, to refuse a policy named inside the
    workspace's tree that is a link to a file outside it. That refusal judges
    the spelling, so the name is made absolute by prefixing the working
    directory, never by ``os.path.abspath``: collapsing ``ws/L/../../pol.yaml``
    as text drops the link ``L`` from the name, and the gate then judged a
    sibling path the host never read. Call it after
    :func:`resolve_workspace_policy` has accepted the policy: with several
    candidates this returns the first, and that call has already refused them.
    """
    if explicit is not None:
        named = Path(explicit)
        return named if named.is_absolute() else Path(os.getcwd()) / named
    directory = Path(root)
    for parent in (directory, directory / _POLICY_SUBDIR):
        for name in WORKSPACE_POLICY_FILE_NAMES:
            candidate = parent / name
            # The entry itself, as discovery reads it: Path.is_file() raised a
            # bare PermissionError for an unsearchable .ash on Python 3.10-3.13
            # and read it as no policy on 3.14.
            try:
                os.lstat(candidate)
            except (FileNotFoundError, NotADirectoryError):
                continue
            except OSError as exc:
                raise _refuse(
                    f"workspace policy file '{candidate.as_posix()}' could not be "
                    f"examined ({exc.strerror or type(exc).__name__}); a policy "
                    f"file that cannot be read is not treated as no policy"
                ) from exc
            if candidate.is_absolute():
                return candidate
            return Path(os.getcwd()) / candidate
    return None


def _refuse_project_config_as_policy(
    policy_path: Path, project_config_paths: Sequence[Path]
) -> None:
    """Refuse a policy file that is actually some project's config.

    Compared by resolved path rather than by name, so a symlink to a project's
    config, or a differently-spelled path to it, is caught as well. The by-name
    check reads the name the path was given and the name of the file it reaches:
    a link ``pol.yaml`` to the root's own ``ash.yaml`` names a project config
    under another name, and the root project's config is in no project list.
    """
    from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES

    try:
        target = policy_path.resolve()
    except (OSError, RuntimeError):  # pragma: no cover - unresolvable path
        target = policy_path
    for project_config in project_config_paths:
        try:
            same = target == Path(project_config).resolve()
        except (OSError, RuntimeError):  # pragma: no cover - unresolvable path
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
    # project's config path is not known to argument parsing. The name the path
    # was given and the name of the file it reaches both count: a link named
    # otherwise still reads the root's config as the siblings' ceiling.
    named_like_a_config = next(
        (
            name
            for name in (policy_path.name, target.name)
            if name in ASH_CONFIG_FILE_NAMES
        ),
        None,
    )
    if named_like_a_config is not None:
        raise _refuse(
            f"'{policy_path.as_posix()}' is named like an ASH project config "
            f"('{named_like_a_config}'), so it cannot be the workspace policy file. "
            f"Workspace policy must live in a distinct file -- "
            f"'{_POLICY_SUBDIR}/ash-workspace.yaml', or any name passed to "
            f"'--workspace-config' that is not a project config name."
        )


def resolve_workspace_policy(
    root: PathLike,
    *,
    explicit: PathLike | None = None,
    project_config_paths: Iterable[PathLike] = (),
    permit_base: Callable[[Path], bool] | None = None,
    client_supplied: Callable[[Path], bool] | None = None,
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
        permit_base: The MCP session's gate (``cli/mcp/sandbox.config_base_gate``),
            or None. The file the policy path reaches must be one it permits,
            checked before the file is read, for *explicit* and for every
            candidate discovery finds.
        client_supplied: Whether a policy path is a client's file, or None for
            never. A client's file is loaded with ``quote_values`` False.

    Returns:
        ``(policy, source)``, ``source`` the path the file was found or named
        at, made absolute but not resolved. Both are ``None`` when the
        workspace declares no policy, which is not an error -- workspace policy
        is opt-in.

    Raises:
        WorkspaceDefinitionError: Exit code 4. The named file is absent, the
            workspace has two candidates, the file is unusable, or it is a
            project's config. The message names the file in every case.
        ASHConfigInputNotPermittedError: The file is outside what
            ``permit_base`` permits.
    """
    if explicit is not None:
        policy_path = Path(explicit)
        if permit_base is not None and not permit_base(policy_path):
            raise _policy_not_permitted(policy_path, Path(root))
    else:
        discovered = discover_workspace_policy_file(root, permit=permit_base)
        if discovered is None:
            return None, None
        policy_path = discovered

    named = _as_named(policy_path)
    target = _resolved(named)
    # The gate on the file the path reaches comes before any existence test: a
    # link inside the permitted directories to a file outside them was told
    # "does not exist" when that file was absent and refused by this gate when
    # it was present, so the two refusals said whether the outside file exists.
    if permit_base is not None and not permit_base(target):
        raise ASHConfigInputNotPermittedError(
            f"workspace policy file '{named.as_posix()}' reaches a file outside "
            "the directories this caller may read config from."
        )
    if explicit is not None and not _entry_exists(named):
        raise _refuse(
            f"workspace policy file '{policy_path.as_posix()}' does not "
            f"exist. '--workspace-config' names the file to use; ASH does "
            f"not fall back to searching, because that would apply different "
            f"policy than the one asked for."
        )

    _refuse_project_config_as_policy(named, [Path(p) for p in project_config_paths])

    quote_values = client_supplied is None or not client_supplied(named)
    return _load_policy(target, named, quote_values), named


def _entry_exists(path: Path) -> bool:
    """Whether an entry is at *path*, a link to a missing file included.

    ``os.lstat`` with its error read: ``Path.exists()`` raised a bare
    ``PermissionError`` for an unsearchable parent on Python 3.10-3.13, and the
    refusal for that is the resolved-target gate's or the loader's, not a
    traceback here.
    """
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True
    return True


def _push_down(
    entries: Sequence[IgnorePathWithReason],
    project_prefix: PathLike,
    *,
    kind: PatternKind,
    quote_values: bool = True,
) -> _PushedDown:
    """Rewrite each entry's path into *project_prefix*'s coordinates.

    ``kind`` is what the entries are, ``IGNORE_PATH`` or ``SUPPRESSION``: the two
    read a trailing ``/`` differently, so it decides the rewrite
    (``utils/workspace_paths.to_project_pattern``).

    Entries whose pattern cannot match inside the project are dropped -- they are
    about a different project. Entries with no sound rewrite are refused, because
    dropping one would leave a stated suppression unapplied and invisible. With
    ``quote_values`` False (a client's file) the refusal names the entry by its
    kind and position and quotes neither the pattern nor the converter's reason,
    which repeats the pattern: a delivered file's content is not shown.

    Each surviving entry is a COPY, so the shared policy object is not mutated
    as it is pushed into successive projects.
    """
    pushed: list[IgnorePathWithReason] = []
    package_applied: list[int] = []
    package_dropped: list[int] = []
    # The one spelling every refusal below shows, the one the policy records
    # (_prefix_text): a backslash-written prefix reads as ``apps/api`` here as
    # it does in the pattern converter's own message, on POSIX too.
    shown_prefix = _prefix_text(project_prefix)
    for position, entry in enumerate(entries, start=1):
        try:
            rewritten = to_project_pattern(entry.path, project_prefix, kind=kind)
        except WorkspacePatternError as exc:
            if not quote_values:
                raise _refuse(
                    f"workspace policy {kind} entry {position} cannot be applied to "
                    f"project '{shown_prefix}': it has no sound "
                    f"rewrite for that project. The pattern is not shown because "
                    f"an MCP client supplied the file."
                ) from None
            raise _refuse(
                f"workspace policy pattern '{entry.path}' cannot be applied to "
                f"project '{shown_prefix}': {exc}"
            ) from exc
        if rewritten is None:
            continue
        update: dict[str, Any] = {"path": rewritten}
        # A suppression's package_path is matched against the project-relative
        # install path of a finding's package with the path matcher
        # (AshSuppression._package_matches, path_matching._path_pattern_matches,
        # the same reading as the entry's path), and the policy writes it
        # relative to the workspace like the path, so it is rewritten like the
        # path. One that names a copy in another project drops the entry for
        # this project, recorded for the resolver's cross-project read; one with
        # no sound rewrite is refused like a path.
        package_path = getattr(entry, "package_path", None)
        if package_path is not None:
            try:
                rewritten_package = to_project_pattern(
                    package_path, project_prefix, kind=SUPPRESSION
                )
            except WorkspacePatternError as exc:
                if not quote_values:
                    raise _refuse(
                        f"workspace policy {kind} entry {position} has a "
                        f"package_path that cannot be applied to project "
                        f"'{shown_prefix}': it has no sound "
                        f"rewrite for that project. The value is not shown because "
                        f"an MCP client supplied the file."
                    ) from None
                raise _refuse(
                    f"workspace policy package_path '{package_path}' cannot be "
                    f"applied to project '{shown_prefix}': {exc}"
                ) from exc
            if rewritten_package is None:
                # The path reaches this project and the package copy named does
                # not, so the entry does not apply here. Recorded, not said: one
                # project cannot tell a copy in a sibling project (the entry is
                # right, and applies there) from a value that names no project's
                # copy at all ("node_modules/left-pad", written relative to a
                # project, the form that matched before the value was pushed
                # down). The resolver reads every project's record and refuses
                # the second shape (refuse_package_paths_naming_no_project).
                package_dropped.append(position)
                continue
            update["package_path"] = rewritten_package
            package_applied.append(position)
        # model_copy rather than reconstruction, so every field the model gains
        # later is carried over without this call site needing to learn about it.
        pushed.append(entry.model_copy(update=update))
    return _PushedDown(tuple(pushed), tuple(package_applied), tuple(package_dropped))


@dataclass(frozen=True)
class _PushedDown:
    """What :func:`_push_down` made of one kind of entry for one project.

    ``package_path_applied`` and ``package_path_dropped`` are the 1-based
    positions of the suppressions whose ``path`` reaches the project and whose
    ``package_path`` named a copy inside it, or named none. The resolver reads
    them across every project (:func:`refuse_package_paths_naming_no_project`).
    """

    entries: tuple[IgnorePathWithReason, ...]
    package_path_applied: tuple[int, ...]
    package_path_dropped: tuple[int, ...]


def refuse_package_paths_naming_no_project(
    policy: WorkspacePolicyConfig,
    resolved: Iterable[ProjectPolicy],
    *,
    every_project_prefix: Iterable[PathLike],
    quote_values: bool = True,
) -> None:
    """Refuse a suppression whose ``package_path`` named no project's copy.

    Read across the projects, because one project cannot tell the two shapes
    apart. A ``package_path`` written relative to the workspace
    (``api/node_modules/left-pad``) applies in ``api`` and is dropped, rightly,
    from every other project its ``path`` reaches. One written relative to a
    project (``node_modules/left-pad``) reads as a top-level directory of the
    workspace that is no project, so it is dropped from every project, and the
    suppression the operator stated applies nowhere with nothing in the output
    to say so: the module docstring's rule for a suppression is that such an
    entry is refused.

    An entry whose ``path`` reached some scanned project, whose ``package_path``
    matched none of them, and which names a copy in a project of the plan this
    run does not scan (a skipped project) is right and merely inert this run:
    logged once, not refused. Only the skipped projects are read for that copy:
    a copy in a project this run scanned excuses nothing, because that project
    read the entry's ``path`` and found it about another project, so the entry
    applies nowhere and is refused with the rest. An entry whose ``path``
    reached no scanned project is about other projects, as a dropped ``path``
    is, and is left alone.

    Args:
        policy: The workspace policy block the projects were resolved from.
        resolved: :func:`policy_for_project`'s result for each scanned project.
        every_project_prefix: The workspace-relative path of every project of
            the plan, skipped ones included.
        quote_values: False for a client's policy file: the refusal names the
            entry's position and not its value.

    Raises:
        WorkspaceDefinitionError: Exit code 4, listing each such entry.
    """
    applied: set[int] = set()
    dropped: set[int] = set()
    for project_policy in resolved:
        applied.update(project_policy.package_paths_applied)
        dropped.update(project_policy.package_paths_dropped)
    nowhere = sorted(dropped - applied)
    if not nowhere:
        return

    scanned = {project_policy.project_prefix for project_policy in resolved}
    skipped = [
        prefix
        for prefix in (_prefix_text(prefix) for prefix in every_project_prefix)
        if prefix not in scanned
    ]
    problems: list[str] = []
    for position in nowhere:
        package_path = policy.suppressions[position - 1].package_path or ""
        elsewhere = [
            prefix for prefix in skipped if _names_a_copy_in(package_path, prefix)
        ]
        shown = f" '{package_path}'" if quote_values else ""
        if elsewhere:
            ASH_LOGGER.warning(
                f"workspace policy suppression entry {position} applies to no "
                f"project this run scans: its package_path{shown} names a copy in "
                f"{', '.join(repr(prefix) for prefix in elsewhere)}, which the run "
                f"skips, and no copy in the projects its path reaches."
            )
            continue
        problems.append(
            f"suppression entry {position}: its package_path{shown} names no "
            f"project's package copy that its path reaches, so the entry would "
            f"apply nowhere"
        )
    if not problems:
        return
    raise WorkspaceDefinitionError.listing(
        "A workspace policy suppression cannot be applied: a package_path is "
        "read relative to the workspace, like the entry's path (the project's "
        "directory first, 'api/node_modules/left-pad'), and these name a path "
        "that is inside no project. A value written relative to a project "
        "('node_modules/left-pad') matches no finding once the policy is "
        "pushed down, so it is refused rather than dropped silently"
        + (
            ":"
            if quote_values
            else ". The values are not shown because an MCP client supplied the file:"
        ),
        problems,
    )


def _names_a_copy_in(package_path: str, project_prefix: str) -> bool:
    """Whether *package_path*, pushed down into *project_prefix*, still names a path."""
    try:
        return (
            to_project_pattern(package_path, project_prefix, kind=SUPPRESSION)
            is not None
        )
    except WorkspacePatternError:
        return False


def policy_for_project(
    policy: WorkspacePolicyConfig | None,
    *,
    project_prefix: PathLike,
    project_threshold: str | None,
    project_scanners: Iterable[str],
    quote_values: bool = True,
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
        quote_values: False for a client's policy file: a refusal of a pattern
            then names the entry's position and not its text.

    Returns:
        The policy as it applies to this project. ``threshold_tightened`` reads
        ``None`` and ``""`` as the one gate-off value they are to ``stricter_of``,
        so a project that declared ``""`` under a policy with no ceiling is not
        reported tightened.

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
            project_prefix=_prefix_text(project_prefix),
        )

    ceiling = policy.max_severity_threshold
    # Argument order is not arbitrary: stricter_of is commutative, so this is
    # safe either way, but the ceiling is passed second to read as "the project
    # asked for X, capped by Y".
    effective = stricter_of(project_threshold, ceiling)

    declared = {normalise_scanner_name(name) for name in project_scanners}
    # One entry per scanner the project does not declare, under the policy's
    # first spelling of it: "cdk-nag" and "cdk_nag" listed together, or a name
    # listed twice, would otherwise run the scanner twice under default config.
    added: dict[str, str] = {}
    for name in policy.additional_scanners:
        folded = normalise_scanner_name(name)
        if folded not in declared:
            added.setdefault(folded, name)
    policy_scanners = tuple(added.values())

    suppressions = _push_down(
        policy.suppressions,
        project_prefix,
        kind=SUPPRESSION,
        quote_values=quote_values,
    )
    return ProjectPolicy(
        effective_threshold=effective,
        # "" and None are the same value to stricter_of (the gate off), so a
        # project that declared "" under no ceiling is not reported tightened.
        threshold_tightened=effective != (project_threshold or None),
        suppressions=tuple(
            # _push_down returns the base type; suppressions keep their own type
            # because model_copy preserves the class it was called on.
            entry  # type: ignore[misc]
            for entry in suppressions.entries
        ),
        ignore_paths=_push_down(
            policy.ignore_paths,
            project_prefix,
            kind=IGNORE_PATH,
            quote_values=quote_values,
        ).entries,
        policy_scanners=policy_scanners,
        policy_scanners_gate=policy.policy_scanners_gate,
        package_paths_applied=suppressions.package_path_applied,
        package_paths_dropped=suppressions.package_path_dropped,
        project_prefix=_prefix_text(project_prefix),
    )
