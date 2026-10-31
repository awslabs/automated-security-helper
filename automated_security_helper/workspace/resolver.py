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
versions this project supports (3.10 through 3.14) -- a null byte, for instance,
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
  built-in ``>=1.7.8,<2.0.0`` really does constrain a project that never
  mentioned bandit, so a sibling pinning ``>=2.0.0`` really is a conflict. Since
  the default is identical for every project it can never manufacture one.
* Pins are compared pairwise first, then all of a scanner's distinct pins
  together (``scanner_pins.compare_pin_set``), since three pins can be
  satisfiable two at a time and jointly not. The message names the pairs that
  clash, or the whole set, not a minimal explanation of the clash.
* Only an enabled DECLARED scanner's pin is recorded and compared: a disabled
  declared scanner's tool does not run, so its pin cannot conflict with another
  project's. A workspace policy that requires a disabled scanner switches it on
  and keeps its pin, so the policy step records it and compares the pins again
  (``_record_pins_the_policy_turns_on``). An extra,
  plugin-provided section is read by a reduced name, and which of its spellings
  a plugin's registered name selects is unknown here, so the section the lookup
  reads records its pin whether or not it is on, and a pair the plan cannot
  resolve records one only when every section of it sets the same pin
  (``_scanner_state``).
* A refusal for a remote MCP client names a folder entry as the client wrote it
  and the rule it broke, never the real path it resolved to, which a client
  that supplies the workspace file could otherwise learn for any server path.
* A project's config is loaded to read its scanner set and threshold. That runs
  the ordinary config-resolution path, so a config that emits resolution warnings
  emits them here too, during what the operator asked to be a dry run.
"""

from __future__ import annotations

import os
import re
import stat
from itertools import combinations
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from automated_security_helper.config.ash_config import (
    AshConfig,
    plugin_section_claims,
    plugin_section_key,
    plugin_section_peers,
)
from automated_security_helper.config.client_config_policy import ClientConfigRules
from automated_security_helper.config.plugin_module_trust import config_module_names
from automated_security_helper.utils.error_text import (
    config_environment_values,
    text_without_values,
)
from automated_security_helper.config.resolve_config import (
    check_operator_config,
    find_config_file,
    operator_config_digest,
    resolve_config,
)
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    WorkspaceDefinitionError,
    WorkspacePathNotUtf8Error,
)
from automated_security_helper.models.workspace import SkippedProjectReason
from automated_security_helper.utils.path_containment import validate_contained_path
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from automated_security_helper.workspace.policy import (
    normalise_scanner_name,
    policy_for_project,
    refuse_package_paths_naming_no_project,
    resolve_workspace_policy,
)
from automated_security_helper.workspace.scanner_pins import (
    PinVerdict,
    compare_pin_set,
    compare_pins,
)
from automated_security_helper.workspace.workspace_file import (
    NOT_UTF8_ON_THE_HOST,
    WorkspaceDefinition,
    is_utf8_path,
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
    return WorkspaceDefinitionError.listing(headline, problems)


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


def _scanner_state(
    config: AshConfig,
) -> Tuple[List[str], Dict[str, str], Dict[str, List[str]]]:
    """Return the project's enabled scanner names, its effective pins and its twins.

    Walks the declared fields and then anything a plugin contributed via
    ``extra="allow"``, so a scanner ASH does not ship is still accounted for.

    The list is what a scan runs, so it follows the section the lookup reads. A
    declared scanner reads its own section. The sections of one extra plugin name
    are read in this order (``plugin_section_key``, ``plugin_section_claims``):

    1. the key spelled exactly as the name the caller gives, if there is one;
    2. the key spelled as the reduced name (``snykcode``);
    3. the first key whose name without punctuation is the plugin's;
    4. the first whose name is the plugin's only once its Converter, Scanner or
       Reporter word is removed.

    The plan has no registered name, so it applies steps 2 to 4. Every extra key
    that reduces to one name is a twin of the others, a section with no body
    included, because the lookup indexes it. The keys that claimed the name in the
    same pass as the key read (``plugin_section_peers``) are one plugin's
    spellings of its section. The keys of the other rank are other plugins, read
    by their own exact names, so each plugin is listed by its own section; but
    which of them the scan reads for the reduced name depends on the registered
    name, which the plan does not know, so they are twins all the same. A policy
    that requires the name would otherwise take the section of one plugin that is
    on for the scanner the scan reads, which may be another's that is off.

    A twin written in a form a plugin could register its name in (lowercase words
    joined by ``-`` or ``_``) may be what step 1 selects, and the registered names
    are not known until the plugin modules load, after the plan. Such a pair is
    unresolved: it is not listed as enabled unless every section of it is, and a
    section with no body is off and sets no pin. It records a pin when the
    sections set the same one. When they differ, ``_unresolved_pins`` holds each
    version the pair may apply, and ``_validate_unresolved_pins`` compares them
    with the pins of the other projects. The sections of the two ranks record a pin
    each, under their own keys, and ``_unresolved_pins`` holds them as a pair too.

    The twins are returned by reduced name, the keys of every rank together. The
    caller refuses a project's twins when the workspace policy requires that
    scanner (``_apply_workspace_policy``), because only a policy compares this
    list with names of its own. Two spellings of a declared plugin's section are
    refused earlier (``plugin_section_names.fold_known_plugin_sections``).
    """
    segment = config.scanners
    sections: List[Tuple[str, bool]] = []
    pins: Dict[str, str] = {}

    fields = type(segment).model_fields
    for field_name in fields:
        entry = _field(segment, field_name)
        if entry is None:
            continue
        name = _scanner_display_name(field_name, config)
        on = _section_is_on(entry)
        sections.append((name, on))
        pin = _scanner_pin(entry)
        # A disabled scanner's tool does not run, so its pin constrains nothing
        # and must not refuse the workspace over a sibling's. A policy that
        # requires it switches it on later and its pin is recorded then
        # (_record_pins_the_policy_turns_on).
        if pin is not None and on:
            pins[name] = pin

    groups = _extra_scanner_groups(config)
    for group in groups:
        candidates = group.candidates()
        bodies = {name: _field(segment, name) for name in candidates}
        if not group.unresolved:
            if bodies[group.read] is None:
                continue
            # An extra section's pin is recorded whether or not the section is on:
            # the scan may read it for the reduced name, and which section a
            # plugin's registered name selects is not known until the modules
            # load. The disabled-pin rule above is for declared scanners only.
            sections.append((group.read, _section_is_on(bodies[group.read])))
            pin = _scanner_pin(bodies[group.read])
        else:
            every_section_on = all(_section_is_on(body) for body in bodies.values())
            sections.append((group.read, every_section_on))
            # Every section of the pair counts, a section with no body included:
            # one that sets no pin beside one that does means the pair does not
            # agree, and the version is held, not recorded.
            group_pins = {_scanner_pin(body) for body in bodies.values()}
            pin = group_pins.pop() if len(group_pins) == 1 else None
        if pin is not None:
            pins[group.read] = pin

    keys_of: Dict[str, List[str]] = {}
    for group in groups:
        keys_of.setdefault(group.folded, []).extend(group.names)
    twins = {folded: names for folded, names in keys_of.items() if len(names) > 1}
    enabled = [name for name, on in sections if on]
    return sorted(enabled), pins, twins


def _disabled_scanner_pins(config: AshConfig) -> Dict[str, str]:
    """The pins of the declared scanners whose section is off, by display name.

    ``_scanner_state`` leaves them out, because a scanner that is off does not run
    and its pin constrains nothing. A workspace policy that requires the scanner
    switches the section on and keeps the pin, so
    :func:`_record_pins_the_policy_turns_on` takes it from here once the policy
    is known.
    """
    segment = config.scanners
    held: Dict[str, str] = {}
    for field_name in type(segment).model_fields:
        entry = _field(segment, field_name)
        if entry is None or _section_is_on(entry):
            continue
        pin = _scanner_pin(entry)
        if pin is not None:
            held[_scanner_display_name(field_name, config)] = pin
    return held


def _record_pins_the_policy_turns_on(
    projects: Sequence[ProjectPlan],
    disabled: Dict[str, Dict[str, str]],
    switched: Optional[Dict[str, List[str]]] = None,
) -> bool:
    """Record the pin of each disabled scanner that a project's policy switches on.

    *disabled* maps a project key to ``_disabled_scanner_pins`` of its config.
    The policy is applied after the pins are compared, so the pin of a scanner it
    adds was not in that comparison although the scan applies it. Returns whether
    any pin was added, so the caller compares the projects' pins again.

    When *switched* is given it receives, by project key, the scanners whose pin
    was recorded here, so a refusal can say the project's config has the scanner
    off and the workspace policy is what turned it on.
    """
    recorded = False
    for project in projects:
        if project.skipped or not project.policy_scanners:
            continue
        required = {normalise_scanner_name(name) for name in project.policy_scanners}
        for name, pin in (disabled.get(project.key) or {}).items():
            if (
                normalise_scanner_name(name) in required
                and name not in project.scanner_pins
            ):
                project.scanner_pins[name] = pin
                if switched is not None:
                    switched.setdefault(project.key, []).append(name)
                recorded = True
    return recorded


class _ExtraScanners(NamedTuple):
    """The extra scanner sections that one plugin reads, or one section alone.

    *folded* is the reduced name they claim, *names* the keys in file order, *read*
    the key a lookup by the reduced name reads, and *unresolved* the other keys of
    the group that may be the registered name of the plugin. A reduced name has a
    group for each rank of key that claims it (``plugin_section_peers``).
    """

    folded: str
    names: List[str]
    read: str
    unresolved: List[str]

    def candidates(self) -> List[str]:
        """The sections a scan may read: the one read, and the unresolved ones."""
        return [n for n in self.names if n == self.read or n in self.unresolved]


def _extra_scanner_groups(config: AshConfig) -> List[_ExtraScanners]:
    """Group the extra scanner sections of *config* by the plugin that reads them.

    Declared scanners own the names they claim, so an extra key whose name a
    declared key claims first is left out. The rest are split by rank
    (``plugin_section_peers``), and a section with no body is still a member.
    """
    segment = config.scanners
    fields = type(segment).model_fields
    extra: List[str] = [
        name
        for name in (getattr(segment, "__pydantic_extra__", None) or {})
        if name not in fields
    ]
    claims = plugin_section_claims(
        [*(info.alias or n for n, info in fields.items()), *extra]
    )
    by_name: Dict[str, List[str]] = {}
    for name in extra:
        folded = normalise_scanner_name(name)
        if (claims.get(folded) or [name])[0] in extra:
            by_name.setdefault(folded, []).append(name)

    groups: List[_ExtraScanners] = []
    for folded, names in by_name.items():
        remaining = names
        while remaining:
            claimed = plugin_section_claims(remaining)
            read = plugin_section_key(remaining, folded, claimed)
            if read not in remaining:
                read = remaining[0]
            peers = plugin_section_peers(claimed, read, folded)
            members = [n for n in remaining if n == read or n in peers]
            unresolved = [
                n for n in members if n != read and _REGISTRABLE_SPELLING.fullmatch(n)
            ]
            groups.append(_ExtraScanners(folded, members, read, unresolved))
            remaining = [n for n in remaining if n not in members]
    return groups


def _section_is_on(body: Any) -> bool:
    """Whether a scanner section is enabled; a section with no body is not.

    A body that is a mapping or a model is read by its ``enabled`` field, on by
    default. A bare boolean is that boolean (``acme: false`` turns the section
    off). Any other scalar or a list is no section body: nothing in it can
    enable a scanner, and ``getattr(False, "enabled", True)`` read every such
    body as enabled.
    """
    if body is None or isinstance(body, bool):
        return bool(body)
    if isinstance(body, (str, bytes, int, float, list, tuple, set, frozenset)):
        return False
    return bool(_field(body, "enabled", True))


class _PossiblePins(NamedTuple):
    """The tool versions the scan may apply for one unresolved pair of sections.

    *sections* are the keys of the pair in file order, *pins* the distinct
    versions they set, sorted. A section that sets none adds no version.
    """

    sections: List[str]
    pins: List[str]


def _unresolved_pins(config: AshConfig) -> Dict[str, _PossiblePins]:
    """The versions each unresolved pair of sections may apply, by the name read.

    A pair is the sections of one reduced name that the scan may read: the
    candidates of its group when it holds an unresolved key, and the candidates of
    every group of the name when it has groups of both ranks (``acme`` beside
    ``acme-scanner``), as ``_scanner_state`` returns its twins. The plugin's
    registered name, which the plan cannot tell, selects the section either way.
    Only a pair whose sections do not all set the same pin is held: the plan
    records a pin for the rest (``_scanner_state``), and for the sections of the
    two ranks it records the pin of each on its own. The scan applies the pin of the
    section the registered name selects, so ``_validate_unresolved_pins`` holds each
    version against the other projects' pins. A section with no body, or one that
    sets no pin, differs from one that sets a pin, and contributes no version. A pair
    is held under the key its first group reads.
    """
    segment = config.scanners
    by_name: Dict[str, List[_ExtraScanners]] = {}
    for group in _extra_scanner_groups(config):
        by_name.setdefault(group.folded, []).append(group)

    held: Dict[str, _PossiblePins] = {}
    for groups in by_name.values():
        if len(groups) == 1 and not groups[0].unresolved:
            continue
        sections = [name for group in groups for name in group.candidates()]
        pins = {_scanner_pin(_field(segment, name)) for name in sections}
        if len(pins) > 1:
            held[groups[0].read] = _PossiblePins(
                sections, sorted(pin for pin in pins if pin is not None)
            )
    return held


def _first_clash(mine: List[str], theirs: List[str]) -> Optional[Tuple[str, str, str]]:
    """The first pair of one pin from each list that is not compatible, or ``None``.

    The third item is the reason, worded as ``_validate_scanner_pins`` words it.
    """
    for first in mine:
        for second in theirs:
            comparison = compare_pins(first, second)
            if comparison is PinVerdict.INCOMPATIBLE:
                return first, second, "no version satisfies both"
            if comparison is not PinVerdict.COMPATIBLE:
                return first, second, "ASH cannot prove any version satisfies both"
    return None


def _pins_under_name(
    folded: str, project: ProjectPlan, held: Dict[str, _PossiblePins]
) -> Tuple[List[str], bool]:
    """The versions *project* may apply to the scanner reduced to *folded*, and
    whether any of them comes from a pair it holds.

    The scan reads one section of a scanner in every project, but which key that
    is depends on the order the project writes its sections in, so the plan
    records a pin, or holds a pair, under the key that project's lookup reads.
    Two projects can therefore record one scanner under different spellings. The
    keys are matched by the reduced name they share, as ``_extra_scanner_groups``
    groups them.
    """
    versions = {
        pin
        for name, pin in project.scanner_pins.items()
        if normalise_scanner_name(name) == folded
    }
    pairs = [
        pair for name, pair in held.items() if normalise_scanner_name(name) == folded
    ]
    for pair in pairs:
        versions.update(pair.pins)
    return sorted(versions), bool(pairs)


def _recorded_pins_under_name(folded: str, project: ProjectPlan) -> List[str]:
    """The pins *project* records for the scanner reduced to *folded*, under any spelling."""
    return [
        pin
        for name, pin in project.scanner_pins.items()
        if normalise_scanner_name(name) == folded
    ]


def _validate_unresolved_pins(
    projects: Sequence[ProjectPlan], unresolved: Dict[str, Dict[str, _PossiblePins]]
) -> None:
    """Refuse a workspace where a version an unresolved pair may apply cannot be
    reconciled with the pin of another project.

    *unresolved* maps a project key to what ``_unresolved_pins`` held for it. The
    scan may apply any one version of a pair, so one that no version of the other
    project fits is enough to refuse, as an undecidable comparison is refused in
    ``_validate_scanner_pins``. The pins of the other project are every one it
    records under a key that reduces to the same name as the pair's, whatever the
    spelling (``_pins_under_name``), and each version of a pair it holds under such
    a key. A project that no other project pins has nothing to be compared with,
    and a pair of two such projects is compared once.

    Pairwise compatibility is not enough once two or more other projects pin the
    scanner: a version that fits each of their pins on its own can fit no version
    they allow together (``>=1,<3`` beside ``>=2,<4`` and ``!=2.*``). So each
    version a pair may apply is also held against all the pins the other projects
    record, at once (``compare_pin_set``), when no pairwise clash was found for it.
    The versions another project's own pair may apply are compared pairwise, as
    before: the scan applies only one of them.
    """
    by_key = {project.key: project for project in projects}
    problems: List[str] = []
    for key, by_name in sorted(unresolved.items()):
        for name, mine in sorted(by_name.items()):
            folded = normalise_scanner_name(name)
            before = len(problems)
            for other in projects:
                if other.key == key:
                    continue
                their_pins, theirs_held = _pins_under_name(
                    folded, other, unresolved.get(other.key, {})
                )
                if theirs_held and other.key < key:
                    continue
                verb = "may apply" if theirs_held or len(their_pins) > 1 else "requires"
                clash = _first_clash(mine.pins, their_pins)
                if clash is None:
                    continue
                first, second, reason = clash
                problems.append(
                    text_without_values(
                        f"scanner '{name}': project '{key}' may apply '{first}' "
                        f"(scanners.{' and scanners.'.join(mine.sections)} set "
                        "different tool versions and the plan cannot tell which "
                        f"one the scan reads) and project '{other.key}' {verb} "
                        f"'{second}' -- {reason}",
                        (*by_key[key]._environment_values, *other._environment_values),
                    )
                )
            if len(problems) != before:
                continue
            fixed = sorted(
                {
                    pin
                    for other in projects
                    if other.key != key
                    for pin in _recorded_pins_under_name(folded, other)
                }
            )
            if len(fixed) < 2:
                continue
            for first in mine.pins:
                together = compare_pin_set([first, *fixed])
                if together is PinVerdict.COMPATIBLE:
                    continue
                explanation = (
                    "no one version satisfies all of them together"
                    if together is PinVerdict.INCOMPATIBLE
                    else "ASH cannot prove one version satisfies all of them together"
                )
                problems.append(
                    text_without_values(
                        f"scanner '{name}': project '{key}' may apply '{first}' "
                        f"(scanners.{' and scanners.'.join(mine.sections)} set "
                        "different tool versions and the plan cannot tell which "
                        "one the scan reads) and the other projects require "
                        f"{', '.join(repr(pin) for pin in fixed)}; each of them can "
                        f"be satisfied with it, but {explanation}",
                        tuple(
                            value
                            for project in projects
                            for value in project._environment_values
                        ),
                    )
                )
                break

    if problems:
        raise _refuse(
            "A project's configuration cannot be planned: it holds sections that may "
            "each be the one the plugin lookup reads for a scanner, and a tool "
            "version one of them sets cannot be reconciled with another project's. "
            "One ASH run installs one version of each tool. Keep one section per "
            "scanner, or reconcile the pins:",
            problems,
        )


#: The spelling a plugin could register its name in: lowercase words joined by
#: ``-`` or ``_``. A key in this form may be the exact name a lookup is given.
_REGISTRABLE_SPELLING = re.compile(r"[a-z0-9+]+(?:[-_][a-z0-9+]+)*")


def _scanner_pin(entry: Any) -> Optional[str]:
    """The ``tool_version`` pin of a scanner section, or ``None`` when it sets none."""
    pin = _field(_field(entry, "options"), "tool_version")
    return pin if isinstance(pin, str) and pin.strip() else None


def _twin_section_problems(
    config: AshConfig, project_key: str, twins: Dict[str, List[str]]
) -> Dict[str, str]:
    """One refusal line per reduced scanner name a project holds twins of.

    Built where the project's config is in hand, because the keys may hold values
    the config read from the environment and ``text_without_values`` needs them
    to leave those out. The line names every key of the name: the scan reads one
    of them, and which one depends on the plugin's registered name.
    """
    return {
        folded: text_without_values(
            f"project '{project_key}': scanners.{' and scanners.'.join(names)} "
            f"may each be the section the scan reads as '{folded}'",
            config_environment_values(config),
        )
        for folded, names in sorted(twins.items())
    }


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

    A name the config read from the environment (``!ENV``) is shown by its
    masked form (``text_without_values``), never as the value: the label is
    printed by the plan render, the MCP resolve response, the console summary,
    the workspace HTML table and the aggregate SARIF, none of which may carry an
    environment value.
    """
    default = AshConfig.model_fields["project_name"].default
    declared = getattr(config, "project_name", None)
    if isinstance(declared, str) and declared.strip() and declared != default:
        return text_without_values(declared, config_environment_values(config))
    return key


def _validate_containment(
    definition: WorkspaceDefinition, remote_client: bool = False
) -> List[_Candidate]:
    """Run Phase 0's containment check over every entry, collecting rejections.

    For a remote MCP client a rejection names the entry as the client wrote it
    and the rule it broke. The containment check's own message names the real
    path the entry resolved to, which a client that supplies the workspace file
    could otherwise read for any absolute path or link it names there.
    """
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
            if remote_client:
                problems.append(
                    f"'{folder.path}' is refused ({result.error.violation.value}); "
                    f"the path it reaches is not shown because an MCP client "
                    f"supplied the workspace file"
                )
                continue
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


def _refuse_folders_that_are_not_utf8(
    definition: WorkspaceDefinition, candidates: List[_Candidate]
) -> None:
    """Refuse the entries whose resolved path is not UTF-8, naming every one.

    Each project's path, relative path and key go into the plan and the results
    file, which are UTF-8 only, and pydantic refused the first such project with
    a traceback. Run right after containment, before any project's config is
    read. The root is UTF-8 here: load_workspace_file refused it otherwise. The
    message holds the paths as they are, on one line; each sink shows it once
    (see WorkspacePathNotUtf8Error).
    """
    problems = [
        f"'{candidate.entry}' at '{candidate.resolved.as_posix()}'"
        for candidate in candidates
        if not (
            is_utf8_path(candidate.resolved) and is_utf8_path(Path(candidate.entry))
        )
    ]
    if problems:
        raise WorkspacePathNotUtf8Error(
            f"Workspace '{definition.path.as_posix()}' lists folders whose path is "
            "not UTF-8. The workspace plan and its results hold every project's "
            "path, and they are UTF-8 only, so the workspace cannot be planned: "
            f"{'; '.join(problems)}. Rename each of them. {NOT_UTF8_ON_THE_HOST}"
        )


def _refuse_config_files_that_are_not_utf8(
    workspace_config: Optional[PathLike],
    default_config: Optional[PathLike],
    trusted_config: Optional[PathLike] = None,
) -> None:
    """Refuse a policy file or an operator config whose path is not UTF-8, naming each.

    The plan holds the policy file's resolved path, and the operator's config's
    (``trusted_config`` when the MCP server registered one, else the default
    config) for every project that declares none, and the plan is UTF-8 only:
    both MCP workspace tools built a response their client could not be sent.
    Checked as given, made absolute, and resolved, so a link whose own name is
    UTF-8 does not get around it. Refused whenever given, whether or not a
    project ends up using the operator's config. Run with the folder check,
    before any project's config is read.

    A path that holds a NUL byte is refused here too, as a definition error: no
    file can have that name. It is read off the text itself (``"\\x00" in`` the
    path), not caught from ``Path.resolve``: which inputs pathlib refuses, and
    with what exception, has changed across the supported Python versions, and a
    version whose non-strict ``realpath`` returned normally would have let the
    NUL through this gate (NUL is valid UTF-8) to raise a bare ``ValueError``
    later. The ``ValueError`` arm stays for whatever else the filesystem layer
    refuses. A path that cannot be resolved at all is refused the same way:
    ``Path.resolve`` raises ``RuntimeError`` for a link loop on 3.10 to 3.12
    (and ``OSError`` where the filesystem layer cannot read the chain), which
    escaped as a traceback.
    """
    problems = []
    for described, given in (
        ("the workspace policy file", workspace_config),
        ("the default config, for a project that declares none", default_config),
        ("the operator's registered config", trusted_config),
    ):
        if given is None or given == "":
            continue
        text = os.fspath(given)
        if "\x00" in text:
            raise WorkspaceDefinitionError(
                f"The path given for {described} holds a NUL character, which no "
                f"file's name can: {text!r}."
            )
        absolute = Path(os.path.abspath(text))
        try:
            resolved = absolute.resolve()
        except ValueError as exc:
            raise WorkspaceDefinitionError(
                f"The path given for {described} cannot be a file's name "
                f"({type(exc).__name__} from the filesystem layer): "
                f"{str(absolute)!r}. Check it for a character the filesystem "
                f"layer refuses."
            ) from exc
        except (RuntimeError, OSError) as exc:
            raise WorkspaceDefinitionError(
                f"The path given for {described} cannot be resolved "
                f"({type(exc).__name__} from the filesystem layer): "
                f"{str(absolute)!r}. Check it for a symbolic link that points "
                "back at itself, and that every directory on it can be read."
            ) from exc
        for path in dict.fromkeys((absolute, resolved)):
            if not is_utf8_path(path):
                problems.append(f"{described}, '{path.as_posix()}'")
    if problems:
        raise WorkspacePathNotUtf8Error(
            "A config file the workspace plan names has a path that is not UTF-8. "
            "The plan holds its path, and it is UTF-8 only, so the workspace "
            f"cannot be planned: {'; '.join(problems)}. Rename the file, or the "
            f"directory whose name is not UTF-8, or move it. {NOT_UTF8_ON_THE_HOST}"
        )


#: A directory's identity, ``(st_dev, st_ino)``, or None when it cannot be read or
#: the filesystem gives it no inode (``st_ino == 0``: Python's docs say the inode
#: identifies a file only "if non-zero", and some Windows network shares, RAM
#: disks and FUSE mounts report 0). None never equals anything, so such a
#: directory is judged by its text alone instead of being read as every other.
_Identity = Optional[Tuple[int, int]]


def _directory_identity(path: Path, cache: Dict[Path, _Identity]) -> _Identity:
    """*path*'s identity, read once per path per *cache*.

    One ``stat`` per distinct path: the overlap check compares every pair of
    entries and every ancestor of each, and ``os.path.samefile`` stats both sides
    on every call, which made the check O(N^2 * depth) system calls (about 1.5
    million for 300 projects at depth 8, before anything is scanned).
    """
    if path not in cache:
        try:
            result = os.stat(path)
        except OSError:
            identity: _Identity = None
        else:
            identity = (result.st_dev, result.st_ino) if result.st_ino else None
        cache[path] = identity
    return cache[path]


def _same_directory(
    first: Path, second: Path, cache: Optional[Dict[Path, _Identity]] = None
) -> bool:
    """Whether two canonical paths name one directory.

    Equal as text, or one directory by identity (:func:`_directory_identity`),
    which is what joins ``api`` and ``API`` on a case-insensitive filesystem and
    keeps them apart on a case-sensitive one. A path that cannot be examined, or
    whose filesystem reports no inode, is judged by its text alone; the existence
    check names an unreadable one later.
    """
    if first == second:
        return True
    if cache is None:
        cache = {}
    identity = _directory_identity(first, cache)
    return identity is not None and identity == _directory_identity(second, cache)


def same_config_file(
    first: PathLike, second: PathLike, cache: Optional[Dict[Path, _Identity]] = None
) -> bool:
    """Whether two paths name one config file, by any reading either side used.

    The same text, one file by identity (:func:`_directory_identity`, which joins
    ``/ops/ash.yaml`` and ``/ops/ASH.yaml`` on a case-insensitive filesystem), or
    one file once both are resolved (a link, on a filesystem that reports no
    inode). The planner and the scan both ask this question of a project's config
    and the operator's, and they have to get one answer: a reading either side
    alone admitted made the plan layer the operator's file where the scan
    expected none, or the reverse, and the project was refused at scan time. A
    path that cannot be examined is judged by the readings that can be made.
    """
    left, right = Path(first), Path(second)
    if _same_directory(left, right, cache):
        return True
    try:
        return left.resolve() == right.resolve()
    except (OSError, RuntimeError, ValueError):
        return False


def config_is_the_operators(
    config_path: Optional[PathLike],
    default_config: Optional[PathLike],
    trusted_config: Optional[PathLike] = None,
) -> bool:
    """Whether *config_path* is a file the operator named, not a project's own.

    The operator names two: ``default_config`` (``--config``, or under the MCP
    server the session's copy of the profile) and ``trusted_config`` (the
    profile as it was registered). A project config that is either of them is
    not a config of the project's own, so the operator's file is not layered over
    it and the policy resolver does not treat it as "a project's own config". The
    planner (:func:`_resolve_project_config`, :func:`_apply_workspace_policy`) and
    the scan (``execution._check_the_plans_operator_config``) both decide "own
    config" by this one call, with the same two arguments.
    """
    if config_path is None:
        return False
    cache: Dict[Path, _Identity] = {}
    return any(
        same_config_file(config_path, named, cache)
        for named in (default_config, trusted_config)
        if named is not None and named != ""
    )


def _is_inside(
    inner: Path,
    outer: Path,
    cache: Dict[Path, _Identity],
    root: Optional[Path] = None,
) -> bool:
    """Whether *inner* is below *outer*: by text, or by the identity of one of
    *inner*'s ancestors, so ``Api/sub`` is inside ``api`` where the two spellings
    are one directory.

    Only the ancestors below *root* are read when *inner* is under it: *outer* is
    an entry inside the root, so no directory at or above the root can be it, and
    reading the chain up to ``/`` bought nothing."""
    if inner.is_relative_to(outer):
        return True
    target = _directory_identity(outer, cache)
    if target is None:
        return False
    bounded = root is not None and inner.is_relative_to(root)
    for ancestor in inner.parents:
        if bounded and (ancestor == root or not ancestor.is_relative_to(root)):
            break
        if _directory_identity(ancestor, cache) == target:
            return True
    return False


def _validate_no_overlap(
    definition: WorkspaceDefinition, candidates: List[_Candidate]
) -> None:
    """Reject entries that are the same directory, or nested one inside another.

    Compares canonicalised real paths, which is what catches a symlink alias that
    containment validation accepts, and then the directories themselves by
    identity (``(st_dev, st_ino)``, each path read once): on a case-insensitive
    filesystem whose ``realpath`` keeps the case it was given (macOS APFS by
    default) ``api`` and ``API`` are two texts naming one directory, and a text
    comparison accepted them as two projects to be scanned twice and written to
    one output path.
    """
    problems: List[str] = []
    cache: Dict[Path, _Identity] = {}
    root = Path(definition.root)
    for first, second in combinations(candidates, 2):
        if _same_directory(first.resolved, second.resolved, cache):
            problems.append(
                f"'{first.entry}' and '{second.entry}' resolve to the same "
                f"directory '{first.resolved.as_posix()}'; findings would be "
                f"attributed twice and suppressions applied twice"
            )
        elif _is_inside(second.resolved, first.resolved, cache, root):
            problems.append(
                f"'{second.entry}' is inside '{first.entry}' "
                f"('{second.resolved.as_posix()}' is below "
                f"'{first.resolved.as_posix()}'); overlapping projects would be "
                f"scanned twice"
            )
        elif _is_inside(first.resolved, second.resolved, cache, root):
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
    """Reject two distinct projects that would share a project key.

    Keys that differ only by case are refused as well: a key names the project's
    output directory, and ``projects/Api-sub`` and ``projects/api-sub`` are one
    directory on macOS and Windows. A plan that holds on one host and writes two
    projects' output into one directory on another is refused on both.
    """
    by_key: Dict[str, List[_Candidate]] = {}
    for candidate in candidates:
        by_key.setdefault(candidate.key.casefold(), []).append(candidate)

    problems: List[str] = []
    for group in by_key.values():
        if len(group) < 2:
            continue
        listed = ", ".join(f"'{member.relative.as_posix()}'" for member in group)
        keys = sorted({member.key for member in group})
        if len(keys) == 1:
            problems.append(
                f"{listed} all reduce to the same project key '{keys[0]}', so "
                f"they would share an output path"
            )
        else:
            spelled = ", ".join(f"'{key}'" for key in keys)
            problems.append(
                f"{listed} reduce to the project keys {spelled}, which differ "
                f"only by case and so name one output path on a case-insensitive "
                f"filesystem"
            )

    if problems:
        raise _refuse(
            f"Workspace '{definition.path.as_posix()}' has colliding project keys:",
            problems,
        )


def _unscannable_detail(candidate: _Candidate) -> Optional[str]:
    """Why *candidate* cannot be scanned, or None when it can.

    Read with ``os.stat`` and ``S_ISDIR`` rather than ``Path.is_dir()``: on Python
    3.10-3.13 ``is_dir()`` re-raises a ``PermissionError`` from an unsearchable
    parent directory while 3.14 reads it as absent, so the same locked parent was
    reported as "cannot be examined (Permission denied)" on one version and
    "does not exist as a directory" on another. The stat answers the same on
    every version: a missing entry, or a file on the way to it, does not exist
    as a directory; any other ``OSError`` is a directory that cannot be examined,
    named with the system's reason, never a traceback.
    """
    where = f"'{candidate.entry}' at '{candidate.resolved.as_posix()}'"
    try:
        result = os.stat(candidate.resolved)
    except (FileNotFoundError, NotADirectoryError):
        is_directory = False
    except OSError as exc:
        return f"{where} cannot be examined ({exc.strerror or type(exc).__name__})"
    else:
        is_directory = stat.S_ISDIR(result.st_mode)
    if not is_directory:
        return (
            f"'{candidate.entry}' does not exist as a directory at "
            f"'{candidate.resolved.as_posix()}'"
        )
    if not os.access(candidate.resolved, os.R_OK | os.X_OK):
        return f"{where} is not readable by this process"
    return None


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
        detail = _unscannable_detail(candidate)
        if detail is None:
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


def _as_named(path: Optional[Path]) -> Optional[str]:
    """``path`` made absolute without following a symlink, or None."""
    return Path(os.path.abspath(path)).as_posix() if path is not None else None


def _operator_config(
    default_config: Optional[Path], trusted_config: Optional[Path]
) -> Optional[Path]:
    """The operator's config a workspace layers over each project's own, or None.

    ``trusted_config`` when there is one: under the MCP server, the profile as the
    operator registered it, never the client's patched ``default_config``.
    Otherwise ``default_config``, which ``check_operator_config`` then refuses if
    it is a client's file, so a client's copy is never layered for want of the
    registered one.
    """
    return trusted_config if trusted_config is not None else default_config


def _resolve_project_config(
    candidate: _Candidate,
    config_overrides: Tuple[str, ...] = (),
    default_config: Optional[Path] = None,
    workspace_root: Optional[Path] = None,
    client_config_rules: Optional[ClientConfigRules] = None,
    trusted_config: Optional[Path] = None,
    remote_client: bool = False,
    permit_base: Optional[Callable[[Path], bool]] = None,
) -> Tuple[AshConfig, Optional[Path], Optional[Path]]:
    """Load one project's config through ASH's ordinary resolution path.

    ``workspace_root`` and ``trusted_config`` (``default_config`` when None) are
    passed on as ``scanned_root`` and ``trusted_config_path``, as
    ``execution._project_config_with_policy`` does, so what an in-tree config may
    set (sandbox grants, ``ash_plugin_modules``) is decided against the whole
    workspace here too. The plan's plugin list is what the registry is pre-warmed
    from, before any project's scan resolves its config.

    The two differ under the MCP server when a client patched the session's
    profile: ``default_config`` is then the client's copy, and ``trusted_config``
    the profile as the operator registered it. Taking the client's copy as the
    trusted base would let it grant what it sets; it is refused as one
    (``resolve_config``), and falling back to the defaults would drop the
    profile's own grants.

    The config file is located once and passed back in, rather than letting
    resolution search again, so the file the plan reports is definitionally the
    file that was loaded and the two cannot disagree.

    ``permit_base`` is the MCP session's gate (``cli/mcp/sandbox.config_base_gate``),
    or None for the CLI. It covers the config discovery finds in the project
    (``find_config_file``) and every base its ``extends`` chain names.

    The operator's config, and where it sits in the precedence
    ----------------------------------------------------------
    The operator's config is ``trusted_config``, or ``default_config`` when that
    is None: ``--config`` on the CLI, the profile the session bound or the call
    named under the MCP server. Every field it sets is final for every project,
    and a project's own config fills only the fields it leaves unset:

    * A project with a config of its own resolves that file with the operator's
      layered over it (``resolve_config``'s ``overlay_config_path``), by the
      ``extends`` merge rule with the operator's file as the child: mappings
      merge key by key, and a list the operator sets replaces the project's.
      "Sets" means the key is in the operator's file or its ``extends`` chain,
      whatever its value. The CLI overrides apply after both.
    * A project with none resolves ``default_config`` alone, where ASH's built-in
      default would otherwise apply.

    Rejected: ignoring every project's own config when the operator names one,
    which loses the per-project settings a workspace exists to keep; and taking
    the operator's file as the base with the project merged over it, which lets
    a project turn off ``fail_on_findings`` or ``fail_on_incomplete_scanners``
    that the operator set.

    Under the MCP server the client's patched copy (``default_config`` when it
    differs from ``trusted_config``) is not layered over a project's own config:
    the registered profile is. So a client's values are never final over a
    project, and they are not trusted either: the patched copy is a project's
    config only when the project has none, and is then checked as a file the
    client delivered, as before. A session's operator copy holds only the fields
    the profile sets (``profile_registry.materialize_session_config``), so the
    project still fills the rest.

    Every file the operator's config is built from must be the operator's.
    ``resolve_workspace`` refuses one with a file inside the workspace or one an
    MCP client delivered (``resolve_config.check_operator_config``), as a config
    error, before any project resolves; ``resolve_config`` refuses such an
    overlay again for each project. There is no fallback from a missing
    ``trusted_config`` to a client's ``default_config``: that copy is a client's
    file, so it is refused rather than layered (``_operator_config``).

    These values must reach BOTH this function and
    ``execution._project_config_with_policy``, which re-resolves at scan time:
    the plan's reported threshold comes from this call and the scan's actual
    config from that one, so a value threaded into only one of them makes
    ``--dry-run`` report a plan the scan does not run. The layered file is
    recorded as ``ProjectPlan.operator_config``, which execution reads, and
    ``ProjectScanSettings.default_config_path`` holds ``default_config`` on the
    execution side.

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
        The resolved config; the config file it came from, ``None`` when the
        project has none and took ASH's default config; and the operator's file
        layered over it, ``None`` when nothing was layered.

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
    operator = _operator_config(default_config, trusted_config)
    try:
        # The project directory is one the caller may read, but a source found
        # there may be a link out of it, and discovery reads a pyproject.toml to
        # look for its table; a caller's gate covers every source before any is
        # opened (config_sources.check_discovery_candidates).
        config_path = find_config_file(candidate.resolved, permit=permit_base)
        # A discovered config that is a file the operator named (a link to the
        # --config file, or to the registered profile) is not a config of the
        # project's own: execution decides "own config" by this same call, and a
        # plan that layered the operator's file over itself, or over the other
        # file the operator named, was refused at scan time.
        if config_path is not None and config_is_the_operators(
            config_path, default_config, trusted_config
        ):
            overlay = None
        else:
            overlay = operator if config_path is not None else None
        if config_path is None and default_config is not None:
            config_path = Path(default_config)
        config = resolve_config(
            config_path=config_path,
            source_dir=candidate.resolved,
            fallback_to_default=True,
            config_overrides=list(config_overrides),
            scanned_root=workspace_root,
            trusted_config_path=operator,
            client_config_policy=client_config_rules,
            remote_client=remote_client,
            overlay_config_path=overlay,
            permit_base=permit_base,
        )
        return config, config_path, overlay
    except ASHConfigValidationError as exc:
        raise ASHConfigValidationError(
            f"Project '{candidate.key}' at '{candidate.resolved.as_posix()}' has "
            f"an invalid configuration: {exc}"
        ) from exc


_SWITCHED_ON_BY_POLICY = "switched on by the workspace policy"


def _required_by(
    keys: Sequence[str], scanner: str, switched: Optional[Dict[str, List[str]]]
) -> str:
    """The projects holding a pin, each marked when the policy switched *scanner* on.

    A project whose config has the scanner off and whose pin was recorded only
    because the workspace policy requires the scanner would otherwise be named
    as if it had asked for that version, with nothing to say where to look.
    """
    held = switched or {}
    return ", ".join(
        f"{key} ({_SWITCHED_ON_BY_POLICY})" if scanner in held.get(key, ()) else key
        for key in sorted(keys)
    )


def _validate_scanner_pins(
    definition: WorkspaceDefinition,
    projects: List[ProjectPlan],
    switched: Optional[Dict[str, List[str]]] = None,
) -> None:
    """Refuse a workspace whose projects demand irreconcilable tool versions.

    Only projects that will actually be scanned are compared: a skipped project
    cannot conflict with one that runs. A project's own config does not choose
    ``tool_version`` (``config/tool_config_trust.confine_tool_versions``), so the
    pins recorded are the operator's or the scanner's default; the check still
    holds the plan to one installable version per scanner, whatever set them.

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
        before = len(problems)
        _refuse_incompatible_pin_pairs(scanner, by_pin, problems, switched)
        if len(problems) == before and len(by_pin) > 2:
            # Every pair can be satisfied; that does not prove one version
            # satisfies three or more pins together (scanner_pins.compare_pin_set).
            together = compare_pin_set(sorted(by_pin))
            if together is not PinVerdict.COMPATIBLE:
                listed = "; ".join(
                    f"'{pin}' (required by "
                    f"{_required_by(by_pin[pin], scanner, switched)})"
                    for pin in sorted(by_pin)
                )
                explanation = (
                    "no one version satisfies all of them together"
                    if together is PinVerdict.INCOMPATIBLE
                    else "ASH cannot prove one version satisfies all of them together"
                )
                problems.append(
                    f"scanner '{scanner}': every pair of its pins can be "
                    f"satisfied, but {explanation}: {listed}"
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


def _refuse_incompatible_pin_pairs(
    scanner: str,
    by_pin: Dict[str, List[str]],
    problems: List[str],
    switched: Optional[Dict[str, List[str]]] = None,
) -> None:
    """Append a problem for each pair of *scanner*'s pins no version satisfies."""
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
            f"{_required_by(by_pin[first_pin], scanner, switched)}) and "
            f"'{second_pin}' (required by "
            f"{_required_by(by_pin[second_pin], scanner, switched)}) -- {explanation}"
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
    ``ash_plugin_manager.plugin_modules()``. That method's memo follows the
    registrations, but the registry is process-wide, so the order in which
    projects register still decides what one of them gets:

    * project-without-the-plugin first -- the project that declared the plugin
      keeps it. A memo keyed on the plugin kind alone would make that project
      lose it: a silent false negative, fewer findings than ``ash --source-dir``
      would report, with no warning anywhere.
    * project-with-the-plugin first -- the other project gains a scanner it never
      declared, because the registry holds every module any project loaded.
      This one can still happen.

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

    Each module is named as the plan names it (``ProjectPlan.plugin_module_names``):
    an entry a config read from the environment appears as its masked form, never
    as the value, which is what the plan carries that map for.
    """
    by_modules: Dict[Tuple[str, ...], List[ProjectPlan]] = {}
    for project in projects:
        by_modules.setdefault(tuple(project.ash_plugin_modules), []).append(project)

    if len(by_modules) <= 1:
        return

    problems = []
    for modules, members in sorted(by_modules.items()):
        names = {}
        for member in members:
            names.update(member.plugin_module_names)
        shown = ", ".join(names.get(module, module) for module in modules)
        problems.append(
            f"{', '.join(sorted(member.key for member in members))}: "
            + (shown if modules else "no plugin modules")
        )
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

    A decorated label can equal another project's plain label (a project named
    ``svc (api)`` beside two named ``svc``, one of them keyed ``api``), and
    decorating that plain one can land on a third's (``svc (api) (web)``). So the
    display labels are compared again after each pass: a colliding label that is
    still the project's plain one is decorated, and where only decorated ones
    collide each is decorated with its key once more. Keys are unique, so that
    ends in a few passes; a bound of one pass per project and a numbered suffix
    on whatever still collides make it end whatever the labels are.
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

    for _ in projects:
        shown: Dict[str, int] = {}
        for project in projects:
            shown[project.display_label] = shown.get(project.display_label, 0) + 1
        colliding = [p for p in projects if shown[p.display_label] > 1]
        if not colliding:
            return
        plain = [p for p in colliding if p.display_label == p.label]
        for project in plain or colliding:
            project.display_label = f"{project.display_label} ({project.key})"

    taken: set = set()
    for project in projects:
        label, number = project.display_label, 2
        while label in taken:
            label = f"{project.display_label} #{number}"
            number += 1
        taken.add(label)
        project.display_label = label


def _policy_document(
    suppressions: Any, ignore_paths: Any, scanners: Any
) -> Dict[str, Any]:
    """A workspace policy's effect on a project, written as the config it amounts to.

    Its suppressions and ignore paths land in ``global_settings``, and each
    scanner it adds is a ``scanners.<name>.enabled: true``, so the rules that
    govern a client's config file govern a client's policy file the same way.
    """
    document: Dict[str, Any] = {
        "global_settings": {
            "suppressions": [
                entry.model_dump(mode="json", exclude={"client_supplied"})
                for entry in suppressions or []
            ],
            "ignore_paths": [
                entry.model_dump(mode="json", exclude={"client_supplied"})
                for entry in ignore_paths or []
            ],
        }
    }
    if scanners:
        document["scanners"] = {str(name): {"enabled": True} for name in scanners}
    return document


def _check_a_client_supplied_policy(
    source: Path,
    documents: List[Dict[str, Any]],
    root: Path,
    default_config: Optional[PathLike],
    client_config_rules: Optional[ClientConfigRules],
) -> None:
    """Hold a policy file an MCP client delivered to the rules a client's config file gets.

    ``documents`` are the policy as written and as each active project gets
    it, after its patterns are rewritten for the project (``_policy_document``),
    since a rewritten entry can be one the rules deny when the written one is
    not. Under the default ``denied_paths`` its suppressions and ignore paths
    apply, marked, and an operator's ``denied_value_patterns`` still hold; a
    profile whose own ``denied_paths`` lists them, or a scanner's ``enabled``,
    refuses the file. Its ceiling only tightens a project's threshold, and its
    scanners gate only makes the verdict stricter, so neither is checked.

    Raises:
        ASHConfigFieldDeniedError: The file sets a field the rules deny.
        ASHConfigPolicyUnreadableError: The rules cannot be established.
    """
    from automated_security_helper.config.client_config_policy import (
        _trusted_config,
        client_file_denials,
        denied_fields_message,
        rules_from,
    )
    from automated_security_helper.core.exceptions import (
        ASHConfigFieldDeniedError,
        ASHConfigPolicyUnreadableError,
    )

    rules = client_config_rules or rules_from(
        _trusted_config(default_config, root, None)
    )
    if rules.unreadable is not None:
        raise ASHConfigPolicyUnreadableError(
            f"A workspace policy an MCP client delivered cannot be checked: "
            f"{rules.unreadable}"
        )
    for document in documents:
        found = client_file_denials(
            {source: document}, rules, scanned_root=root, all_delivered=True
        )
        if found:
            path, denials = found[0]
            raise ASHConfigFieldDeniedError(denied_fields_message(path, denials))


def _apply_workspace_policy(
    definition: WorkspaceDefinition,
    projects: List[ProjectPlan],
    workspace_config: Optional[PathLike],
    default_config: Optional[PathLike] = None,
    client_config_rules: Optional[ClientConfigRules] = None,
    trusted_config: Optional[PathLike] = None,
    remote_client: bool = False,
    permit_base: Optional[Callable[[Path], bool]] = None,
    scanner_twins: Optional[Dict[str, Dict[str, str]]] = None,
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

    A policy file an MCP client delivered (``config_is_client_supplied``) is
    checked as a delivered config is (``_check_a_client_supplied_policy``), and
    each suppression and ignore path it pushes down is marked
    ``client_supplied``, so a finding it hides is reported suppressed and
    marked rather than dropped and the files under its ignore paths are still
    scanned. Any other policy's entries are left unmarked, whatever the file
    says: only ASH marks an entry. Delivered is judged at the path the file was
    found or named at, so a delivered link is the client's wherever it points.

    The file that path reaches must be one ``permit_base`` permits, checked
    before it is read. For a delivered file, or any under a remote caller, a
    refusal of its content says where each problem is, not what the file holds.

    *scanner_twins* maps a project key to the refusal line of each reduced name
    that two or more of its extra scanner sections reduce to (``_scanner_state``,
    by reduced name, the keys of every rank together). A project's twins are
    refused only when the policy requires a scanner of that reduced name, and one
    refusal names every project that holds some.

    Returns:
        The path the applied policy file was found or named at, or ``None``
        when there is no policy.

    Raises:
        WorkspaceDefinitionError: Exit code 4, for an unusable policy file, a
            pattern with no sound rewrite for some project, or a project that
            holds more than one section the scan may read for a scanner the policy
            requires. The message names the project as well as the pattern,
            because a workspace-level pattern is legal in itself and only fails
            in combination with one project.
        ASHConfigFieldDeniedError: Exit code 3, for a delivered policy that sets
            a field the rules deny.
        ASHConfigInputNotPermittedError: The policy file is outside what
            ``permit_base`` permits.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    def client_supplied(path: Path) -> bool:
        return remote_client or config_is_client_supplied(path)

    # The configs the projects declared themselves. A project with none records
    # the operator's --config file as its config_source, and that file is the
    # operator's, not a project's, so a policy path that is the same file is not
    # refused as "a project's own ASH config" on its account. The registered
    # profile is the operator's too, and so is a link to either.
    own_configs = [
        Path(project.config_source)
        for project in projects
        if project.config_source
        and not config_is_the_operators(
            project.config_source, default_config, trusted_config
        )
    ]
    policy, source = resolve_workspace_policy(
        definition.root,
        explicit=workspace_config,
        project_config_paths=own_configs,
        permit_base=permit_base,
        client_supplied=client_supplied,
    )
    # The same predicate the loader used: under a remote client every policy
    # file is the client's, so its entries are marked and it is held to the
    # client-config rules, as the ``client_supplied`` closure already said.
    delivered = source is not None and client_supplied(source)
    workspace_policy = policy.workspace if policy else None

    if workspace_policy is not None and scanner_twins:
        required = {
            normalise_scanner_name(name)
            for name in workspace_policy.additional_scanners
        }
        problems = [
            line
            for project in projects
            if not project.skipped
            for reduced, line in (scanner_twins.get(project.key) or {}).items()
            if reduced in required
        ]
        if problems:
            raise _refuse(
                "A project's configuration cannot be planned: it holds more than one "
                "section for a scanner the workspace policy requires, the plugin "
                "lookup reads only one of them, and which one depends on the name "
                "the plugin is registered under. Keep one section per scanner:",
                problems,
            )

    resolved_for: Dict[str, Any] = {}
    for project in projects:
        if project.skipped:
            continue
        resolved_for[project.key] = policy_for_project(
            workspace_policy,
            project_prefix=project.relative_path,
            project_threshold=project.severity_threshold,
            project_scanners=project.scanners,
            # A delivered file's pattern is not quoted in its refusal.
            quote_values=not delivered,
        )
    if workspace_policy is not None:
        # Read across the projects, because one project cannot tell a package
        # copy in a sibling project from a package_path that names no project's
        # copy at all (workspace/policy.py, "Push-down").
        refuse_package_paths_naming_no_project(
            workspace_policy,
            resolved_for.values(),
            every_project_prefix=[project.relative_path for project in projects],
            quote_values=not delivered,
        )
    if delivered and source is not None and workspace_policy is not None:
        _check_a_client_supplied_policy(
            source,
            [
                _policy_document(
                    workspace_policy.suppressions,
                    workspace_policy.ignore_paths,
                    workspace_policy.additional_scanners,
                )
            ]
            + [
                _policy_document(
                    resolved.suppressions,
                    resolved.ignore_paths,
                    resolved.policy_scanners,
                )
                for resolved in resolved_for.values()
            ],
            definition.root,
            trusted_config if trusted_config is not None else default_config,
            client_config_rules,
        )

    for project in projects:
        if project.skipped:
            continue
        resolved = resolved_for[project.key]
        project.effective_severity_threshold = resolved.effective_threshold
        project.threshold_tightened_by_policy = resolved.threshold_tightened
        # The ceiling itself, beside its project-wide effect: a scanner's own
        # options.severity_threshold is bound to it at scan time whether or not
        # it moved the project-wide value.
        project.severity_ceiling = (
            workspace_policy.max_severity_threshold
            if workspace_policy is not None
            else None
        )
        project.policy_suppressions = [
            entry.model_copy(update={"client_supplied": delivered})
            for entry in resolved.suppressions
        ]
        project.policy_ignore_paths = [
            entry.model_copy(update={"client_supplied": delivered})
            for entry in resolved.ignore_paths
        ]
        project.policy_scanners = list(resolved.policy_scanners)
        project.policy_scanners_gate = resolved.policy_scanners_gate

    return source


def _refuse_missing_default_config(default_config: Optional[PathLike]) -> None:
    """Refuse a named default config that is not a file, before any project is read.

    Checked here, not only where a project falls back to it, because every project
    may have its own config, and the file is also the trusted base those projects'
    sandbox grants come from. A missing one used to be skipped without a word, so
    the plan, and ``--dry-run``, described a run with the built-in defaults where
    the operator had named a file. Whether the file parses is left to the
    projects' own resolution, which reads it with the confinement a scan uses.
    """
    if default_config is None:
        return
    if not str(default_config).strip() or not _is_a_regular_file(default_config):
        raise ASHConfigValidationError(
            f"The default configuration file '{default_config}' (--config, or the "
            "profile bound to the MCP session) does not exist, is not a regular "
            "file, or cannot be examined. Name an existing config file, or omit "
            "it so that projects without their own config use ASH's built-in "
            "defaults."
        )


def _is_a_regular_file(path: PathLike) -> bool:
    """Whether *path* is a regular file, a path that cannot be examined read as not.

    ``Path.is_file()`` raised a bare ``PermissionError`` for a file under a
    directory this process cannot search on Python 3.10-3.12, a traceback where
    the caller owes a refusal of the named file.
    """
    try:
        return Path(path).is_file()
    except OSError:
        return False


def _refuse_a_default_config_that_does_not_load(default_config: Path) -> None:
    """Refuse the operator's ``--config`` by its own name when it cannot be read or
    parsed, before a project's resolution quotes it as that project's.

    It is the config of every project that declares none, so it is refused once,
    as the operator's file, rather than once per project. A file that parses and
    does not validate is refused by each project's resolution, which names the
    project. A name with no file there is left to that resolution too.
    """
    import yaml

    from automated_security_helper.config.config_sources import (
        describe_config_path,
        read_config_file,
        unparsed_config_reason,
    )
    from automated_security_helper.core.exceptions import ASHConfigSourceError
    from automated_security_helper.utils.error_text import error_text

    if not _is_a_regular_file(default_config):
        return
    unparsed: Optional[str] = None
    try:
        read_config_file(default_config)
    except ASHConfigValidationError:
        raise
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
        # json.JSONDecodeError, UnicodeDecodeError and a constructor's
        # ValueError are all ValueErrors.
        if isinstance(exc, OSError):
            # Read: the file could not be opened, so there is no syntax to
            # send a reader to.
            raise ASHConfigSourceError(
                f"Config file '{describe_config_path(default_config)}' could not "
                f"be read: {error_text(exc)}"
            ) from exc
        # Anything else here is a parse refusal, and a parser's or
        # a constructor's own words can quote the file (unparsed_config_reason).
        # pydantic's ValidationError, the one excluded ValueError, is never
        # raised here: read_config_file only parses.
        unparsed = unparsed_config_reason(default_config, exc)
    if unparsed is not None:
        # Outside the handler, so the parser's error is not its context.
        raise ASHConfigSourceError(unparsed)


def resolve_workspace(
    workspace_file: PathLike,
    *,
    allow_missing_projects: bool = False,
    workspace_config: Optional[PathLike] = None,
    config_overrides: Tuple[str, ...] = (),
    default_config: Optional[PathLike] = None,
    project_gate: Optional[Callable[[Sequence[Tuple[str, Path]]], None]] = None,
    client_config_rules: Optional[ClientConfigRules] = None,
    trusted_config: Optional[PathLike] = None,
    remote_client: bool = False,
    permit_base: Optional[Callable[[Path], bool]] = None,
    session_id: Optional[str] = None,
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
        default_config: The operator's config file (``--config``). Every field
            it sets is final for every project: it is layered over a project's
            own config, which fills only the fields it leaves unset, and a
            project that declares no config uses it alone in place of ASH's
            built-in default. The MCP server passes the profile a client bound
            with ``select_profile``; see :func:`_resolve_project_config` for the
            precedence, and on why the same value has to reach
            ``ProjectScanSettings.default_config_path`` as well.
        project_gate: Called with ``(key, resolved directory)`` for every
            project that will be scanned, after the definition's own checks and
            before any project's config is read; it raises to refuse the
            workspace. The MCP server passes its scan-root confinement here, so
            a config outside the permitted roots is never read.
        client_config_rules: The rules a config an MCP client delivered is
            checked against (``config/client_config_policy.py``).
        trusted_config: The operator's config the trust checks take as the
            trusted base, when it is not ``default_config``: the registered
            profile, when the MCP client patched the session's copy of it. None
            takes ``default_config``. It is also the file layered over a
            project's own config, so the client's patched copy is not. Must
            reach ``ProjectScanSettings.trusted_config_path`` too.
        remote_client: The workspace is resolved for a remote MCP client, so a
            project config the operator did not set aside resolves no ``!ENV``
            (``resolve_config``). Must reach ``ProjectScanSettings.remote_client``
            too.
        permit_base: The MCP session's gate (``cli/mcp/sandbox.config_base_gate``),
            or None. Every config source in each project's directory, every
            base a project's chain extends, and the workspace policy file must
            resolve to a file it permits; one that is a link out is refused
            before anything opens it (``config_sources.check_discovery_candidates``).
            Must reach ``ProjectScanSettings.config_base_gate`` too. A refusal is
            raised as the project's ``ASHConfigValidationError``, from the
            ``ASHConfigInputNotPermittedError``, and names neither the file's
            target nor anything in it.
        session_id: The MCP session the workspace is resolved for, or None. The
            operator config's chain is judged for ``!ENV`` with it
            (``resolve_config.check_operator_config``), as each project's
            resolution judges its chain with ``client_config_rules.session_id``:
            for a remote caller only that session's own bound profile is set
            aside, so a non-default session's profile that uses ``!ENV`` is
            accepted at planning as it is at each project's scan. None reads the
            session from ``client_config_rules`` when those carry one; given
            beside rules that carry a different session, it is refused (see
            Raises), because the operator check and each project's resolution
            would then judge two sessions, the planning-vs-scan mismatch this
            parameter exists to remove.

    Returns:
        A :class:`~automated_security_helper.workspace.plan.WorkspacePlan` with
        one entry per folder in the definition, skipped ones included.

    Raises:
        WorkspaceDefinitionError: Exit code 4. The definition is malformed, or an
            entry escapes the workspace root, is a symlink, names the root, does
            not exist, is unreadable, overlaps another entry, collides on its
            key, or pins a scanner version irreconcilable with another project's.
            The message names every offending entry. A workspace file, root,
            entry, policy file, default config or registered ``trusted_config``
            whose path is not UTF-8 raises its WorkspacePathNotUtf8Error subclass,
            and a policy file, default config or registered config whose path
            holds a NUL character, or cannot be resolved, raises the plain error,
            each before any project's config is read.
        ASHConfigValidationError: Exit code 3. The workspace is fine but one
            project's own config is invalid, or cannot be loaded, or
            ``default_config`` names a file that does not exist. The message
            names the project or the file.
        ValueError: ``session_id`` and ``client_config_rules.session_id`` are
            both given and differ. A caller's error, not the workspace's: the
            two would judge the operator config and the projects for two
            different sessions.
    """
    rules_session = getattr(client_config_rules, "session_id", None)
    if (
        session_id is not None
        and rules_session is not None
        and session_id != rules_session
    ):
        raise ValueError(
            f"resolve_workspace: session_id {session_id!r} differs from "
            f"client_config_rules.session_id {rules_session!r}; the operator "
            f"config and the projects would be judged for two sessions"
        )
    operator_session = session_id if session_id is not None else rules_session

    definition = load_workspace_file(workspace_file)

    candidates = _validate_containment(definition, remote_client=remote_client)
    _refuse_folders_that_are_not_utf8(definition, candidates)
    _refuse_config_files_that_are_not_utf8(
        workspace_config, default_config, trusted_config
    )
    _validate_no_overlap(definition, candidates)
    _validate_unique_keys(definition, candidates)
    _apply_existence_checks(definition, candidates, allow_missing_projects)
    _refuse_missing_default_config(default_config)

    if all(candidate.skipped for candidate in candidates):
        raise WorkspaceDefinitionError(
            f"Workspace '{definition.path.as_posix()}' has no project left to "
            f"scan: every folder it lists was skipped. Exiting 0 here would "
            f"report a clean result for a workspace nothing examined."
        )

    if project_gate is not None:
        project_gate([(c.key, c.resolved) for c in candidates if not c.skipped])

    if default_config is not None:
        _refuse_a_default_config_that_does_not_load(Path(default_config))

    operator = _operator_config(
        Path(default_config) if default_config else None,
        Path(trusted_config) if trusted_config else None,
    )
    operator_digest: Optional[str] = None
    if operator is not None:
        # Once for the whole workspace, so a project with no config of its own,
        # which uses the operator's file alone, is refused with the rest. Under
        # the caller's gate: the file's extends chain is opened here, before any
        # project's resolution applies the same gate to the same file. With the
        # call's session, so the !ENV judgement is the one each project's
        # resolution makes (resolve_config reads client_config_policy.session_id);
        # the two sources were checked to agree above.
        check_operator_config(
            operator,
            definition.root,
            permit_base=permit_base,
            remote_client=remote_client,
            session_id=operator_session,
        )
        operator_digest = operator_config_digest(operator)

    projects: List[ProjectPlan] = []
    scanner_twins: Dict[str, Dict[str, str]] = {}
    unresolved_pins: Dict[str, Dict[str, _PossiblePins]] = {}
    disabled_pins: Dict[str, Dict[str, str]] = {}
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

        config, config_path, operator_config = _resolve_project_config(
            candidate,
            config_overrides,
            default_config=Path(default_config) if default_config else None,
            workspace_root=definition.root,
            client_config_rules=client_config_rules,
            trusted_config=Path(trusted_config) if trusted_config else None,
            remote_client=remote_client,
            permit_base=permit_base,
        )
        scanners, pins, twins = _scanner_state(config)
        disabled_pins[candidate.key] = _disabled_scanner_pins(config)
        if twins:
            scanner_twins[candidate.key] = _twin_section_problems(
                config, candidate.key, twins
            )
        held = _unresolved_pins(config)
        if held:
            unresolved_pins[candidate.key] = held
        label = _project_label(config, candidate.key)
        project = ProjectPlan(
            key=candidate.key,
            relative_path=candidate.relative.as_posix(),
            path=candidate.resolved.as_posix(),
            label=label,
            # Settled below by _assign_display_labels, which needs the whole
            # sibling set to know whether this label is ambiguous.
            display_label=label,
            # By the path the project holds it at, not the file a link there
            # reaches: execution re-resolves from it, and a file is judged by
            # every path it was reached by (config_sources, "Base paths"). The
            # sandbox check needs the config's own name too, and a symlinked
            # .ash.yaml resolves out of the project.
            config_source=_as_named(config_path),
            operator_config=_as_named(operator_config),
            # For every project the operator's file governs: layered over the
            # project's own config, or the project's config itself because it
            # declares none. A rewrite of that file between plan and scan is
            # then detectable for the second kind too.
            operator_config_digest=operator_digest,
            scanners=scanners,
            severity_threshold=config.global_settings.severity_threshold,
            scanner_pins=pins,
            ash_plugin_modules=_project_plugin_modules(config),
            plugin_module_names=config_module_names(config),
        )
        # Private: no dump of the plan shows it (ProjectPlan._environment_values).
        project._environment_values = config_environment_values(config)
        projects.append(project)

    active = [project for project in projects if not project.skipped]
    _validate_scanner_pins(definition, active)
    _validate_unresolved_pins(active, unresolved_pins)
    _validate_plugin_modules(definition, active)
    _assign_display_labels(projects)
    policy_source = _apply_workspace_policy(
        definition,
        projects,
        workspace_config,
        default_config=default_config,
        client_config_rules=client_config_rules,
        trusted_config=trusted_config,
        remote_client=remote_client,
        permit_base=permit_base,
        scanner_twins=scanner_twins,
    )
    # A scanner the policy switches on keeps the pin of its off section, and the
    # comparisons above ran before the policy was known: the pairs a project's
    # sections may apply are held against the new pin as well.
    switched_on: Dict[str, List[str]] = {}
    if _record_pins_the_policy_turns_on(active, disabled_pins, switched_on):
        _validate_scanner_pins(definition, active, switched_on)
        _validate_unresolved_pins(active, unresolved_pins)

    return WorkspacePlan(
        workspace_file=definition.path.as_posix(),
        workspace_root=definition.root.as_posix(),
        workspace_config_source=(
            policy_source.as_posix() if policy_source is not None else None
        ),
        projects=projects,
        allow_missing_projects=allow_missing_projects,
    )
