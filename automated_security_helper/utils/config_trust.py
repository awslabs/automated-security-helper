# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which configuration values the operator set, and which the scanned tree set.

Why this exists
---------------
Unless ``--config`` names a file elsewhere, ASH reads its configuration from the tree
it scans (``.ash/.ash.yaml`` and the other discovered names). A few options of the
actionlint, cfn-lint and trivy fs scanners name something the scanner's tool executes
or loads as code:

* actionlint's ``shellcheck`` and ``pyflakes``: the program actionlint pipes every
  ``run:`` script to;
* cfn-lint's ``config_file``: a ``.cfnlintrc``, whose ``append_rules`` makes cfn-lint
  import Python files as rules;
* trivy's and trivy-repo's ``config_file``: a ``trivy.yaml``, which can point trivy
  at a directory of WASM modules and enable them, and trivy-repo's ``module_dir``,
  which names that directory directly.

Before a scanner hands such a value to its tool it asks ``set_by_operator``, and it
refuses a path inside the scanned tree whoever named it, with
``config/path_trust.py``'s ``in_scanned_tree`` (from ``scan_root``), the test every
other scanner's tool config and plugin paths go through.

Options that name a file or directory a tool reads as its own configuration, even
one that only tunes findings (a gitleaks baseline, a zizmor or actionlint config,
cfn-guard rules), go through ``operator_path`` or its list form ``operator_paths``:
the value is used only when the operator set it, as the resolved path that was
checked. A repository could otherwise hide its own findings, or, for a tool that
prints a file it cannot parse, put any file the scan can read into the report. For
the same reason a path the operator writes inside the tree is refused when a
symbolic link there leads it out of the tree (``leaves_the_tree_through_a_link``).

This module and ``config/sandbox_grants.py`` share their idea of the tree and of the
trusted base. ``set_by_operator`` is the only provenance call the scanners make, so a
shared implementation can replace this one behind it.

How the answer is reached
-------------------------
``resolve_config`` records a ``ConfigProvenance`` on the config it returns. It uses
the same facts ``config/sandbox_grants.py`` uses for the sandbox's grants: a config
is not the operator's when any file it was built from, an ``extends`` base
included, is repository-written (``sandbox_grants.repository_written``: inside any
git checkout, or inside the scanned directory when that is outside every checkout,
or delivered by an MCP client), and the operator's values are those of the trusted
base plus ``--config-overrides``. A value is the operator's when the config was
built from no repository-written file, or when resolving the trusted base plus the
overrides gives the same value. ("In the tree" below means repository-written.) Comparing resolutions, not override key names,
makes ``key+=``, the dashed scanner spelling and a whole-section override count the
same as ``key=value``.

Overrides an MCP client supplied (``resolve_config(client_overrides=True)``) are not
the operator's, as they are not for ``config/path_trust.OperatorPaths``: they are
left out of the replay, and a config built from no file in the tree is then
compared with the operator's files as resolved before those overrides, so a value
only the client set is not the operator's.

Constraints and failure modes
-----------------------------
* Fail closed. A config with no recorded provenance (one built without
  ``resolve_config``) counts as the tree's, and so does a key whose trusted value
  cannot be resolved because an override does not apply to the bare trusted base.
  The overrides of a section are replayed together first, as the scan applies
  them, and one at a time when the batch does not apply, so such an override
  makes only the keys it writes to (and the keys above them) unresolvable; the
  other keys of the section keep their trusted value, and a pair of overrides
  valid only together stays the operator's.
* A trusted config outside the tree that ``extends`` a base inside it counts as the
  tree's as a whole, as it does for the sandbox's grants: the merged document does not
  record which file set a value. Set such a value with ``--config-overrides``.
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING

PathLike = Union[str, "os.PathLike[str]"]

_MISSING = object()


@dataclass
class ConfigProvenance:
    """Where a resolved config came from.

    Attributes:
        in_tree: The config files it was built from that are repository-written
            (``sandbox_grants.repository_written``). Empty, with no
            ``client_overrides``, means the operator's: a file that is not, or none.
        trusted: The config the operator's values come from when ``in_tree`` or
            ``client_overrides`` is not empty: the trusted base, before the
            overrides below. With only ``client_overrides``, the config as the
            operator's files resolved it, before the client's overrides.
        overrides: The operator's ``--config-overrides``, replayed onto
            ``trusted``.
        client_overrides: Overrides an MCP client supplied
            (``resolve_config(client_overrides=True)``). They are applied to the
            config but are not the operator's, so they are not replayed, and a
            value only they set is not the operator's.
    """

    in_tree: Tuple[Path, ...] = ()
    trusted: Any = None
    overrides: Tuple[str, ...] = ()
    client_overrides: Tuple[str, ...] = ()
    _resolved: Dict[str, Any] = field(default_factory=dict, repr=False)

    def trusted_value(self, key: str) -> Any:
        """The value at ``key`` in the trusted base plus the overrides under it.

        ``_MISSING`` when there is no trusted base, or when an override that
        writes to ``key``, to a key under it or to a key above it cannot be
        applied to the base: that override's effect on ``key`` cannot be told.
        An override elsewhere in the section that fails leaves ``key`` resolved.
        """
        section = _key_parts(key)[0]
        if section not in self._resolved:
            self._resolved[section] = self._resolve_section(section)
        resolved = self._resolved[section]
        if resolved is _MISSING:
            return _MISSING
        asked = _key_parts(key)
        if any(_one_under_the_other(asked, failed) for failed in resolved.failed):
            return _MISSING
        return value_at(resolved.value, key)

    def _resolve_section(self, section: str) -> Any:
        """The trusted base with the section's overrides replayed.

        The section's overrides are applied together first, as the scan applies
        them: ``apply_config_overrides`` validates the configuration it returns,
        so two overrides that are valid only together (a mode and the path that
        mode requires) are taken as the operator wrote them. Only when the batch
        raises is each override applied on its own, in the order given, so one
        that the bare trusted base cannot take (it writes under a section only
        the tree's config introduced, say) is recorded in ``failed`` by its key
        and the others still apply. Replayed together alone, one such override
        made the whole section unresolvable, and every key under ``scanners``
        then read as not the operator's; replayed one at a time alone, a pair
        valid only together failed, and the operator's own value read as not
        the operator's.
        """
        if self.trusted is None:
            return _MISSING
        mine = [o for o in self.overrides if _key_parts(_override_key(o))[0] == section]
        base = copy.deepcopy(self.trusted)
        if not mine:
            return _ResolvedSection(base, ())
        from automated_security_helper.config.resolve_config import (
            apply_config_overrides,
        )

        try:
            return _ResolvedSection(apply_config_overrides(base, mine), ())
        except Exception:  # noqa: BLE001 - any failure means "cannot tell"
            pass
        # The batch may have been applied in part before it raised; replay from
        # an untouched copy of the base.
        base = copy.deepcopy(self.trusted)
        failed: List[Tuple[str, ...]] = []
        for override in mine:
            try:
                base = apply_config_overrides(base, [override])
            except Exception:  # noqa: BLE001 - any failure means "cannot tell"
                failed.append(_key_parts(_override_key(override)))
        return _ResolvedSection(base, tuple(failed))


@dataclass(frozen=True)
class _ResolvedSection:
    """One section of the trusted base with its overrides replayed.

    ``failed`` holds the key of each override the base could not take, as its
    folded parts (:func:`_key_parts`).
    """

    value: Any
    failed: Tuple[Tuple[str, ...], ...]


def _override_key(override: Any) -> str:
    """The dotted key a ``--config-overrides`` entry writes to, ``key=value`` and
    ``key+=value`` alike."""
    return str(override).partition("=")[0].strip().removesuffix("+")


def _key_parts(key: str) -> Tuple[str, ...]:
    """The segments of dotted ``key``, with ``-`` read as ``_`` in each, as the
    config accepts either spelling (:func:`value_at`)."""
    return tuple(part.replace("-", "_") for part in key.split("."))


def _one_under_the_other(first: Tuple[str, ...], second: Tuple[str, ...]) -> bool:
    """Whether one key is the other, or lies under it."""
    shorter = min(len(first), len(second))
    return first[:shorter] == second[:shorter]


def record_provenance(
    config: Any,
    *,
    in_tree: Sequence[Path],
    trusted: Any = None,
    config_overrides: Optional[Iterable[Any]] = None,
    client_overrides: Optional[Iterable[Any]] = None,
) -> None:
    """Attach a ``ConfigProvenance`` to ``config`` (an ``AshConfig``).

    ``config_overrides`` are the operator's; ``client_overrides`` an MCP client's.
    """
    config._provenance = ConfigProvenance(
        in_tree=tuple(in_tree),
        trusted=trusted,
        overrides=tuple(str(o) for o in (config_overrides or [])),
        client_overrides=tuple(str(o) for o in (client_overrides or [])),
    )


def _spellings(part: str) -> Tuple[str, ...]:
    return tuple(dict.fromkeys((part, part.replace("-", "_"), part.replace("_", "-"))))


def value_at(config: Any, key: str) -> Any:
    """The value at dotted ``key`` in ``config``, or ``_MISSING``.

    Walks pydantic models by field name or alias and dicts by key, trying each
    segment with ``-`` and ``_`` interchanged, as the config accepts both.
    """
    current: Any = config
    for part in key.split("."):
        found: Any = _MISSING
        for spelling in _spellings(part):
            if isinstance(current, dict):
                if spelling in current:
                    found = current[spelling]
                    break
                continue
            if hasattr(current, "model_fields"):
                for name, info in type(current).model_fields.items():
                    if spelling in (name, info.alias):
                        found = getattr(current, name)
                        break
                if found is not _MISSING:
                    break
                extra = getattr(current, "__pydantic_extra__", None) or {}
                if spelling in extra:
                    found = extra[spelling]
                    break
        if found is _MISSING:
            return _MISSING
        current = found
    if hasattr(current, "model_dump"):
        return current.model_dump()
    return current


def _comparable(value: Any) -> Any:
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    return value


def _same_value(expected: Any, value: Any) -> bool:
    """Whether the trusted value and the value about to be used are the same.

    A scanner holds a path option as a ``Path`` where the config holds the string,
    so when either side is a path both are compared as paths: on Windows
    ``str(Path("/x/rc"))`` is ``\\x\\rc``, which no string comparison matches
    with ``/x/rc``. Two strings are compared as strings, exactly as written:
    ``operator_path`` resolves ``value`` as given, so a value that differs from
    the operator's by a leading or trailing character (whitespace, or one of the
    separators ``str.strip`` also removes that the config model keeps) names a
    different path and is not the operator's.
    """
    as_paths = isinstance(expected, os.PathLike) or isinstance(value, os.PathLike)
    expected, value = _comparable(expected), _comparable(value)
    if as_paths and isinstance(expected, str) and isinstance(value, str):
        return PurePath(expected) == PurePath(value)
    return expected == value


def operator_value(config: Any, key: str) -> Tuple[bool, Any]:
    """The operator's own value for dotted ``key``, when ``config`` records one.

    ``(True, value)`` when ``config`` carries a provenance whose trusted base plus
    the operator's ``--config-overrides`` resolves ``key``; ``(False, None)`` when
    ``config`` carries no provenance, no trusted base, the key is not there, or an
    override cannot be applied to the bare trusted base. A scanner that ignores a
    value the repository or an MCP client set takes this value in its place, so a
    client cannot narrow the operator's choice down to the default by writing the
    default: ``set_by_operator`` says whether the value about to be used is the
    operator's, and this says what the operator's is. The value is the trusted
    base's own object (a model is dumped), so a caller that changes it copies it.
    """
    provenance = getattr(config, "_provenance", None)
    if not isinstance(provenance, ConfigProvenance):
        return False, None
    found = provenance.trusted_value(key)
    if found is _MISSING:
        return False, None
    return True, found


def set_by_operator(config: Any, key: str, value: Any) -> bool:
    """Whether ``value``, about to be used for dotted ``key``, is the operator's.

    True when ``config`` was built from no file inside the scanned tree and no MCP
    client's overrides, or when the trusted base plus the operator's
    ``--config-overrides`` resolves ``key`` to ``value``. False otherwise, including
    when ``config`` carries no provenance. The value the scanner will use is
    compared, rather than the one at ``key`` in ``config``, so a scanner constructed
    with options of its own is judged by what it would actually run.
    """
    provenance = getattr(config, "_provenance", None)
    if not isinstance(provenance, ConfigProvenance):
        return False
    if not provenance.in_tree and not provenance.client_overrides:
        return True
    expected = provenance.trusted_value(key)
    if expected is _MISSING:
        return False
    return _same_value(expected, value)


def scan_root(config: Any, source_dir: PathLike) -> Path:
    """The root ``config/path_trust.py``'s ``in_scanned_tree`` takes for this scan.

    The config's recorded scanned root (the workspace root in workspace mode), else
    ``source_dir``, as ``path_trust.honored_path`` decides it.
    """
    return Path(getattr(config, "_scanned_root", None) or source_dir)


#: Why ``operator_path`` refused a value the operator did not set. A warning that
#: gives it ends with the remedy every confinement warning ends with,
#: ``confinement_remedy.KEEP_A_SETTING`` (``refusal_warning``).
NOT_THE_OPERATORS = (
    "it came from a config file inside a git checkout or the scanned directory, or "
    "from an MCP client"
)


def refusal_warning(message: str, refusal: Optional[str]) -> str:
    """``message``, ending with ``KEEP_A_SETTING`` when ``refusal`` is ``NOT_THE_OPERATORS``.

    Only that refusal is the operator's to undo by moving the setting. A path
    refused for where it is (``INSIDE_THE_TREE``, ``LEADS_OUT_OF_THE_TREE``) is not,
    and its message says what to name instead.
    """
    if refusal == NOT_THE_OPERATORS:
        return f"{message} {KEEP_A_SETTING}"
    return message


#: Why ``operator_path`` refused a path inside the scanned tree.
INSIDE_THE_TREE = "it is inside the scanned tree"

#: Why ``operator_path`` refused a path in the scanned tree that a symbolic link
#: there leads out of it (``leaves_the_tree_through_a_link``).
LEADS_OUT_OF_THE_TREE = (
    "it is a path inside the scanned tree that resolves outside it through a "
    "symbolic link, and the scanned repository decides what is at that path"
)


def leaves_the_tree_through_a_link(
    value: Any, source_dir: PathLike, root: PathLike
) -> bool:
    """Whether ``value`` follows a symbolic link inside the scanned tree and ends
    outside it.

    The one check every tool path goes through:
    ``config/path_trust.leaves_the_tree_through_a_link``, which finds each link the
    kernel's lookup of the path as written follows (``utils/link_locations``), at
    any depth and through a chain of links. A path that leaves by ``..`` with no
    link in the tree is the path as written: ``../shared.toml`` from the source
    directory names a file next to the tree.
    """
    from automated_security_helper.config import path_trust

    return path_trust.leaves_the_tree_through_a_link(
        value, Path(source_dir), Path(root)
    )


@dataclass(frozen=True)
class OperatorPath:
    """The outcome of ``operator_path``: the path to use, or why there is none."""

    path: Optional[Path]
    refusal: Optional[str] = None


def operator_path(
    config: Any,
    key: str,
    value: Any,
    source_dir: PathLike,
    *,
    outside_tree: bool = True,
    operator_wrote: bool = False,
) -> OperatorPath:
    """``value`` as the path a tool will read, when the operator chose it.

    The one rule for a scanner option that names a file or directory a tool reads:
    used only when ``set_by_operator`` accepts ``value`` for ``key`` (or the
    caller says the operator wrote it, ``operator_wrote``: a scanner configuration
    the embedding caller built itself, judged by
    ``operator_only_options.operator_wrote_value``) and, with
    ``outside_tree``, when it resolves outside the scanned tree
    (``config/path_trust.in_scanned_tree``, from ``scan_root``). The path returned
    is ``path_trust.resolved_path`` of ``value`` (``~`` expanded, relative to
    ``source_dir``, symlinks and ``..`` resolved), the same path that was checked,
    so a caller hands the tool exactly that and nothing rebuilt from ``value``.
    Whether the file exists is left to the caller, which knows whether a missing
    one should fail the scan.

    ``outside_tree`` is for a file whose content can make the tool run code, or
    that ``path_trust`` already keeps out of the tree for every scanner; such a
    file is refused inside the tree even when the operator named it. Without it,
    the operator may name a file of their own in the tree (a findings config, a
    baseline, a rules directory), which is a choice about that tree's content
    they are entitled to make.

    Either way, what a path written inside the tree leads to is the tree's choice,
    so one that resolves outside the tree through a symbolic link in it is refused
    with ``LEADS_OUT_OF_THE_TREE``: with ``outside_tree`` the link would otherwise
    pass the check on where the path lands, and choose a program or config
    outside the tree. A scanner that must not run without the operator's file
    turns that refusal into its own failure instead of ignoring the option.
    """
    return _operator_candidate(
        config,
        value,
        source_dir,
        operator_wrote or set_by_operator(config, key, value),
        outside_tree,
    )


def operator_paths(
    config: Any,
    key: str,
    values: Sequence[Any],
    source_dir: PathLike,
    *,
    outside_tree: bool = True,
) -> List[OperatorPath]:
    """``operator_path`` for an option that holds a list of paths, entry by entry.

    Provenance is decided per entry: the whole list is the operator's when
    ``set_by_operator`` accepts it as set, and otherwise an entry is the
    operator's when the trusted base plus the operator's overrides holds that
    entry in the list at ``key`` (:func:`_operator_entries`). So an entry the
    operator appended with ``key+=`` to a list a tree config also fills is used,
    and the tree's own entries are refused. Each entry the operator set is then
    resolved and, with ``outside_tree``, checked on its own. A list the operator
    did not set gives one refusal per entry, so a caller can name each one it
    ignores.
    """
    entries = list(values)
    return [
        _operator_candidate(config, entry, source_dir, trusted, outside_tree)
        for entry, trusted in zip(entries, _operator_entries(config, key, entries))
    ]


def _operator_entries(config: Any, key: str, entries: List[Any]) -> List[bool]:
    """Whether each of ``entries``, the list about to be used for ``key``, is
    the operator's.

    Every entry is, when ``set_by_operator`` accepts the list as a whole; else an
    entry is, when the trusted base plus the operator's overrides resolves
    ``key`` to a list holding it, and the list holds every entry of the
    operator's. An entry of the tree's, and every entry when the trusted list
    cannot be resolved, is not. Nor is any entry when the list leaves one of the
    operator's own entries out: a tree config that writes ``[A]`` over the
    operator's ``[A, B]`` chose which of the operator's rules run, and taking
    ``A`` alone as the operator's would drop ``B`` with no refusal, no warning
    and no fallback. Refusing the whole list gives the caller one refusal per
    entry, as a list the operator did not set does, so it warns and falls back.
    """
    if set_by_operator(config, key, entries):
        return [True] * len(entries)
    provenance = getattr(config, "_provenance", None)
    if not isinstance(provenance, ConfigProvenance):
        return [False] * len(entries)
    expected = provenance.trusted_value(key)
    if expected is _MISSING or not isinstance(expected, (list, tuple)):
        return [False] * len(entries)
    if any(
        not any(_same_value(trusted_entry, entry) for entry in entries)
        for trusted_entry in expected
    ):
        return [False] * len(entries)
    return [
        any(_same_value(trusted_entry, entry) for trusted_entry in expected)
        for entry in entries
    ]


def _operator_candidate(
    config: Any,
    value: Any,
    source_dir: PathLike,
    trusted: bool,
    outside_tree: bool,
) -> OperatorPath:
    """The body of ``operator_path``, given its provenance verdict."""
    from automated_security_helper.config.path_trust import (
        in_scanned_tree,
        resolved_path,
    )

    if not trusted:
        return OperatorPath(None, NOT_THE_OPERATORS)
    root = scan_root(config, source_dir)
    candidate = resolved_path(value, Path(source_dir))
    if outside_tree and in_scanned_tree(candidate, root):
        return OperatorPath(None, INSIDE_THE_TREE)
    if leaves_the_tree_through_a_link(value, source_dir, root):
        return OperatorPath(None, LEADS_OUT_OF_THE_TREE)
    return OperatorPath(candidate)
