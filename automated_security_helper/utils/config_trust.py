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

This module and ``config/sandbox_grants.py`` share their idea of the tree and of the
trusted base. ``set_by_operator`` is the only provenance call the scanners make, so a
shared implementation can replace this one behind it.

How the answer is reached
-------------------------
``resolve_config`` records a ``ConfigProvenance`` on the config it returns. It uses
the same facts ``config/sandbox_grants.py`` uses for the sandbox's grants: the
scanned tree is the outermost enclosing checkout (``scanned_trees``), a config file is in it when
it or any ``extends`` base is (``files_inside``), and the operator's values are those
of the trusted base plus ``--config-overrides``. A value is the operator's when the
config was not built from a file in the tree, or when resolving the trusted base plus
the overrides gives the same value. Comparing resolutions, not override key names,
makes ``key+=``, the dashed scanner spelling and a whole-section override count the
same as ``key=value``.

Constraints and failure modes
-----------------------------
* Fail closed. A config with no recorded provenance (one built without
  ``resolve_config``) counts as the tree's, and so does a key whose trusted value
  cannot be resolved because an override does not apply to the bare trusted base.
* A trusted config outside the tree that ``extends`` a base inside it counts as the
  tree's as a whole, as it does for the sandbox's grants: the merged document does not
  record which file set a value. Set such a value with ``--config-overrides``.
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple, Union

PathLike = Union[str, "os.PathLike[str]"]

_MISSING = object()


@dataclass
class ConfigProvenance:
    """Where a resolved config came from.

    Attributes:
        in_tree: The config files it was built from that are inside the scanned
            tree. Empty means the operator's: a file outside the tree, or none.
        trusted: The config the operator's values come from when ``in_tree`` is
            not empty: the trusted base, before the overrides below.
        overrides: The ``--config-overrides`` given to the resolution.
    """

    in_tree: Tuple[Path, ...] = ()
    trusted: Any = None
    overrides: Tuple[str, ...] = ()
    _resolved: Dict[str, Any] = field(default_factory=dict, repr=False)

    def trusted_value(self, key: str) -> Any:
        """The value at ``key`` in the trusted base plus the overrides under it.

        ``_MISSING`` when there is no trusted base or an override cannot be
        applied to it.
        """
        section = key.split(".")[0]
        if section not in self._resolved:
            self._resolved[section] = self._resolve_section(section)
        resolved = self._resolved[section]
        if resolved is _MISSING:
            return _MISSING
        return value_at(resolved, key)

    def _resolve_section(self, section: str) -> Any:
        if self.trusted is None:
            return _MISSING
        mine = [
            o
            for o in self.overrides
            if str(o).partition("=")[0].removesuffix("+").split(".")[0] == section
        ]
        base = copy.deepcopy(self.trusted)
        if not mine:
            return base
        from automated_security_helper.config.resolve_config import (
            apply_config_overrides,
        )

        try:
            return apply_config_overrides(base, mine)
        except Exception:  # noqa: BLE001 - any failure means "cannot tell"
            return _MISSING


def record_provenance(
    config: Any,
    *,
    in_tree: Sequence[Path],
    trusted: Any = None,
    config_overrides: Optional[Iterable[Any]] = None,
) -> None:
    """Attach a ``ConfigProvenance`` to ``config`` (an ``AshConfig``)."""
    config._provenance = ConfigProvenance(
        in_tree=tuple(in_tree),
        trusted=trusted,
        overrides=tuple(str(o) for o in (config_overrides or [])),
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
    return value.strip() if isinstance(value, str) else value


def _same_value(expected: Any, value: Any) -> bool:
    """Whether the trusted value and the value about to be used are the same.

    A scanner holds a path option as a ``Path`` where the config holds the string,
    so when either side is a path both are compared as paths: on Windows
    ``str(Path("/x/rc"))`` is ``\\x\\rc``, which no string comparison matches
    with ``/x/rc``. Two strings are compared as strings.
    """
    as_paths = isinstance(expected, os.PathLike) or isinstance(value, os.PathLike)
    expected, value = _comparable(expected), _comparable(value)
    if as_paths and isinstance(expected, str) and isinstance(value, str):
        return PurePath(expected) == PurePath(value)
    return expected == value


def set_by_operator(config: Any, key: str, value: Any) -> bool:
    """Whether ``value``, about to be used for dotted ``key``, is the operator's.

    True when ``config`` was built from no file inside the scanned tree, or when the
    trusted base plus ``--config-overrides`` resolves ``key`` to ``value``. False
    otherwise, including when ``config`` carries no provenance. The value the scanner
    will use is compared, rather than the one at ``key`` in ``config``, so a scanner
    constructed with options of its own is judged by what it would actually run.
    """
    provenance = getattr(config, "_provenance", None)
    if not isinstance(provenance, ConfigProvenance):
        return False
    if not provenance.in_tree:
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


#: Why ``operator_path`` refused a value the operator did not set.
NOT_THE_OPERATORS = (
    "it came from a config file in the scanned tree or from an MCP client; set it "
    "with --config-overrides or a config file outside the tree"
)

#: Why ``operator_path`` refused a path inside the scanned tree.
INSIDE_THE_TREE = "it is inside the scanned tree"


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
) -> OperatorPath:
    """``value`` as the path a tool will read, when the operator chose it.

    The one rule for a scanner option that names a file a tool reads as its own
    configuration: used only when ``set_by_operator`` accepts ``value`` for ``key``
    and, with ``outside_tree``, when it resolves outside the scanned tree
    (``config/path_trust.in_scanned_tree``, from ``scan_root``). The path returned
    is ``path_trust.resolved_path`` of ``value`` (``~`` expanded, relative to
    ``source_dir``, symlinks and ``..`` resolved), the same path that was checked,
    so a caller hands the tool exactly that and nothing rebuilt from ``value``.
    Whether the file exists is left to the caller, which knows whether a missing
    one should fail the scan.
    """
    from automated_security_helper.config.path_trust import (
        in_scanned_tree,
        resolved_path,
    )

    candidate = resolved_path(value, Path(source_dir))
    if not set_by_operator(config, key, value):
        return OperatorPath(None, NOT_THE_OPERATORS)
    if outside_tree and in_scanned_tree(candidate, scan_root(config, source_dir)):
        return OperatorPath(None, INSIDE_THE_TREE)
    return OperatorPath(candidate)
