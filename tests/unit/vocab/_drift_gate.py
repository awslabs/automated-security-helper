# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The two-mode vocabulary drift gate that every enum unit registers into.

A vocabulary that became an enum stays one only while nothing re-spells it. This
module is the scanner and the registry; ``test_vocab_drift.py`` runs every
registered vocabulary through it, and each later enum unit adds its own
``VocabEntry`` to ``REGISTRY`` (and its scope files to the entry it extends)
instead of writing a gate of its own.

Two modes, because gate strength follows how distinctive a spelling is:

* NEGATIVE (distinctive spellings such as ``"below-threshold"`` or
  ``"skip_offline"``): an ``ast`` walk over the entry's scope files flags any string
  constant that equals a member value, skipping docstring positions and the
  allowlisted files. Comments never reach the AST.
* POSITIVE (ambiguous short words such as ``"low"``, ``"all"``, ``"info"``, where a
  naive scan drowns in false positives): the entry pins the sites instead. A
  ``collections`` scan flags any tuple, list, set or dict literal that spells
  ``min_hits`` or more of the vocabulary's values together (the shape a copied
  ladder has), and an explicit list of ``(path, forbidden fragment)`` pairs, taken
  from the catalog, asserts the previously inventoried copy sites stay gone.

Every mode ships with a planted-positive control: ``planted_control`` writes a
stray spelling into a temp file, and the gate asserts the scanner flags it, so a
scan that has silently stopped looking cannot read as clean.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Type

#: The package the scope paths are relative to.
PACKAGE_ROOT = Path(__file__).resolve().parents[3] / "automated_security_helper"


@dataclass(frozen=True)
class Hit:
    """One stray spelling: where it is and what it spelled."""

    path: str
    line: int
    text: str


@dataclass
class VocabEntry:
    """One vocabulary's registration in the gate."""

    name: str
    enum: Type[Enum]
    #: Package-relative files the unit cured. A scope is never the whole tree
    #: until every unit that owns part of it has landed.
    scope: Tuple[str, ...]
    #: ``path -> reason`` for files that may spell the values (wire-byte tests,
    #: ingest normalizers, recorded exceptions). The reason is mandatory.
    allowlist: Dict[str, str] = field(default_factory=dict)
    #: ``"negative"`` scans constants; ``"positive"`` scans collections and pins sites.
    mode: str = "negative"
    #: Positive mode: spell this many of the values in one collection to be a copy.
    min_hits: int = 3
    #: Values to look for when they are not the members' own (derived spellings
    #: such as the lowercase count buckets). Defaults to the members' values.
    values: Optional[Tuple[str, ...]] = None
    #: Positive mode: ``(package-relative path, fragment that must not appear)``.
    forbidden_fragments: Tuple[Tuple[str, str], ...] = ()
    #: Positive mode: named derivations, each a callable raising on drift.
    derivations: Dict[str, Callable[[], None]] = field(default_factory=dict)

    def spelled_values(self) -> Tuple[str, ...]:
        if self.values is not None:
            return self.values
        return tuple(str(m.value) for m in self.enum)


def _docstring_nodes(tree: ast.AST) -> set:
    """The ``ast.Constant`` nodes that are docstrings, which are prose, not data."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                out.add(id(body[0].value))
    return out


def scan_constants(source: str, path: str, values: Iterable[str]) -> List[Hit]:
    """NEGATIVE mode: every non-docstring string constant equal to a value."""
    wanted = set(values)
    tree = ast.parse(source, filename=path)
    docs = _docstring_nodes(tree)
    hits = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docs
            and node.value in wanted
        ):
            hits.append(Hit(path, node.lineno, node.value))
    return hits


def scan_collections(
    source: str, path: str, values: Iterable[str], min_hits: int
) -> List[Hit]:
    """POSITIVE mode: collection literals that spell ``min_hits`` or more values.

    Tuples, lists, sets and dict KEYS count, so a copied ladder is caught whether
    it is a tuple, a rank table or a ``Literal[...]`` subscript.
    """
    wanted = set(values)
    tree = ast.parse(source, filename=path)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            elements = node.elts
        elif isinstance(node, ast.Dict):
            elements = [k for k in node.keys if k is not None]
        else:
            continue
        spelled = {
            e.value
            for e in elements
            if isinstance(e, ast.Constant) and isinstance(e.value, str)
        } & wanted
        if len(spelled) >= min_hits:
            hits.append(Hit(path, node.lineno, ",".join(sorted(spelled))))
    return hits


def _read(rel: str, root: Path) -> str:
    return (root / rel).read_text(encoding="utf-8")


def scan_entry(entry: VocabEntry, root: Path = PACKAGE_ROOT) -> List[Hit]:
    """Every stray spelling in the entry's scope, allowlist removed."""
    hits: List[Hit] = []
    for rel in entry.scope:
        if rel in entry.allowlist:
            continue
        source = _read(rel, root)
        if entry.mode == "negative":
            hits.extend(scan_constants(source, rel, entry.spelled_values()))
        else:
            hits.extend(
                scan_collections(source, rel, entry.spelled_values(), entry.min_hits)
            )
    return hits


def forbidden_fragment_hits(
    entry: VocabEntry, root: Path = PACKAGE_ROOT
) -> List[Tuple[str, str]]:
    """POSITIVE mode: inventoried copy sites that have come back."""
    return [
        (rel, fragment)
        for rel, fragment in entry.forbidden_fragments
        if fragment in _read(rel, root)
    ]


def planted_control(entry: VocabEntry, tmp_dir: Path) -> List[Hit]:
    """Plant one stray spelling in a temp file and scan it the way the gate scans.

    A gate whose scanner finds nothing here is dead, and its clean reading on the
    real scope means nothing.
    """
    values = entry.spelled_values()
    if entry.mode == "negative":
        planted = f"STRAY = {values[0]!r}\n"
    else:
        spelled = ", ".join(repr(v) for v in values[: max(entry.min_hits, 1)])
        planted = f"STRAY = ({spelled},)\n"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    (tmp_dir / "planted.py").write_text(planted, encoding="utf-8")
    probe = VocabEntry(
        name=entry.name + " (planted)",
        enum=entry.enum,
        scope=("planted.py",),
        mode=entry.mode,
        min_hits=entry.min_hits,
        values=entry.values,
    )
    return scan_entry(probe, root=tmp_dir)


#: Every vocabulary a unit has cured. A later unit appends its own entry here (or
#: extends an entry's scope), in its own module that this one imports last.
REGISTRY: List[VocabEntry] = []


def register(entry: VocabEntry) -> VocabEntry:
    for existing in REGISTRY:
        if existing.name == entry.name:
            raise ValueError(f"vocabulary {entry.name!r} is already registered")
    for rel, reason in entry.allowlist.items():
        if not reason.strip():
            raise ValueError(f"allowlist entry {rel!r} has no reason")
    REGISTRY.append(entry)
    return entry


def entries() -> Sequence[VocabEntry]:
    return tuple(REGISTRY)
