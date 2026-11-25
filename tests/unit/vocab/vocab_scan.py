# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner behind the vocabulary drift gate.

Walks Python files with ``ast`` (never a regex over raw text) and reports each
string constant that equals a member value of a vocabulary, so a spelling that
creeps back next to its enum is found. Docstring positions are skipped, and
comments never reach the AST.
"""

import ast
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

#: One finding: the file, the line, and the constant's text.
Hit = Tuple[str, int, str]


def _docstring_nodes(tree: ast.AST) -> Set[int]:
    """The ids of the ``ast.Constant`` nodes that are docstrings."""
    found: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node,
            (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                found.add(id(body[0].value))
    return found


def stray_spellings(
    path: Path, spellings: Iterable[str], *, label: str | None = None
) -> List[Hit]:
    """Every non-docstring string constant in ``path`` equal to one of ``spellings``."""
    wanted = set(spellings)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    skip = _docstring_nodes(tree)
    shown = label or str(path)
    hits: List[Hit] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in skip
            and node.value in wanted
        ):
            hits.append((shown, node.lineno, node.value))
    return sorted(hits)


def scan_scope(
    root: Path, scope: Iterable[str], spellings: Iterable[str]
) -> Dict[str, List[Hit]]:
    """``stray_spellings`` for each file of ``scope`` (paths under ``root``)."""
    spellings = tuple(spellings)
    return {
        relative: stray_spellings(root / relative, spellings, label=relative)
        for relative in scope
    }
