# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""test_page_claims.py defines each top-level function and class once.

A second definition of a name replaces the first for every caller in the module, with
no error, so tests written against the first one run against the second. Ruff's F811
reports a redefinition only when the first definition is unused, so it misses a helper
that tests already call.
"""

import ast
from pathlib import Path
from typing import Dict, List

PAGE_CLAIMS = Path(__file__).with_name("test_page_claims.py")


def _duplicated_top_level_names(source: str) -> List[str]:
    """Each top-level function or class name ``source`` defines more than once, as
    ``name: lines A, B`` with the line of every definition."""
    lines: Dict[str, List[int]] = {}
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            lines.setdefault(node.name, []).append(node.lineno)
    return [
        f"{name}: lines {', '.join(str(line) for line in found)}"
        for name, found in lines.items()
        if len(found) > 1
    ]


def test_page_claims_defines_each_top_level_name_once() -> None:
    duplicated = _duplicated_top_level_names(PAGE_CLAIMS.read_text(encoding="utf-8"))

    assert not duplicated, f"{PAGE_CLAIMS.name} defines a name more than once:\n" + (
        "\n".join(duplicated)
    )


def test_a_name_defined_twice_is_found() -> None:
    """The control: a function and a class name each defined twice, the second time
    as the other kind, are both found with both lines."""
    source = (
        "def helper(): ...\nclass Box: ...\nasync def Box(): ...\nclass helper: ...\n"
    )

    assert _duplicated_top_level_names(source) == [
        "helper: lines 1, 4",
        "Box: lines 2, 3",
    ]
