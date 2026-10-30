# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The content-database cases of test_content_db_staleness.py write each tier once.

``CASE_TIERS`` is the one dict literal that names a database case's tier, and every
list of cases the module parametrizes a ``name`` argument over is built from it. A
second list of ``pytest.param(..., marks=pytest.mark.<tier>)`` would be a copy that
drifts, which is what this reads for: each such list must resolve to a
comprehension whose ``marks=`` is a lookup in ``CASE_TIERS``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

MODULE = Path(__file__).with_name("test_content_db_staleness.py")
TIER_TABLE = "CASE_TIERS"
CASE_ARGNAME = "name"


def _module() -> ast.Module:
    return ast.parse(MODULE.read_text(encoding="utf-8"))


def _top_level_assignments(module: ast.Module) -> dict[str, ast.AST]:
    found: dict[str, ast.AST] = {}
    for statement in module.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    found[target.id] = statement.value
    return found


def _case_lists(module: ast.Module):
    """Each ``parametrize("name", <argvalues>)`` in the module, with its test."""
    for node in ast.walk(module):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "parametrize"
                and len(decorator.args) >= 2
                and isinstance(decorator.args[0], ast.Constant)
                and decorator.args[0].value == CASE_ARGNAME
            ):
                yield node.name, decorator.args[1]


def _is_a_lookup_in_the_tier_table(comprehension: ast.AST) -> bool:
    """``[pytest.param(<x>, marks=CASE_TIERS[<x>]) for <x> in <anything>]``."""
    if not isinstance(comprehension, ast.ListComp):
        return False
    element = comprehension.elt
    if not (
        isinstance(element, ast.Call)
        and isinstance(element.func, ast.Attribute)
        and element.func.attr == "param"
    ):
        return False
    marks = [keyword.value for keyword in element.keywords if keyword.arg == "marks"]
    return (
        len(marks) == 1
        and isinstance(marks[0], ast.Subscript)
        and isinstance(marks[0].value, ast.Name)
        and marks[0].value.id == TIER_TABLE
    )


def test_the_tier_table_is_a_dict_literal_of_marks():
    """The one place a tier is written, in the shape the static tier check follows."""
    table = _top_level_assignments(_module())[TIER_TABLE]

    assert isinstance(table, ast.Dict), ast.dump(table)
    for value in table.values:
        assert isinstance(value, ast.Attribute) and value.attr in {
            "unit",
            "integration",
            "e2e",
        }, ast.dump(value)


def test_every_database_case_list_is_built_from_the_tier_table():
    module = _module()
    assignments = _top_level_assignments(module)
    case_lists = list(_case_lists(module))
    assert case_lists, "no test parametrizes a database case by name"

    for test, argvalues in case_lists:
        if isinstance(argvalues, ast.Name):
            # A Name has to resolve to the comprehension over CASE_TIERS.
            bound = assignments.get(argvalues.id)
            assert bound is not None, (test, argvalues.id)
            assert _is_a_lookup_in_the_tier_table(bound), (test, ast.dump(bound))
        else:
            # A literal list of plain case names is fine (the test carries its own
            # mark); a literal pytest.param(..., marks=...) writes a tier a second
            # time, which is the copy this forbids.
            assert isinstance(argvalues, (ast.List, ast.Tuple)), (
                test,
                ast.dump(argvalues),
            )
            for element in argvalues.elts:
                keywords = element.keywords if isinstance(element, ast.Call) else []
                assert not any(keyword.arg == "marks" for keyword in keywords), (
                    test,
                    ast.dump(element),
                )
