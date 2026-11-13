# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The content-database cases of test_content_db_staleness.py write each tier once.

``CASE_TIERS`` is the one dict literal that names a database case's tier. Every
``parametrize`` in the module, whatever its argument names, is read: its argvalues
are either a comprehension whose ``marks=`` looks the comprehension's own variable
up in ``CASE_TIERS`` (directly, or through a module-level name bound to one), or a
literal list that carries no tier mark at all. A second list of
``pytest.param(..., marks=pytest.mark.<tier>)`` would be a copy that drifts, and
any other shape is one this check cannot read, so both fail here.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

MODULE = Path(__file__).with_name("test_content_db_staleness.py")
TIER_TABLE = "CASE_TIERS"
TIER_NAMES = {"unit", "integration", "e2e"}


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


def _parametrize_argvalues(decorator: ast.AST) -> ast.AST | None:
    """The argvalues of a ``pytest.mark.parametrize`` decorator, however passed."""
    if not (
        isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr == "parametrize"
    ):
        return None
    if len(decorator.args) >= 2:
        return decorator.args[1]
    for keyword in decorator.keywords:
        if keyword.arg == "argvalues":
            return keyword.value
    return None


def _every_parametrize(module: ast.Module):
    """Each parametrize decorator in the module, on a test or a test class, with
    the name it decorates. The argument names are not read: a copy of the tier
    list can sit behind any names."""
    for node in ast.walk(module):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for decorator in node.decorator_list:
            argvalues = _parametrize_argvalues(decorator)
            if argvalues is not None:
                yield node.name, argvalues


def _is_a_lookup_in_the_tier_table(comprehension: ast.AST) -> bool:
    """``[pytest.param(<x>, marks=CASE_TIERS[<x>]) for <x> in <anything>]``, where
    ``<x>`` is the comprehension's own variable, so each case takes its own tier."""
    if not (
        isinstance(comprehension, ast.ListComp) and len(comprehension.generators) == 1
    ):
        return False
    target = comprehension.generators[0].target
    if not isinstance(target, ast.Name):
        return False
    element = comprehension.elt
    if not (
        isinstance(element, ast.Call)
        and isinstance(element.func, ast.Attribute)
        and element.func.attr == "param"
        and len(element.args) == 1
        and isinstance(element.args[0], ast.Name)
        and element.args[0].id == target.id
    ):
        return False
    marks = [keyword.value for keyword in element.keywords if keyword.arg == "marks"]
    if len(marks) != 1 or not isinstance(marks[0], ast.Subscript):
        return False
    lookup = marks[0]
    return (
        isinstance(lookup.value, ast.Name)
        and lookup.value.id == TIER_TABLE
        and isinstance(lookup.slice, ast.Name)
        and lookup.slice.id == target.id
    )


def _names_a_tier(expression: ast.AST) -> bool:
    """``pytest.mark.<tier>`` anywhere inside *expression* (a bare mark, or one
    inside a list or tuple of marks)."""
    return any(
        isinstance(node, ast.Attribute) and node.attr in TIER_NAMES
        for node in ast.walk(expression)
    )


def _is_a_literal_list_without_tiers(argvalues: ast.AST) -> bool:
    """A literal list of cases where no element's ``marks=`` names a tier. The
    test carries its own mark then; a ``marks=pytest.mark.<tier>`` on an element
    would write a tier a second time."""
    if not isinstance(argvalues, (ast.List, ast.Tuple)):
        return False
    for element in argvalues.elts:
        if not isinstance(element, ast.Call):
            continue
        for keyword in element.keywords:
            if keyword.arg == "marks" and _names_a_tier(keyword.value):
                return False
    return True


def test_the_tier_table_is_a_dict_literal_of_marks():
    """The one place a tier is written, in the shape the static tier check follows."""
    table = _top_level_assignments(_module())[TIER_TABLE]

    assert isinstance(table, ast.Dict), ast.dump(table)
    for value in table.values:
        assert isinstance(value, ast.Attribute) and value.attr in TIER_NAMES, ast.dump(
            value
        )


def test_every_parametrize_is_built_from_the_tier_table_or_carries_no_tier():
    module = _module()
    assignments = _top_level_assignments(module)
    sites = list(_every_parametrize(module))
    assert sites, "no test in the module is parametrized"

    lookups = 0
    for test, argvalues in sites:
        # A module-level name resolves to what it is bound to; the same rules then
        # apply to the bound value as to an inline one.
        bound = (
            assignments.get(argvalues.id)
            if isinstance(argvalues, ast.Name)
            else argvalues
        )
        assert bound is not None, (test, ast.dump(argvalues))
        if _is_a_lookup_in_the_tier_table(bound):
            lookups += 1
            continue
        assert _is_a_literal_list_without_tiers(bound), (test, ast.dump(bound))

    assert lookups, "no parametrize takes its tiers from the tier table"
