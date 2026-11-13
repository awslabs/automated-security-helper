#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Nothing that can raise sits between ``_run_local_mode``'s offline hold and its ``try``.

Why this file exists
--------------------
``_run_local_mode`` holds ``ASH_OFFLINE`` with ``hold_environ`` and releases it in the
``finally`` of the ``try`` that follows. Two function-local imports used to sit between the
hold and the ``try``. A first-use import that raised there (a missing or broken module) escaped
outside the ``try``, so the ``finally`` never ran and the hold was never released: every later
scan in the process then ran with ``ASH_OFFLINE=YES`` held. ``_run_workspace_mode`` already has
the hold immediately followed by its ``try``; this pins the same shape in the local path.

The check reads the function's source with ``ast`` and asserts that, in the function body, the
statements between the ``if opts.offline:`` hold and the ``try`` are only the ``_offline_held``
assignment, and that no import statement follows the hold before the ``try``. It fails on the
shape this unit removed (the imports between the hold and the ``try``) and passes on the fixed
shape. Disarmed: it reads source text only and runs no scanner, process or network call.
"""

from __future__ import annotations

import ast
import inspect

import pytest

from automated_security_helper.interactions import run_ash_scan

pytestmark = pytest.mark.unit


def _body_of(function_name: str) -> list[ast.stmt]:
    source = inspect.getsource(getattr(run_ash_scan, function_name))
    tree = ast.parse(source)
    function = tree.body[0]
    assert isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
    return function.body


def _is_hold(statement: ast.stmt) -> bool:
    if not isinstance(statement, ast.If):
        return False
    for node in ast.walk(statement):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "hold_environ"
        ):
            return True
    return False


def _statements_between_hold_and_try(function_name: str) -> list[ast.stmt]:
    body = _body_of(function_name)
    hold_index = next(i for i, s in enumerate(body) if _is_hold(s))
    try_index = next(
        i for i, s in enumerate(body) if i > hold_index and isinstance(s, ast.Try)
    )
    return body[hold_index + 1 : try_index]


def test_no_import_sits_between_the_local_mode_hold_and_its_try() -> None:
    between = _statements_between_hold_and_try("_run_local_mode")
    imports = [s for s in between if isinstance(s, (ast.Import, ast.ImportFrom))]
    assert imports == [], (
        "an import between the offline hold and its try can raise outside the "
        "finally that releases the hold"
    )


def test_only_the_held_flag_assignment_sits_between_the_hold_and_its_try() -> None:
    between = _statements_between_hold_and_try("_run_local_mode")
    assert between == [], f"statements between hold and try: {len(between)}"


def test_the_workspace_mode_shape_is_the_same() -> None:
    # Control: the neighbor the local path now matches. A detector that reads
    # nothing would pass the two cells above; this one pins the reference shape.
    assert _statements_between_hold_and_try("_run_workspace_mode") == []
