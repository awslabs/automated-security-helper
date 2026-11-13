# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""mcp_tools.py and mcp_server.py bind each name once.

Why this file exists
--------------------
Merging two lines of work into these modules left a function, a constant and a
variable annotation defined twice. A second ``def`` rebinds the name, so the
older body won: the ``_config_env_refusal`` that ``mcp_scan_directory`` and
``get_config`` call was the one with no ``exit_code``, while ``run_ash_scan``
documents and forwards the refusal with one. Nothing failed at import, and
mypy reports the pair as ``no-redef`` only when it is run.

The source is read with ``ast`` and nothing is imported to find a pair. A name
counts when a scope binds it with two ``def`` or ``class`` statements, when an
annotated assignment comes after another binding of it, or when the module
assigns the same constant twice.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from automated_security_helper.cli import mcp_server, mcp_tools
from automated_security_helper.core.exceptions import ASHConfigEnvNotResolvedError

pytestmark = pytest.mark.unit

_DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)

#: (name, line, kind) with kind one of def, annotated, assign.
Binding = Tuple[str, int, str]


def _bindings(body: List[ast.stmt]) -> List[Binding]:
    """What the statements of one scope bind.

    Statements inside if, try, with, for and while blocks bind in the scope that
    holds them, as mypy counts them. The body of a def or class is a scope of its
    own and is not entered.
    """
    found: List[Binding] = []
    for node in body:
        if isinstance(node, _DEFINITIONS):
            found.append((node.name, node.lineno, "def"))
            continue
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            found.append((node.target.id, node.lineno, "annotated"))
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found.append((target.id, node.lineno, "assign"))
        for field in ("body", "orelse", "finalbody"):
            block = getattr(node, field, None)
            if isinstance(block, list):
                found.extend(_bindings(block))
        for handler in getattr(node, "handlers", []):
            found.extend(_bindings(handler.body))
    return found


def _redefinitions(source: str) -> List[str]:
    """One line per name ``source`` binds in a way the module above describes."""
    tree = ast.parse(source)
    scopes: List[Tuple[str, List[ast.stmt]]] = [("module", tree.body)]
    scopes += [
        (node.name, node.body)
        for node in ast.walk(tree)
        if isinstance(node, _DEFINITIONS)
    ]
    problems: List[str] = []
    for scope, body in scopes:
        hits: Dict[str, List[Tuple[int, str]]] = {}
        for name, line, kind in _bindings(body):
            hits.setdefault(name, []).append((line, kind))
        for name, found in hits.items():
            in_order = sorted(found)
            kinds = [kind for _, kind in in_order]
            defined_twice = kinds.count("def") > 1
            annotated_late = "annotated" in kinds[1:]
            constant_twice = scope == "module" and kinds.count("assign") > 1
            if defined_twice or annotated_late or constant_twice:
                lines = [line for line, _ in in_order]
                problems.append(f"{scope}: {name} is bound at lines {lines}")
    return problems


#: One of each shape the check exists for.
PLANTED = """\
CONSTANT = "a"
CONSTANT = "a"


def twice():
    return 1


def twice():
    return 2


def annotated_after_assign():
    value = 1
    value: int = 2
    return value
"""

#: A function may assign a local again, and a name may be defined once.
CLEAN = """\
CONSTANT = "a"


def once():
    local = 1
    local = 2
    return local
"""


def test_the_check_flags_each_shape_it_exists_for():
    flagged = sorted(line.split(" is bound")[0] for line in _redefinitions(PLANTED))

    assert flagged == [
        "annotated_after_assign: value",
        "module: CONSTANT",
        "module: twice",
    ]


def test_the_check_passes_a_module_that_binds_each_name_once():
    assert _redefinitions(CLEAN) == []


@pytest.mark.parametrize(
    "module", [mcp_tools, mcp_server], ids=["mcp_tools", "mcp_server"]
)
def test_each_name_is_bound_once(module):
    source = Path(module.__file__).read_text(encoding="utf-8")

    assert _redefinitions(source) == []


def test_the_env_refusal_run_ash_scan_forwards_carries_its_exit_code():
    """The refusal mcp_scan_directory and get_config return for a delivered
    config that reads the environment is the one with an exit code, in one line."""
    error = ASHConfigEnvNotResolvedError("proj/.ash.yaml reads\nthe environment")

    refusal = mcp_tools._config_env_refusal(error, "scan_directory")

    assert refusal["success"] is False, refusal
    assert refusal["operation"] == "scan_directory", refusal
    assert refusal["error_type"] == mcp_tools.CONFIG_ENV_NOT_RESOLVED, refusal
    assert refusal["exit_code"] == mcp_tools.REFUSED_CONFIG_EXIT_CODE, refusal
    assert refusal["exit_code_meaning"], refusal
    assert "\n" not in refusal["error"], refusal
