# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every caller reads ``MCPSession.try_begin_change`` as the value it returns.

``try_begin_change`` answers None when the change began and the reason when it was
refused, as ``try_begin_write`` does. So ``if session.try_begin_change():`` reads
backwards: it takes a refusal for a success and a success for a refusal, and no type
checker says so, since a str is as good a truth value as a bool. The method keeps its
type (every caller today compares its answer with None), and this module reads every
caller under the CLI package and refuses the backwards shape: the answer read for its
truth value, directly, through a walrus, or through a name the same scope bound to it
(``ok = session.try_begin_change()`` then ``if ok:``), as the test of an if, a while,
an assert, a conditional expression or a match case's guard, as an operand of not,
and or or, as a comprehension's filter, as the argument of bool(), or as an element
any(), all() or filter(None, ...) reads. A comparison, an assignment and a return are
reads of the answer as a value, and pass.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator, List

import pytest

from automated_security_helper.cli.mcp import sessions

pytestmark = pytest.mark.unit

#: The method whose answer is None on success.
METHOD = "try_begin_change"

#: Where its callers live: the CLI package, which holds the MCP server and tools.
CLI_PACKAGE = Path(sessions.__file__).resolve().parent.parent

#: The repository root, for the paths a failure names.
REPOSITORY = CLI_PACKAGE.parent.parent


def _call_of_the_method(node: ast.AST) -> bool:
    """Whether *node* calls the method, a walrus around the call included."""
    if isinstance(node, ast.NamedExpr):
        node = node.value
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == METHOD
    )


def _elements_read_for_truth(call: ast.Call) -> Iterator[ast.expr]:
    """The expressions a call reads for their truth value: each element the
    iterable given to ``any()`` or ``all()`` yields, and each element
    ``filter(None, iterable)`` keeps or drops, when that iterable is a
    comprehension or a literal list, tuple or set."""
    if not isinstance(call.func, ast.Name):
        return
    if call.func.id in ("any", "all"):
        iterables = call.args[:1]
    elif (
        call.func.id == "filter"
        and len(call.args) == 2
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value is None
    ):
        iterables = call.args[1:2]
    else:
        return
    for iterable in iterables:
        if isinstance(iterable, (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
            yield iterable.elt
        elif isinstance(iterable, (ast.List, ast.Tuple, ast.Set)):
            yield from iterable.elts


def _truth_reads(nodes: Iterator[ast.AST]) -> Iterator[ast.expr]:
    """Each expression among *nodes* that is read for its truth value: the test of
    an if, a while, an assert or a conditional expression, the guard of a match
    case, the operand of not, each operand of and or or, each filter of a
    comprehension, the argument of bool(), and the elements any(), all() and
    filter(None, ...) read."""
    for node in nodes:
        if isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            yield node.test
        elif isinstance(node, ast.match_case) and node.guard is not None:
            yield node.guard
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            yield node.operand
        elif isinstance(node, ast.BoolOp):
            yield from node.values
        elif isinstance(node, ast.comprehension):
            yield from node.ifs
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "bool":
                yield from node.args[:1]
            yield from _elements_read_for_truth(node)


#: The nodes that open a scope of their own for the names bound inside them.
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _own_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """Each node under *scope* that is not inside a nested scope of its own, so a
    name bound in one function is read only against that function's reads."""
    pending = list(ast.iter_child_nodes(scope))
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, _SCOPES):
            pending.extend(ast.iter_child_nodes(node))


def _names_bound_from_the_method(nodes: Iterator[ast.AST]) -> set:
    """The names *nodes* bind to the method's answer: the targets of an assignment
    or an annotated assignment whose value is the call, and of a walrus around it."""
    names = set()
    for node in nodes:
        if isinstance(node, ast.Assign) and _call_of_the_method(node.value):
            names.update(
                target.id for target in node.targets if isinstance(target, ast.Name)
            )
        elif (
            isinstance(node, ast.AnnAssign)
            and node.value is not None
            and _call_of_the_method(node.value)
            and isinstance(node.target, ast.Name)
        ):
            names.add(node.target.id)
        elif isinstance(node, ast.NamedExpr) and _call_of_the_method(node.value):
            names.add(node.target.id)
    return names


def backwards_reads(source: str, name: str = "<source>") -> List[str]:
    """``<name>:<line>: <expression>`` for each read of the method's answer as a
    truth value in *source*: the call itself where a truth value is read, or a
    name the same scope bound to the answer, read there for its truth value."""
    tree = ast.parse(source, filename=name)
    found = {}
    scopes = [tree, *(node for node in ast.walk(tree) if isinstance(node, _SCOPES))]
    for scope in scopes:
        bound = _names_bound_from_the_method(_own_nodes(scope))
        for read in _truth_reads(_own_nodes(scope)):
            if _call_of_the_method(read) or (
                isinstance(read, ast.Name) and read.id in bound
            ):
                found[(read.lineno, read.col_offset)] = (
                    f"{name}:{read.lineno}: {ast.unparse(read)}"
                )
    return [found[position] for position in sorted(found)]


def calls_of_the_method(source: str) -> int:
    """How many times *source* calls the method, however it reads the answer."""
    return sum(1 for node in ast.walk(ast.parse(source)) if _call_of_the_method(node))


def test_no_cli_caller_reads_try_begin_change_as_a_truth_value():
    """The guard: no caller under the CLI package reads the answer backwards. The
    walk has to have read at least one caller, or an empty listing would pass."""
    files = sorted(CLI_PACKAGE.rglob("*.py"))
    assert files, CLI_PACKAGE

    callers = 0
    found: List[str] = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        callers += calls_of_the_method(source)
        found.extend(backwards_reads(source, path.relative_to(REPOSITORY).as_posix()))

    assert callers >= 1, "no caller of the method was read; the walk saw nothing"
    assert found == [], "\n".join(found)


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("if session.try_begin_change():\n    pass\n", id="if"),
        pytest.param("if not session.try_begin_change():\n    pass\n", id="not"),
        pytest.param("while session.try_begin_change():\n    pass\n", id="while"),
        pytest.param("assert session.try_begin_change()\n", id="assert"),
        pytest.param("x = 1 if session.try_begin_change() else 2\n", id="ternary"),
        pytest.param("if ok and session.try_begin_change():\n    pass\n", id="and"),
        pytest.param("if ok or session.try_begin_change():\n    pass\n", id="or"),
        pytest.param(
            "if (refused := session.try_begin_change()):\n    pass\n", id="walrus"
        ),
        pytest.param("x = bool(session.try_begin_change())\n", id="bool"),
        pytest.param(
            "xs = [s for s in held if s.try_begin_change()]\n", id="comprehension"
        ),
        pytest.param(
            "if self.sessions[name].try_begin_change(removes_workspace=False):\n"
            "    pass\n",
            id="a-keyword-argument-and-a-subscripted-receiver",
        ),
        pytest.param(
            "ok = session.try_begin_change()\nif ok:\n    pass\n",
            id="assigned-then-tested",
        ),
        pytest.param(
            "ok: str | None = session.try_begin_change()\nwhile ok:\n    pass\n",
            id="annotated-assignment-then-tested",
        ),
        pytest.param(
            "def f():\n"
            "    ok = session.try_begin_change()\n"
            "    other()\n"
            "    return 1 if ok else 2\n",
            id="assigned-then-tested-later-in-the-function",
        ),
        pytest.param(
            "if any(s.try_begin_change() for s in held):\n    pass\n",
            id="any-over-a-generator",
        ),
        pytest.param(
            "if all([session.try_begin_change()]):\n    pass\n", id="all-over-a-list"
        ),
        pytest.param(
            "kept = list(filter(None, [session.try_begin_change()]))\n",
            id="filter-none",
        ),
        pytest.param(
            "match x:\n    case _ if session.try_begin_change():\n        pass\n",
            id="a-match-guard",
        ),
    ],
)
def test_the_reader_refuses_each_backwards_shape(source):
    """Control: each way of reading the answer for its truth value is one finding."""
    assert len(backwards_reads(source)) == 1, backwards_reads(source)


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            "if session.try_begin_change() is None:\n    pass\n", id="is-none"
        ),
        pytest.param(
            "if session.try_begin_change() is not None:\n    pass\n", id="is-not-none"
        ),
        pytest.param(
            "refused = session.try_begin_change()\nif refused is not None:\n    pass\n",
            id="assigned-then-compared",
        ),
        pytest.param(
            "assert session.try_begin_change() == CHANGE_REFUSED_BY_SCAN\n",
            id="compared-with-a-reason",
        ),
        pytest.param("return session.try_begin_change()\n", id="returned"),
        pytest.param(
            "if session.try_claim_scan():\n    pass\n",
            id="another-method-of-the-session",
        ),
        pytest.param(
            "ok = session.try_begin_change()\nif ok is None:\n    pass\n",
            id="assigned-then-compared-with-none",
        ),
        pytest.param(
            "ok = session.try_begin_change()\nreturn ok\n", id="assigned-then-returned"
        ),
        pytest.param(
            "def f():\n"
            "    ok = session.try_begin_change()\n"
            "    return ok\n"
            "\n"
            "def g(ok):\n"
            "    if ok:\n"
            "        pass\n",
            id="a-same-named-name-in-another-scope",
        ),
        pytest.param(
            "if any(s.is_open() for s in held):\n    pass\n",
            id="any-over-another-method",
        ),
    ],
)
def test_the_reader_admits_a_read_of_the_answer_as_a_value(source):
    """Control: a comparison, an assignment, a return, a name bound in another
    scope, and another method's truth value are not this reader's business."""
    assert backwards_reads(source) == []


def test_the_reader_counts_every_call_whatever_the_read():
    """The caller count that keeps the guard honest counts a forward read too."""
    source = (
        "refused = session.try_begin_change()\n"
        "if session.try_begin_change() is None:\n    pass\n"
    )

    assert calls_of_the_method(source) == 2
