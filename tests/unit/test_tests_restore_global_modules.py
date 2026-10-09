# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No test leaves a standard-library module patched for the tests after it.

Why this file exists
--------------------
test_eks_operator_applier.py replaced ``urllib.request.urlopen`` through the applier's
globals (``applier["urllib"].request.urlopen = fake``) and never put it back. The
applier's ``urllib`` is the process-wide module, so every later test in the same
xdist worker called the fake: nine latest-release tests in test_e2e_prev_tree.py
failed on eight CI cells with ``'_Response' object has no attribute 'read'``, and
passed whenever the scheduler put them on another worker.

So this walks every test file and refuses an assignment, or a ``setattr``, whose
target reaches a standard-library module: a name imported from one
(``sys.argv = ...``), a mapping key naming one (``g["urllib"].request.urlopen``), or
an attribute naming one of the modules tests patch (``mod.subprocess.run = ...``).
Such an assignment passes only when the same target is assigned again in a
``finally`` block or after a ``yield`` in the same function, which is how the
restoring cases here are written. ``monkeypatch.setattr`` and ``mock.patch`` never
appear as an assignment, so they are not read at all.

What it does not cover
----------------------
``os.environ[...] = ...`` and ``sys.modules[...] = ...`` are item assignments on a
mapping, a different class with its own handling (conftest restores the
environment; registering a loaded module is how importlib needs it done).
"""

from __future__ import annotations

import ast
import sys
import warnings
from pathlib import Path

import pytest

from tests.utils.helpers import iter_repo_files

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS = REPO_ROOT / "tests"
STDLIB = frozenset(sys.stdlib_module_names)

# Modules reached as an attribute of something else (a script module loaded by
# path, a globals mapping) that tests patch. Only these count when the root is not
# itself a standard-library import, so `event.select.id = ...` is not read as the
# `select` module.
PATCHED_THROUGH = frozenset(
    {
        "http",
        "importlib",
        "logging",
        "os",
        "pathlib",
        "shutil",
        "socket",
        "subprocess",
        "sys",
        "tempfile",
        "threading",
        "time",
        "urllib",
    }
)

# (path relative to the repository, target) assignments that are meant to last.
DELIBERATE = {
    # The session-wide temp root conftest sets up before any test runs.
    ("tests/conftest.py", "tempfile.tempdir"),
}


def _stdlib_imports(tree: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in STDLIB:
                    names.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if node.module.split(".")[0] in STDLIB and alias.name in STDLIB:
                    names.add(alias.asname or alias.name)
    return names


def _reaches_stdlib(target: ast.expr, imported: set[str]) -> bool:
    node = target
    through = []
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        if isinstance(node, ast.Subscript):
            key = node.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if key.value.split(".")[0] in STDLIB:
                    return True
        elif node is not target:
            through.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name) and node.id in imported:
        return True
    return any(attr in PATCHED_THROUGH for attr in through)


def _targets(node: ast.AST) -> list[ast.expr]:
    if isinstance(node, ast.Assign):
        return [t for t in node.targets if isinstance(t, ast.Attribute)]
    if isinstance(node, (ast.AugAssign, ast.AnnAssign)) and isinstance(
        node.target, ast.Attribute
    ):
        return [node.target]
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "setattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
    ):
        return [ast.Attribute(value=node.args[0], attr=node.args[1].value)]
    return []


def _is_restore(function: ast.AST, at: ast.AST) -> bool:
    """Whether `at` itself is the putting-back: in a finally block or after a yield."""
    for node in ast.walk(function):
        if isinstance(node, ast.Try):
            for statement in node.finalbody:
                if any(inner is at for inner in ast.walk(statement)):
                    return True
    yields = [n.lineno for n in ast.walk(function) if isinstance(n, ast.Yield)]
    return bool(yields) and at.lineno > min(yields)


def _restored(function: ast.AST, target: str, at: ast.AST) -> bool:
    """Whether `target` is assigned again in a finally block or after a yield."""
    for node in ast.walk(function):
        if isinstance(node, ast.Try):
            for statement in node.finalbody:
                for inner in ast.walk(statement):
                    if inner is not at and any(
                        ast.unparse(t) == target for t in _targets(inner)
                    ):
                        return True
    yields = [n.lineno for n in ast.walk(function) if isinstance(n, ast.Yield)]
    if yields:
        first_yield = min(yields)
        for inner in ast.walk(function):
            if getattr(inner, "lineno", 0) > first_yield and any(
                ast.unparse(t) == target for t in _targets(inner)
            ):
                return True
    return False


def leaks(source: str, relative: str = "<planted>") -> list[str]:
    """Every stdlib-reaching assignment in `source` that is not put back."""
    with warnings.catch_warnings():
        # A test file's own invalid escape sequence is that file's business.
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(source)
    imported = _stdlib_imports(tree)
    functions = [
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    found = []
    for node in ast.walk(tree):
        for target in _targets(node):
            if not _reaches_stdlib(target, imported):
                continue
            text = ast.unparse(target)
            if (relative, text) in DELIBERATE:
                continue
            owners = [
                f
                for f in functions
                if f.lineno <= node.lineno <= (f.end_lineno or f.lineno)
            ]
            owner = owners[-1] if owners else tree
            if _is_restore(owner, node):
                continue
            if not _restored(owner, text, node):
                found.append(f"{relative}:{node.lineno}: {text}")
    return found


def _test_files() -> list[Path]:
    # Pruned rather than TESTS.rglob(): tests/pytest-temp is under TESTS, and other
    # xdist workers create and delete directories there while this walks.
    return sorted(
        path
        for path in iter_repo_files(TESTS, skip_dirs=frozenset({"__pycache__"}))
        if path.suffix == ".py"
    )


def test_the_walk_reaches_the_tests():
    files = _test_files()
    assert len(files) > 500, len(files)
    assert Path(__file__) in files


def test_no_test_leaves_a_stdlib_module_patched():
    found = []
    for path in _test_files():
        relative = path.relative_to(REPO_ROOT).as_posix()
        found += leaks(path.read_text(encoding="utf-8"), relative)
    assert found == [], (
        "these assignments patch a standard-library module and never put it back; "
        "use monkeypatch.setattr or restore it in a finally block:\n" + "\n".join(found)
    )


PLANTED_LEAKS = [
    # The shape that leaked: a globals mapping keyed by the module name.
    'def test_x(applier):\n    applier["urllib"].request.urlopen = fake\n',
    # A module imported by the test file.
    "import sys\n\ndef test_x():\n    sys.argv = ['x']\n",
    "import urllib.request\n\ndef test_x():\n    urllib.request.urlopen = fake\n",
    # A module reached through a script loaded by path.
    "def test_x(script):\n    script.subprocess.run = fake\n",
    "import os\n\ndef test_x():\n    setattr(os, 'getcwd', fake)\n",
    # Restored, but not in a finally block: an assertion between them skips it.
    (
        "import sys\n\ndef test_x():\n    old = sys.argv\n    sys.argv = ['x']\n"
        "    assert run()\n    sys.argv = old\n"
    ),
]

PLANTED_CLEAN = [
    (
        "import sys\n\ndef test_x():\n    old = sys.argv\n    sys.argv = ['x']\n"
        "    try:\n        run()\n    finally:\n        sys.argv = old\n"
    ),
    (
        "import threading\n\ndef hook():\n    old = threading.excepthook\n"
        "    threading.excepthook = fake\n    yield\n    threading.excepthook = old\n"
    ),
    (
        "def test_x(monkeypatch, applier):\n"
        "    monkeypatch.setattr(applier['urllib'].request, 'urlopen', fake)\n"
    ),
    "def test_x(event):\n    event.select.id = 'a'\n",
]


@pytest.mark.parametrize("source", PLANTED_LEAKS)
def test_a_planted_leak_is_caught(source):
    assert leaks(source), source


@pytest.mark.parametrize("source", PLANTED_CLEAN)
def test_a_restored_or_unrelated_assignment_passes(source):
    assert leaks(source) == [], source
