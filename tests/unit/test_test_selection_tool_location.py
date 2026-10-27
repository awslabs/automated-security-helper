# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The test-selection tools are where the testing docs and their own imports say.

``docs/content/docs/testing/test_selection.md``, ``index.md`` and the tools' own
imports name modules under ``tests/utils/``, so that is where the tools live, as
``selection.py`` and ``optimization.py``. Both are tools, not tests: under a ``test_``
name pytest would collect them and find nothing to run.
"""

from __future__ import annotations

import ast
import importlib
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest

from tests.utils.helpers import checkout_env

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTING_DOCS = REPO_ROOT / "docs" / "content" / "docs" / "testing"
TOOLS = ("tests.utils.selection", "tests.utils.optimization")


def _selection_doc_text() -> str:
    """test_selection.md whole, and the "Test Selection Utilities" part of index.md."""
    index = (TESTING_DOCS / "index.md").read_text(encoding="utf-8")
    section = index.split("### Test Selection Utilities", 1)[1].split("\n## ", 1)[0]
    return (TESTING_DOCS / "test_selection.md").read_text(encoding="utf-8") + section


def test_every_module_the_selection_docs_name_imports():
    text = _selection_doc_text()
    commands = re.findall(r"python -m (tests\.[\w.]+)", text)
    imports = re.findall(r"from (tests\.[\w.]+) import ([\w, ]+)", text)
    assert commands and imports, "found no commands or imports; the regexes are wrong"
    for module in commands:
        importlib.import_module(module)
    for module, names in imports:
        imported = importlib.import_module(module)
        for name in (n.strip() for n in names.split(",")):
            assert hasattr(imported, name), f"{module} has no {name}"


@pytest.mark.parametrize("module", TOOLS)
def test_the_tool_runs_from_the_repository_root(module):
    result = subprocess.run(
        [sys.executable, "-m", module, "--help"],
        cwd=REPO_ROOT,
        env=checkout_env(),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout


@pytest.mark.parametrize("module", TOOLS)
def test_the_tools_own_imports_resolve(module):
    """optimization.py imported tests.utils.test_selection, which did not exist."""
    path = REPO_ROOT / (module.replace(".", "/") + ".py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            "tests."
        ):
            imported = importlib.import_module(node.module)
            for alias in node.names:
                assert hasattr(imported, alias.name), f"{node.module}.{alias.name}"


def _defines_a_test(tree: ast.Module) -> bool:
    """Whether pytest would find a test at the top level of this module."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test"):
                return True
        elif isinstance(node, ast.Assign):
            if any(
                isinstance(t, ast.Name) and t.id.startswith("test")
                for t in node.targets
            ):
                return True
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            members = node.body
            if any(
                isinstance(m, ast.FunctionDef) and m.name == "__init__" for m in members
            ):
                continue  # pytest refuses to collect it, with a warning
            if node.bases or any(
                isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                and m.name.startswith("test")
                for m in members
            ):
                return True
    return False


def test_no_tool_is_named_like_a_test_module():
    """pytest collects tests/**/test_*.py; a tool there is imported for nothing.

    Every tracked test_*.py under tests/ has to define a test pytest can collect. The
    selection and optimization tools lived in tests/unit/utils/ under test_ names, and
    pytest warned that it could not collect their classes.
    """
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "tests/*test_*.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    modules = [
        name
        for name in listed.split("\0")
        if name and Path(name).name.startswith("test_")
    ]
    assert "tests/unit/test_test_selection_tool_location.py" in modules, modules[:5]
    assert len(modules) > 100, f"git listed only {len(modules)} test modules"
    tools = [
        name
        for name in modules
        if not _defines_a_test(
            ast.parse((REPO_ROOT / name).read_text(encoding="utf-8"), filename=name)
        )
    ]
    assert not tools, (
        f"{tools} are named like test modules but define no test pytest can collect; "
        "move them to tests/utils/ under a name that does not start with test_"
    )


def test_the_test_finder_recognises_each_shape():
    """Positive and negative controls for _defines_a_test."""

    def finds(source: str) -> bool:
        return _defines_a_test(ast.parse(source))

    assert finds("def test_x(): pass")
    assert finds("async def test_x(): pass")
    assert finds("class TestX:\n    def test_y(self): pass")
    assert finds("class TestX(Base):\n    pass")
    assert finds("test_x = make()")
    assert not finds("def helper(): pass")
    assert not finds(
        "class TestX:\n    def __init__(self): pass\n    def test_y(self): pass"
    )
    assert not finds("class Helper:\n    def test_y(self): pass")


def _record_runs(monkeypatch, module) -> list:
    calls = []

    def fake_run(argv, *args, **kwargs):
        calls.append(list(argv))
        return types.SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    return calls


def _every_pytest_invocation(monkeypatch) -> list:
    selection = importlib.import_module("tests.utils.selection")
    optimization = importlib.import_module("tests.utils.optimization")
    calls = _record_runs(monkeypatch, selection)
    selection.get_tests_by_marker("unit")
    selection.get_tests_by_keyword("config")
    selection.get_slow_tests()
    selection.run_selected_tests(markers=["unit"])
    optimization.run_tests_with_optimization(test_files=["tests/unit"], parallel=False)
    return calls


def test_the_tools_run_pytest_with_the_interpreter_they_run_under(monkeypatch):
    """A bare `pytest` is whatever PATH finds first, or nothing, outside an activated venv.

    `python -m tests.utils.selection` is run with the project's interpreter, which is
    the one whose pytest and plugins the suite needs.
    """
    calls = _every_pytest_invocation(monkeypatch)
    assert len(calls) == 5, calls
    wrong = [argv for argv in calls if argv[:3] != [sys.executable, "-m", "pytest"]]
    assert not wrong, wrong
