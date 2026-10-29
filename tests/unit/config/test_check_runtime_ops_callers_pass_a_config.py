# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every test that calls ``check_runtime_ops`` passes ``config``.

Why this file exists
--------------------
``check_runtime_ops`` takes ``config`` as a keyword-only argument with no
default, on purpose: a caller with no config says ``config=None`` and so
chooses the mode that names every policy entry ``<value>`` in a refusal
(``test_check_runtime_ops_requires_a_config_argument`` pins the missing
default). Twenty-one test call sites in four files still passed only
``allowlist=``, so each raised ``TypeError`` at the call. Inside
``pytest.raises(RuntimePatchDeniedError)`` the ``TypeError`` is not the
expected class and propagates, and a bare call fails outright; 39 test ids
were red on every platform for it, none of them about the rule they test.

The test files are read with ``ast`` and nothing is imported. Each ``Call``
whose callee is the bare name ``check_runtime_ops`` (or that name as an
attribute of a module) must carry a ``config`` keyword, or a ``**`` splat that
may hold one. The one admitted exception is a call written inside a
``with pytest.raises(TypeError, ...)`` block: that is the guard test proving
the argument has no default, and leaving it out is the point of the call.
Offenders are listed as ``path:line`` so the next one is found by its
location, not by the shard it reddened.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import List, Set

import pytest

pytestmark = pytest.mark.unit

TESTS_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = TESTS_ROOT.parent

CALLEE = "check_runtime_ops"


def _callee_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _passes_a_config(node: ast.Call) -> bool:
    for keyword in node.keywords:
        if keyword.arg is None:
            # A ``**mapping`` splat may carry ``config``; the source cannot say.
            return True
        if keyword.arg == "config":
            return True
    return False


def _expects_a_type_error(node: ast.With) -> bool:
    """Whether the ``with`` is ``pytest.raises(TypeError, ...)``: the guard's shape."""
    for item in node.items:
        call = item.context_expr
        if not isinstance(call, ast.Call) or _callee_name(call) != "raises":
            continue
        if call.args and isinstance(call.args[0], ast.Name):
            if call.args[0].id == "TypeError":
                return True
    return False


def _guarded_calls(tree: ast.AST) -> Set[int]:
    """Ids of the calls written inside a ``with pytest.raises(TypeError)`` block."""
    guarded: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.With) and _expects_a_type_error(node):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    guarded.add(id(inner))
    return guarded


def _config_less_calls(source: str, label: str) -> List[str]:
    tree = ast.parse(source, filename=label)
    guarded = _guarded_calls(tree)
    found: List[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _callee_name(node) != CALLEE:
            continue
        if id(node) in guarded or _passes_a_config(node):
            continue
        found.append(f"{label}:{node.lineno}")
    return found


def _test_files() -> List[Path]:
    return sorted(
        path for path in TESTS_ROOT.rglob("*.py") if "__pycache__" not in path.parts
    )


def test_the_walk_sees_a_call_without_a_config() -> None:
    """The must-flag controls: a bare call, and one inside the wrong ``raises``."""
    bare = "check_runtime_ops(ops, allowlist=policy)\n"
    assert _config_less_calls(bare, "bare.py") == ["bare.py:1"]
    wrong_raises = (
        "with pytest.raises(RuntimePatchDeniedError):\n"
        "    check_runtime_ops(ops, allowlist=policy)\n"
    )
    assert _config_less_calls(wrong_raises, "denied.py") == ["denied.py:2"]


def test_the_walk_accepts_a_call_with_a_config() -> None:
    """The must-not-flag controls: ``config=None``, a config object, a splat, and
    the guard test's own call inside ``pytest.raises(TypeError)``."""
    for source in (
        "check_runtime_ops(ops, allowlist=policy, config=None)\n",
        "runtime_patch.check_runtime_ops(ops, allowlist=policy, config=base)\n",
        "check_runtime_ops(ops, **kwargs)\n",
        (
            "with pytest.raises(TypeError, match='config'):\n"
            "    check_runtime_ops([], allowlist=policy)\n"
        ),
    ):
        assert _config_less_calls(source, "ok.py") == [], source


def test_every_test_call_of_check_runtime_ops_passes_a_config() -> None:
    """The guard test keeps the signature free of a default; this one keeps the
    callers honest about it, so a missing argument is a listed location and
    not a ``TypeError`` inside an unrelated test."""
    files = _test_files()
    assert files, TESTS_ROOT
    offenders: List[str] = []
    for path in files:
        label = path.relative_to(REPO_ROOT).as_posix()
        offenders.extend(_config_less_calls(path.read_text(encoding="utf-8"), label))
    assert offenders == [], "\n".join(offenders)
