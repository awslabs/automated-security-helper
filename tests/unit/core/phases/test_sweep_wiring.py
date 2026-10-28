# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every post-scan sweep in the executor passes the scope's values.

The failure this pins
---------------------
The executor's sweeps run OUTSIDE sandbox_scope, so the values argument is
their only redaction: a ``sweep_writable([...])`` call with the values
dropped (the MO1 wiring mutant) left every removal-failure warning
unredacted while every behavior cell stayed green, because those cells plant
no value in the swept names.

Scope, stated precisely: this guard walks scanner_executor.py's AST and
fails on any ``sweep_writable`` call with fewer than two positional
arguments and no ``values``-named keyword. It does not see aliased calls or
other modules; those stay the review's to catch.
"""

import ast
from pathlib import Path

import automated_security_helper.core.phases.scanner_executor as executor_module


def test_every_sweep_passes_the_scopes_values():
    tree = ast.parse(Path(executor_module.__file__).read_text(encoding="utf-8"))
    bare = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
        if name != "sweep_writable":
            continue
        has_values = len(node.args) >= 2 or any(
            kw.arg in ("values", "environment_values") for kw in node.keywords
        )
        if not has_values:
            bare.append(f"scanner_executor.py:{node.lineno}")
    assert bare == [], (
        "sweep_writable called without the scope's values -- the sweep runs "
        f"outside sandbox_scope, so values is its only redaction: {bare}"
    )
