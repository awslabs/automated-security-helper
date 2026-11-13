# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The transpiler must import, with every backend registered, without python-frontmatter.

The drift check (scripts/check_agentic_plugins_drift.sh at the repository root) imports
transpiler.orchestrator inside the ASH virtual environment, which does not carry
python-frontmatter. That is why generic_skill imports frontmatter inside smoke_test()
rather than at module level: importing a backend registers it, and a registry with no
backends is a fault there. A top-level ``import frontmatter`` added to any backend or to
core would break only that environment -- every test that runs inside the transpiler's
own environment, where frontmatter is installed, would stay green.

This test blocks the module in a subprocess (``None`` in ``sys.modules`` makes the
import raise ImportError, the same observable shape as a missing install) and asserts
that importing the orchestrator still registers every backend.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TRANSPILER_DIR = Path(__file__).resolve().parent.parent

CODE = """\
import sys

sys.modules["frontmatter"] = None
sys.path.insert(0, sys.argv[1])

try:
    import frontmatter  # noqa: F401
except ImportError:
    pass
else:
    raise SystemExit("control failed: the frontmatter block is not effective")

from transpiler import orchestrator  # noqa: F401
from transpiler.registry import BackendRegistry

names = BackendRegistry.names()
assert names, "no backends registered"
print("BACKENDS", len(names))
"""


def test_orchestrator_imports_and_registers_backends_without_frontmatter():
    proc = subprocess.run(
        [sys.executable, "-I", "-B", "-c", CODE, str(TRANSPILER_DIR)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    tag, _, count = proc.stdout.strip().partition(" ")
    assert tag == "BACKENDS", proc.stdout
    assert count.isdigit() and int(count) > 0, proc.stdout
