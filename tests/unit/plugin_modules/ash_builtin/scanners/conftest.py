# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every test in this directory starts no program at all and leaves its HOME empty.

Every unit test runs under the tool guard of tests/unit/conftest.py, which fails one
that starts a guarded tool or leaves a tool's file in its HOME. Building a scanner
probes its tool: SemgrepScanner runs ``uv --version`` and then ``uv tool run --from
'semgrep...' semgrep --version``, and OpengrepScanner runs ``opengrep --version``.
Unstubbed, the offline-fallback tests here did that on every run, so a run fetched
and started semgrep wherever uv could reach PyPI, and semgrep and uv wrote
``~/.cache/semgrep_version``, ``~/.config/.semgrep`` and ``~/.local/share/uv/tools``
under the HOME of the run.

So the check here is stricter. A test fails if the guard recorded any start but
git's and ASH's workers (a shell, this interpreter, a fork included), and if it left
any file in its HOME, ASH's own included. A test the unit tests' list lets run a
real tool (``runs_real_tools``) keeps the HOME check.
"""

from __future__ import annotations

import pytest

from tests.utils.tool_guard import files_left_in


@pytest.fixture(autouse=True)
def _nothing_started_and_nothing_left(request, _unit_tool_guard):
    yield
    guard, home = _unit_tool_guard
    if guard is not None:
        assert guard.started == [], f"{request.node.nodeid} started: {guard.started}"
    if home is not None:
        left = files_left_in(home)
        assert left == [], f"{request.node.nodeid} left files in HOME: {left}"
