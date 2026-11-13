#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The repository's uv configuration sets a dependency cooldown.

Why this file exists
--------------------
Both of the self-scan's SAST scanners flag ``package_managers.uv.uv-missing-dependency-cooldown``
on a ``pyproject.toml`` whose ``[tool.uv]`` table has no ``exclude-newer`` setting: a
version published minutes ago can otherwise enter the resolution before anyone has
looked at it. The cure the rule names is the one-line setting, and this test keeps it
from being dropped again.

What is asserted
----------------
``[tool.uv].exclude-newer`` is present in ``pyproject.toml`` and is spelled in one of
the two grammars uv documents: a friendly duration (``7 days``, ``24 hours``,
``1 week``) or an ISO 8601 duration (``P7D``, ``PT24H``).

What is not asserted, and why
-----------------------------
The lock half is not asserted. uv 0.11.4, the version CI installs
(``.github/actions/setup-ash/action.yml``), writes no ``[options]`` table into
``uv.lock`` from the ``[tool.uv]`` setting: ``uv lock`` reports that the existing lock
satisfies the workspace, and only the ``--exclude-newer`` command-line flag
re-resolves. A plain ``uv sync`` therefore reads the lock as written and does not
re-lock, so under that uv version the setting alone is the whole cure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
PYPROJECT = REPO_ROOT / "pyproject.toml"

# uv's own grammar for the setting: https://docs.astral.sh/uv/concepts/resolution/#dependency-cooldowns
COOLDOWN_GRAMMAR = re.compile(r"^(\d+ (hours?|days?|weeks?)|P(T\d+H|\d+D))$")


def test_pyproject_sets_a_uv_dependency_cooldown() -> None:
    with PYPROJECT.open("rb") as handle:
        tool_uv = tomllib.load(handle)["tool"]["uv"]
    assert "exclude-newer" in tool_uv, (
        "pyproject.toml [tool.uv] has no exclude-newer: the uv dependency cooldown is not set"
    )
    cooldown = tool_uv["exclude-newer"]
    assert isinstance(cooldown, str) and COOLDOWN_GRAMMAR.match(cooldown), (
        f"exclude-newer must be a friendly or ISO 8601 duration, got {cooldown!r}"
    )
