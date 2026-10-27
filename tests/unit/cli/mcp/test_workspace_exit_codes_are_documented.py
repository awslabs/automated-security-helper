# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every exit code a workspace scan can return is documented where clients read it.

mcp_scan_workspace's docstring said a successful scan's ``exit_code`` was "0, or 2
when a project exceeded its threshold". A successful scan also returns 1 (a
project failed, or ran without one of its scanners finishing), 3 (a project's own
config is invalid) and 4 (no project was attempted), and a client that branched
on the two documented codes read those three as clean. The run_ash_workspace_scan
tool, whose docstring is the tool description clients are given, listed its codes
in one run with no word on which come from a scan that ran.

Both docstrings list the codes in an "On success" paragraph and an "On
failure" paragraph, and these tests tie the lists to the code:

- the success codes are exactly what workspace_exit_code can return, found by
  running it over every combination of project outcomes;
- the failure codes cover every code mcp_scan_workspace hands to an error
  response, and the code an unmapped error gets;
- every WorkspaceExitCode member is listed in one or the other, so a new code
  cannot go undocumented.
"""

from __future__ import annotations

import inspect
import itertools
import re
from types import SimpleNamespace
from typing import Callable, Set

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp import workspace as mcp_workspace
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceExitCode,
    workspace_exit_code,
)

#: How both docstrings introduce a code: "3 when ...", "1 for ...".
_CODE = re.compile(r"(?<![\w.`])([0-9])\s+(?:when|for)\b")

DOCUMENTED = [
    pytest.param(mcp_workspace.mcp_scan_workspace, id="mcp_scan_workspace"),
    pytest.param(mcp_server.run_ash_workspace_scan, id="run_ash_workspace_scan"),
]


def _paragraph(func: Callable, lead: str) -> str:
    """The Returns paragraph of ``func``'s docstring that starts with ``lead``."""
    doc = inspect.getdoc(func) or ""
    assert "Returns:" in doc, f"{func.__name__} has no Returns section"
    returns = doc.split("Returns:", 1)[1]
    for paragraph in returns.split("\n\n"):
        text = " ".join(paragraph.split())
        if text.startswith(lead):
            return text
    raise AssertionError(
        f"{func.__name__}'s Returns section has no paragraph starting {lead!r}"
    )


def _codes(text: str) -> Set[int]:
    return {int(code) for code in _CODE.findall(text)}


def _reachable_verdicts() -> Set[int]:
    """Every code workspace_exit_code returns, over up to two projects of any outcome."""
    outcomes = [
        SimpleNamespace(
            status=status,
            skip_reason=reason,
            invalid_config=invalid,
            exceeds_threshold=exceeds,
            scan_incomplete=incomplete,
        )
        for status in ProjectRunStatus
        for reason in (None, *SkippedProjectReason)
        for invalid in (False, True)
        for exceeds in (False, True)
        for incomplete in (False, True)
    ]
    verdicts = {int(workspace_exit_code([]))}
    for size in (1, 2):
        for projects in itertools.combinations_with_replacement(outcomes, size):
            verdicts.add(int(workspace_exit_code(list(projects))))
    return verdicts


def _refusal_codes() -> Set[int]:
    """Every code mcp_scan_workspace can put in an error response."""
    source = inspect.getsource(mcp_workspace.mcp_scan_workspace)
    named = {
        int(WorkspaceExitCode[name])
        for name in re.findall(r"exit_code=int\(WorkspaceExitCode\.(\w+)\)", source)
    }
    # A code passed by a module constant, OUTPUT_TREE_REFUSED_EXIT_CODE.
    constants = {
        int(getattr(mcp_workspace, name))
        for name in re.findall(r"exit_code=([A-Z][A-Z0-9_]*)\b", source)
    }
    mapped = {int(code) for _, code in mcp_workspace._EXIT_CODE_BY_EXCEPTION}
    return named | constants | mapped | {int(WorkspaceExitCode.INTERNAL_ERROR)}


def test_the_reachable_verdicts_are_found():
    """The enumeration reaches every verdict, so the check below can fail."""
    assert _reachable_verdicts() >= {0, 1, 2, 3, 4}


@pytest.mark.parametrize("func", DOCUMENTED)
def test_a_successful_scan_lists_every_verdict_it_can_return(func):
    documented = _codes(_paragraph(func, "On success"))
    reachable = _reachable_verdicts()
    assert documented == reachable, (
        f"{func.__name__} lists {sorted(documented)} for a scan that ran; "
        f"workspace_exit_code returns {sorted(reachable)}"
    )


@pytest.mark.parametrize("func", DOCUMENTED)
def test_a_refused_scan_lists_every_code_its_errors_get(func):
    documented = _codes(_paragraph(func, "On failure"))
    missing = _refusal_codes() - documented
    assert not missing, (
        f"{func.__name__} does not list {sorted(missing)} for a scan that did not "
        f"run; it lists {sorted(documented)}"
    )


@pytest.mark.parametrize("func", DOCUMENTED)
def test_every_workspace_exit_code_is_listed(func):
    documented = _codes(_paragraph(func, "On success")) | _codes(
        _paragraph(func, "On failure")
    )
    missing = {int(member) for member in WorkspaceExitCode} - documented
    assert not missing, f"{func.__name__} never lists {sorted(missing)}"


@pytest.mark.parametrize("func", DOCUMENTED)
def test_the_findings_verdict_says_at_or_above(func):
    """A finding at the threshold counts (aggregation.count_actionable_results)."""
    success = _paragraph(func, "On success")
    clause = re.search(r"(?<![\w.`])2\s+when\b([^;]*)", success)
    assert clause, f"{func.__name__} has no '2 when' clause: {success}"
    assert "at or above" in clause.group(1), clause.group(0)
