# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan the tool could not start leaves no run log scope behind.

``mcp_scan_directory`` opens the run's log scope before registering the scan,
and the runner task owns it from ``_start_scan_task`` on. Every way out of the
window between those two points -- the handled refusals and the unexpected
failures alike -- must end the scope, exactly once: a scope left active there
takes every later run's lines in the server, since the scope set is
process-wide (``utils.log._ACTIVE_RUN_LOG_SCOPES``), which is what these cells
read. The failures pinned are the ones with no handled arm of their own: a
set-aside failure that is not an OSError, and ``_start_scan_task`` itself
raising; the handled unmakeable-output refusal is the control.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.utils import log as log_module

pytestmark = pytest.mark.unit

SESSION = "client-one"


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.core.resource_management import scan_registry

    isolated = scan_registry.ScanRegistry()
    monkeypatch.setattr(scan_registry, "_scan_registry", isolated)
    return isolated


@pytest.fixture
def target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, registry) -> Path:
    roots = tmp_path / "roots"
    roots.mkdir()
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(roots))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    project = roots / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return project.resolve()


def _scan(target: Path, **kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    return asyncio.run(
        mcp_scan_directory(directory_path=str(target), session_id=SESSION, **kwargs)
    )


@pytest.fixture
def scopes_before():
    before = set(log_module._ACTIVE_RUN_LOG_SCOPES)
    yield before
    # Whatever a red state leaked, later tests must not inherit it.
    for scope in set(log_module._ACTIVE_RUN_LOG_SCOPES) - before:
        log_module.close_run_log_scope(scope)


def test_a_set_aside_failure_that_is_not_an_oserror_ends_the_scope(
    target, scopes_before, monkeypatch
):
    from automated_security_helper.core import previous_results

    def boom(self):
        raise RuntimeError("set-aside crashed")

    monkeypatch.setattr(previous_results.PreviousResults, "set_aside", boom)

    response = _scan(target, clean_output=True)

    assert response.get("success") is not True, response
    assert set(log_module._ACTIVE_RUN_LOG_SCOPES) == scopes_before, (
        "a failed start left its log scope active"
    )


def test_a_start_task_failure_ends_the_scope(target, scopes_before, monkeypatch):
    from automated_security_helper.cli import mcp_tools

    def boom(scan_id, runner, **start_options):
        # The coroutine handed in is closed so the test ends with no
        # never-awaited warning; the real failure mode leaves it unawaited.
        # The start's keywords (ran, if_never_run) are accepted and left
        # alone, so the failure the test reads is this one and not a
        # TypeError raised before the runner is closed.
        runner.close()
        raise RuntimeError("no event loop for the runner")

    monkeypatch.setattr(mcp_tools, "_start_scan_task", boom)

    response = _scan(target)

    assert response.get("success") is not True, response
    assert set(log_module._ACTIVE_RUN_LOG_SCOPES) == scopes_before, (
        "a failed start left its log scope active"
    )


def test_an_unmakeable_output_directory_still_ends_the_scope(target, scopes_before):
    """The control: the handled refusal (``.ash`` is a file, so the output
    directory cannot be made) ends its scope too."""
    (target / ".ash").write_text("not a directory\n", encoding="utf-8")

    response = _scan(target)

    assert response.get("success") is not True, response
    assert set(log_module._ACTIVE_RUN_LOG_SCOPES) == scopes_before, (
        "the handled refusal leaked its log scope"
    )
