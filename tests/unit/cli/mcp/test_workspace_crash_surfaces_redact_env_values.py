# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A crashed workspace run shows a config's environment value on no surface.

The projects' configs read values from the environment, and the run's failure
can quote one: the exception execute_workspace raises is written to the scan
entries, the progress answers, and the MCP response. The crash arm carries
the run's environment values on the exception, so every one of those writers
redacts. The arm writes no log line carrying the failure text (a cell below
pins that, so a later log write has to bring its own redaction cell). The
response is the surface that regressed before: its text comes from the
exception alone, so an uncarried exception printed the value.
"""

import json
import logging

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.utils.log import ASH_LOGGER

from tests.unit.cli.mcp.test_mcp_resource_limits import (
    _scan_workspace,
    _workspace,
    _workspace_entries,
)

pytestmark = pytest.mark.unit

SECRET = "ws-crash-canary-h6j1"


@pytest.fixture(autouse=True)
def _isolated_mcp_state(tmp_path, monkeypatch):
    from automated_security_helper.core.resource_management import scan_registry

    monkeypatch.setattr(scan_registry, "_scan_registry", ScanRegistry())
    for name in ("ASH_MCP_ALLOWED_CONFIG_ROOTS", "ASH_MCP_TRANSPORT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "allowed"))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    (tmp_path / "allowed").mkdir()


def _shows(canary: str, text: str) -> bool:
    flat = "".join(text.split())
    return canary in text or canary in flat or canary[:12] in flat


class _Collect(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines = []

    def emit(self, record):
        text = record.getMessage()
        if record.exc_info:
            text += " " + logging.Formatter().formatException(record.exc_info)
        self.lines.append(text)


@pytest.fixture
def logged():
    handler = _Collect()
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield handler.lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


async def _crashed_workspace(tmp_path, monkeypatch, collected):
    """Run a workspace scan whose projects' configs read SECRET from the
    environment and whose run crashes quoting it; return every surface."""
    from automated_security_helper.cli.mcp import workspace as workspace_module

    monkeypatch.setenv("ASH_WS_CRASH_HELD", SECRET)
    workspace_file = _workspace(tmp_path, "api", "web")
    for name in ("api", "web"):
        (workspace_file.parent / name / ".ash.yaml").write_text(
            "project_name: ${ASH_WS_CRASH_HELD:unset}\n", encoding="utf-8"
        )

    def _execute(plan, settings, **kwargs):
        raise RuntimeError(f"the run broke: {SECRET}")

    monkeypatch.setattr(workspace_module, "execute_workspace", _execute)
    response = await _scan_workspace(workspace_file)
    entries = _workspace_entries()
    if response.get("success") is not False or set(entries) != {"api", "web"}:
        raise RuntimeError(("premise: the run failed registered", response, entries))
    progress = {}
    for key, entry in entries.items():
        progress[key] = await mcp_tools.mcp_get_scan_progress(entry.scan_id)
    return {
        "entries": json.dumps({k: e.error_message for k, e in entries.items()}),
        "progress": json.dumps(progress, default=str),
        "response": json.dumps(response, default=str),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["entries", "progress", "response"])
async def test_a_crashed_workspace_run_shows_the_value_on_no_surface(
    tmp_path, monkeypatch, logged, surface
):
    surfaces = await _crashed_workspace(tmp_path, monkeypatch, logged)
    if "the run broke" not in surfaces["entries"]:
        raise RuntimeError(
            ("premise: the entries carry the failure", surfaces["entries"])
        )
    text = surfaces[surface]
    # The test-report backstop rewrites env values in pytest's own output, so
    # the message marks where the canary sat with a token that is no env value.
    marked = text.replace(SECRET, "@@CANARY-HERE@@")
    assert not _shows(SECRET, text), (surface, text.count(SECRET), marked[:2000])


@pytest.mark.asyncio
async def test_the_crash_arm_writes_no_log_line_with_the_failure_text(
    tmp_path, monkeypatch, logged
):
    """The arm answers through the response and the entries; no ASH_LOGGER
    line carries the failure text, so there is no log surface to redact on
    this path. If this pin fails, a log write was added to the arm: give the
    log surface its own redaction cell with a premise that the line exists."""
    await _crashed_workspace(tmp_path, monkeypatch, logged)
    carrying = [line for line in logged if "the run broke" in line]
    assert carrying == [], carrying
    # The whole-log check the failure-text pin had replaced: a line that
    # carries the value some other way -- a DEBUG config dump, a traceback
    # frame -- is a leak whether or not it quotes the failure.
    assert not _shows(SECRET, "\n".join(logged))


@pytest.mark.asyncio
@pytest.mark.parametrize("part", ["error", "context"])
async def test_a_resource_error_raised_by_the_run_hides_the_value(
    tmp_path, monkeypatch, logged, part
):
    """An MCPResourceError the run raises is printed with its text AND its
    context (create_error_response shows error.context's strings as they
    are), so the arm redacts the context with the run's values, as the
    single-scan arm redacts its own."""
    from automated_security_helper.cli.mcp import workspace as workspace_module
    from automated_security_helper.core.resource_management.exceptions import (
        MCPResourceError,
    )

    monkeypatch.setenv("ASH_WS_CRASH_HELD", SECRET)
    workspace_file = _workspace(tmp_path, "api", "web")
    for name in ("api", "web"):
        (workspace_file.parent / name / ".ash.yaml").write_text(
            "project_name: ${ASH_WS_CRASH_HELD:unset}\n", encoding="utf-8"
        )

    def _execute(plan, settings, **kwargs):
        raise MCPResourceError(
            f"the run broke: {SECRET}",
            context={"error_category": "unexpected_error", "detail": f"near {SECRET}"},
        )

    monkeypatch.setattr(workspace_module, "execute_workspace", _execute)
    response = await _scan_workspace(workspace_file)
    if response.get("success") is not False or "the run broke" not in (
        response.get("error") or ""
    ):
        raise RuntimeError(("premise: crash arm", response))
    if "detail" not in (response.get("context") or {}):
        raise RuntimeError(("premise: the context is shown", response))
    shown = (
        response.get("error")
        if part == "error"
        else json.dumps(response.get("context"), default=str)
    )
    assert not _shows(SECRET, shown), (part, shown)


@pytest.mark.asyncio
async def test_a_non_utf8_path_refusal_raised_in_the_run_hides_the_value(
    tmp_path, monkeypatch, logged
):
    """The response's error for a WorkspacePathNotUtf8Error is rewritten on
    one line, through error_text, so values the arm carried stay redacted.
    Only the resolver and the workspace-file reader raise it today, before
    any project config is read; this cell pins what the arm does if the run
    ever raises one."""
    from automated_security_helper.cli.mcp import workspace as workspace_module
    from automated_security_helper.core.exceptions import WorkspacePathNotUtf8Error

    monkeypatch.setenv("ASH_WS_CRASH_HELD", SECRET)
    workspace_file = _workspace(tmp_path, "api", "web")
    for name in ("api", "web"):
        (workspace_file.parent / name / ".ash.yaml").write_text(
            "project_name: ${ASH_WS_CRASH_HELD:unset}\n", encoding="utf-8"
        )

    def _execute(plan, settings, **kwargs):
        raise WorkspacePathNotUtf8Error(f"the run broke: {SECRET}")

    monkeypatch.setattr(workspace_module, "execute_workspace", _execute)
    response = await _scan_workspace(workspace_file)
    if response.get("success") is not False or "the run broke" not in (
        response.get("error") or ""
    ):
        raise RuntimeError(("premise: crash arm", response))
    assert not _shows(SECRET, response.get("error") or ""), response.get("error")
