# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP scan tools give a committed-output refusal the exit code the CLI exits with.

Why this exists
---------------
A file git tracks where a scan deletes or writes its own output stops the scan,
and so does any file there when git cannot say what is committed
(core/committed_output.py). The CLI exits 3 for both. run_ash_scan and
scan_directory refuse the same tree before a scan starts, but their responses
carried no exit_code, unlike their other refusals (a link in the output tree,
for one), so a client that branches on exit_code had nothing to branch on.

Each cell refuses one tree through the CLI and through both MCP tools, and the
MCP responses must carry the CLI's code and its meaning.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from tests.unit.test_committed_output_refused_at_entry_points import _repo
from tests.unit.test_committed_output_when_git_cannot_answer import (
    _broken_repo,
    _no_orchestrator,
)
from tests.unit.test_committed_results_paths_are_never_deleted import (
    _confined,
    _snapshot,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def mcp_ctx():
    ctx = MagicMock()
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


@pytest.fixture
def isolated_registry(monkeypatch):
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


def _cli_exit_code(source, output) -> int:
    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )
    return exited.value.code


@pytest.mark.asyncio
@pytest.mark.parametrize("tree", ["committed", "git-cannot-answer"])
async def test_the_mcp_scan_tools_refuse_with_the_clis_exit_code(
    tmp_path, monkeypatch, mcp_ctx, isolated_registry, tree
):
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
    )
    from automated_security_helper.cli.mcp_server import run_ash_scan as scan_tool

    if tree == "committed":
        source, output = _repo(tmp_path, monkeypatch)
    else:
        source, output = _broken_repo(tmp_path, monkeypatch)
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    _confined(tmp_path, source, output)
    _no_orchestrator(monkeypatch)
    before = _snapshot(output)

    cli_code = _cli_exit_code(source, output)
    runner = AsyncMock()
    monkeypatch.setattr(mcp_tools, "_run_scan_async", runner)
    direct = await mcp_tools.mcp_scan_directory(directory_path=str(source))
    with (
        patch(
            "automated_security_helper.cli.mcp_server.mcp_scan_directory",
            new_callable=AsyncMock,
            return_value={"success": True, "scan_id": "should-not-start"},
        ) as started,
        patch("automated_security_helper.cli.mcp_server.asyncio.create_task"),
    ):
        tool = await scan_tool(ctx=mcp_ctx, source_dir=str(source), clean_output=True)

    assert cli_code == 3
    for response in (direct, tool):
        assert response["success"] is False, response
        assert response["exit_code"] == cli_code, response
        assert response["exit_code_meaning"] == ASH_EXIT_CODES[cli_code], response
    runner.assert_not_called()
    started.assert_not_called()
    assert _snapshot(output) == before
