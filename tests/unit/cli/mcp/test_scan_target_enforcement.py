#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan-target root policy is enforced at both MCP entry points.

``run_ash_scan`` (the registered MCP tool) and ``mcp_scan_directory`` (the
function behind it, which is also callable directly) each take a
caller-supplied directory and each act on it before the other has run. Both
have to consult the policy, so both are pinned here.

Every assertion in this module reads either the returned response dict or real
filesystem state. None of them read an attribute off a Mock, because a Mock
invents attributes on demand and would answer "yes" to a question the code
never asked.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV


@pytest.fixture
def mock_ctx():
    ctx = MagicMock()
    ctx.info = AsyncMock()
    ctx.debug = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.error = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


@pytest.fixture(autouse=True)
def _clear_policy_env(monkeypatch):
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _project_with_stale_results(tmp_path: Path) -> tuple[Path, Path]:
    """Build a scan target that already holds an aggregated results file."""
    project = tmp_path / "project"
    output_dir = project / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    results = output_dir / "ash_aggregated_results.json"
    results.write_text("{}")
    return project, results


class TestRunAshScanEnforcement:
    """The registered MCP tool refuses a target outside the configured roots."""

    @pytest.mark.asyncio
    async def test_refused_target_does_not_reach_the_scan(
        self, tmp_path, monkeypatch, mock_ctx
    ):
        from automated_security_helper.cli.mcp_server import run_ash_scan

        project, _results = _project_with_stale_results(tmp_path)
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(allowed))

        with patch(
            "automated_security_helper.cli.mcp_server.mcp_scan_directory",
            new_callable=AsyncMock,
        ) as mock_scan:
            result = await run_ash_scan(ctx=mock_ctx, source_dir=str(project))

        assert result["success"] is False
        assert result["error_type"] == "scan_target_not_permitted"
        assert result["error_category"] == "invalid_path"
        mock_scan.assert_not_called()

    @pytest.mark.asyncio
    async def test_refused_target_keeps_its_existing_results_file(
        self, tmp_path, monkeypatch, mock_ctx
    ):
        """The refusal lands before ``clean_output`` deletes anything.

        ``clean_output`` removes a file inside a caller-named directory, so it
        is the first thing in this tool that acts on the target. If the policy
        were consulted after it -- for instance by leaving validation to
        ``mcp_scan_directory`` alone -- a refused target would still have had a
        file deleted from it by the time the refusal was returned. The
        surviving file is what makes the ordering observable.
        """
        from automated_security_helper.cli.mcp_server import run_ash_scan

        project, results = _project_with_stale_results(tmp_path)
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(allowed))

        with patch(
            "automated_security_helper.cli.mcp_server.mcp_scan_directory",
            new_callable=AsyncMock,
            return_value={"success": True, "scan_id": "should-not-happen"},
        ):
            result = await run_ash_scan(
                ctx=mock_ctx, source_dir=str(project), clean_output=True
            )

        assert result["success"] is False
        assert results.exists(), (
            "clean_output deleted a file from a directory the policy refuses"
        )

    @pytest.mark.asyncio
    async def test_allowed_target_scans_and_cleans(
        self, tmp_path, monkeypatch, mock_ctx
    ):
        """Positive control for the pair of assertions above.

        Same tool, same fixture, same ``clean_output=True``. Only the allowlist
        differs. This half must reach the scan and must delete the stale file,
        which is what distinguishes a policy that decides from one that refuses
        everything it is given.
        """
        from automated_security_helper.cli.mcp_server import run_ash_scan

        project, results = _project_with_stale_results(tmp_path)
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_scan_directory",
                new_callable=AsyncMock,
                return_value={"success": True, "scan_id": "scan-allowed"},
            ) as mock_scan,
            patch(
                "automated_security_helper.cli.mcp_server.asyncio.create_task"
            ) as mock_task,
        ):
            mock_task.return_value = MagicMock()
            result = await run_ash_scan(
                ctx=mock_ctx, source_dir=str(project), clean_output=True
            )

        assert result["success"] is True
        assert result["scan_id"] == "scan-allowed"
        mock_scan.assert_called_once()
        assert not results.exists()


class TestMcpScanDirectoryEnforcement:
    """The underlying function refuses independently of the tool wrapper."""

    @pytest.mark.asyncio
    async def test_refused_target_gets_no_output_directory(self, tmp_path, monkeypatch):
        """A refusal must not leave a ``.ash`` tree behind in the target.

        ``mcp_scan_directory`` creates ``<target>/.ash/ash_output`` with
        ``parents=True``, so accepting a target is also a decision to write
        into it. The absence of that directory afterwards is a real filesystem
        fact, not a mocked one.
        """
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        project = tmp_path / "project"
        project.mkdir()
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(allowed))

        with patch(
            "automated_security_helper.cli.mcp_tools.asyncio.create_task"
        ) as mock_task:
            mock_task.return_value = MagicMock()
            result = await mcp_scan_directory(directory_path=str(project))

        assert result["success"] is False
        assert not (project / ".ash").exists()
        mock_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_policy_is_evaluated_before_existence(self, tmp_path, monkeypatch):
        """A refused target reports the refusal, not "directory not found".

        The policy check deliberately ignores existence so that it can run
        first. That makes the order of the two checks load-bearing: if
        existence were consulted first, a refused-and-absent path would come
        back as a missing directory and the operator would never learn that a
        root policy exists. Pinning the category pins the order.
        """
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        allowed = tmp_path / "allowed"
        allowed.mkdir()
        absent = tmp_path / "never-created"
        assert not absent.exists()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(allowed))

        result = await mcp_scan_directory(directory_path=str(absent))

        assert result["success"] is False
        assert result["error_category"] == "invalid_path"

    @pytest.mark.asyncio
    async def test_absent_but_allowed_target_still_reports_not_found(
        self, tmp_path, monkeypatch
    ):
        """The other side of that order: policy passing does not mask existence.

        Without this half, a policy check that returned "refused" for every
        input would satisfy the test above.
        """
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        absent = tmp_path / "never-created"
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))

        result = await mcp_scan_directory(directory_path=str(absent))

        assert result["success"] is False
        assert result["error_category"] == "file_not_found"

    @pytest.mark.asyncio
    async def test_session_id_reaches_the_policy(self, tmp_path, monkeypatch):
        """The session id is passed through, not dropped on the floor.

        A session's own workspace is scannable only if ``mcp_scan_directory``
        hands its ``session_id`` to the policy. Testing the policy directly
        cannot see that wiring: the same target has to be refused without the
        id and accepted with it, through this function.
        """
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        workspace = tmp_path / "cache" / "ash-mcp"
        session = workspace / "session-7"
        session.mkdir(parents=True)
        repos = tmp_path / "repos"
        repos.mkdir()
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(repos))

        with patch(
            "automated_security_helper.cli.mcp_tools.asyncio.create_task"
        ) as mock_task:
            mock_task.return_value = MagicMock()
            without = await mcp_scan_directory(directory_path=str(session))
            with_id = await mcp_scan_directory(
                directory_path=str(session), session_id="session-7"
            )

        assert without["success"] is False
        assert without["error_category"] == "invalid_path"
        assert with_id["success"] is True

    @pytest.mark.asyncio
    async def test_allowed_target_starts_a_scan(self, tmp_path, monkeypatch):
        """Positive control: an allowed target reaches the scan machinery."""
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        project = tmp_path / "project"
        project.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))

        with patch(
            "automated_security_helper.cli.mcp_tools.asyncio.create_task"
        ) as mock_task:
            mock_task.return_value = MagicMock()
            result = await mcp_scan_directory(directory_path=str(project))

        assert result["success"] is True
        assert (project / ".ash" / "ash_output").is_dir()
        mock_task.assert_called_once()
