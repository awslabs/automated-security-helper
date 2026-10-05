#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The output tree ASH writes has to be inside the target the policy permitted.

What the root policy did and did not cover
-----------------------------------------
``validate_scan_target`` canonicalizes exactly one path, the target itself, and
its docstring names the case it was written for: a link sitting inside a
permitted root that points somewhere else. That covers the target *being* a
symlink. It does not cover a symlink *child*, because ``.ash`` is not part of
what was resolved -- and both consumers then built ``<target>/.ash/ash_output``
from the caller's unresolved text.

Accepting a target is also a decision to write into it, and the two writes are
not symmetric in how they fail:

* ``mcp_scan_directory`` calls ``mkdir(parents=True, exist_ok=True)``, which
  follows a symlinked ``.ash`` and creates the output tree wherever the link
  points -- outside the permitted roots, and outside the session workspace.
* ``run_ash_scan`` with ``clean_output=True`` calls ``os.remove`` on
  ``<target>/.ash/ash_output/ash_aggregated_results.json``, which follows the
  same link and deletes a file the caller never named.

So each consumer is pinned separately here, with an assertion on real filesystem
state rather than on a mock: the point is what ended up on disk.

Positive controls are in the same classes on purpose. A guard that refused every
target would satisfy the refusal assertions on its own, and the ordinary case --
a real ``.ash`` directory, created and written -- is the thing that must keep
working.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli.mcp.scan_target import (
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ScanTargetResolution,
    resolve_scan_target,
    validate_output_tree,
    validate_scan_target,
)


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


def _permitted_target_with_symlinked_ash(
    tmp_path: Path, monkeypatch
) -> tuple[Path, Path]:
    """A target the policy permits, whose ``.ash`` child points out of the roots."""
    permitted = tmp_path / "repo"
    permitted.mkdir()
    outside = tmp_path / "outside-the-permitted-roots"
    outside.mkdir()
    (permitted / ".ash").symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(permitted))
    return permitted, outside


class TestMcpScanDirectoryOutputContainment:
    @pytest.mark.asyncio
    async def test_a_symlinked_ash_child_is_refused(self, tmp_path, monkeypatch):
        permitted, outside = _permitted_target_with_symlinked_ash(tmp_path, monkeypatch)
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        with patch(
            "automated_security_helper.cli.mcp_tools.asyncio.create_task"
        ) as mock_task:
            mock_task.return_value = MagicMock()
            result = await mcp_scan_directory(directory_path=str(permitted))

        assert result["success"] is False
        assert result["error_category"] == "invalid_path"
        assert not (outside / "ash_output").exists(), (
            "mkdir followed the symlinked .ash and created the output tree "
            "outside the permitted roots"
        )
        mock_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_a_symlinked_ash_output_grandchild_is_refused(
        self, tmp_path, monkeypatch
    ):
        """The walk has to check every component it is about to create, not just one.

        ``.ash`` real and ``.ash/ash_output`` linked is the same escape one level
        down, and a check that only looked at ``.ash`` would miss it.
        """
        permitted = tmp_path / "repo"
        (permitted / ".ash").mkdir(parents=True)
        outside = tmp_path / "outside-the-permitted-roots"
        outside.mkdir()
        (permitted / ".ash" / "ash_output").symlink_to(
            outside, target_is_directory=True
        )
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(permitted))
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        with patch(
            "automated_security_helper.cli.mcp_tools.asyncio.create_task"
        ) as mock_task:
            mock_task.return_value = MagicMock()
            result = await mcp_scan_directory(directory_path=str(permitted))

        assert result["success"] is False
        assert not (outside / "reports").exists()
        mock_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_an_ordinary_target_still_gets_its_output_tree(
        self, tmp_path, monkeypatch
    ):
        """Positive control: no symlink, so the scan starts and the tree is created."""
        project = tmp_path / "project"
        project.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        with patch(
            "automated_security_helper.cli.mcp_tools.asyncio.create_task"
        ) as mock_task:
            mock_task.return_value = MagicMock()
            result = await mcp_scan_directory(directory_path=str(project))

        assert result["success"] is True
        assert (project / ".ash" / "ash_output").is_dir()
        assert not (project / ".ash" / "ash_output").is_symlink()

    @pytest.mark.asyncio
    async def test_the_output_tree_is_created_where_the_check_looked(
        self, tmp_path, monkeypatch
    ):
        """The directory created has to be the one ``validate_output_tree`` checked.

        With the target reached through a symlink that stays inside the permitted
        roots, both spellings name the same bytes on disk, so nothing escapes
        either way -- which is why this is an assertion about the path rather than
        about a victim file. It is here because the two builders drifting apart is
        the defect: the guard canonicalizes, and a consumer that then joins onto
        the caller's text is checking one path and writing another.
        """
        real = tmp_path / "real-repo"
        real.mkdir()
        link = tmp_path / "link-to-repo"
        link.symlink_to(real, target_is_directory=True)
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        with patch(
            "automated_security_helper.cli.mcp_tools.asyncio.create_task"
        ) as mock_task:
            mock_task.return_value = MagicMock()
            result = await mcp_scan_directory(directory_path=str(link))

        assert result["success"] is True
        assert result["output_directory"] == str(real.resolve() / ".ash" / "ash_output")

    @pytest.mark.asyncio
    async def test_an_existing_real_output_tree_is_reused(self, tmp_path, monkeypatch):
        """Second control: ``exist_ok=True`` behavior is unchanged for a real tree."""
        project = tmp_path / "project"
        (project / ".ash" / "ash_output").mkdir(parents=True)
        (project / ".ash" / "ash_output" / "leftover.json").write_text("{}")
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        with patch(
            "automated_security_helper.cli.mcp_tools.asyncio.create_task"
        ) as mock_task:
            mock_task.return_value = MagicMock()
            result = await mcp_scan_directory(directory_path=str(project))

        assert result["success"] is True
        assert (project / ".ash" / "ash_output" / "leftover.json").exists()


class TestRunAshScanOutputContainment:
    @pytest.mark.asyncio
    async def test_clean_output_cannot_delete_through_a_symlinked_ash(
        self, tmp_path, monkeypatch, mock_ctx
    ):
        permitted, outside = _permitted_target_with_symlinked_ash(tmp_path, monkeypatch)
        victim_dir = outside / "ash_output"
        victim_dir.mkdir()
        victim = victim_dir / "ash_aggregated_results.json"
        victim.write_text('{"not": "this session\'s results"}')
        from automated_security_helper.cli.mcp_server import run_ash_scan

        with patch(
            "automated_security_helper.cli.mcp_server.mcp_scan_directory",
            new_callable=AsyncMock,
            return_value={"success": True, "scan_id": "should-not-happen"},
        ) as mock_scan:
            result = await run_ash_scan(
                ctx=mock_ctx, source_dir=str(permitted), clean_output=True
            )

        assert result["success"] is False
        assert result["error_category"] == "invalid_path"
        assert victim.exists(), (
            "clean_output followed the symlinked .ash and deleted a file outside "
            "the permitted roots"
        )
        mock_scan.assert_not_called()

    @pytest.mark.asyncio
    async def test_clean_output_still_removes_a_real_results_file(
        self, tmp_path, monkeypatch, mock_ctx
    ):
        """Positive control for the assertion above: the real path still gets cleaned."""
        project = tmp_path / "project"
        output_dir = project / ".ash" / "ash_output"
        output_dir.mkdir(parents=True)
        results = output_dir / "ash_aggregated_results.json"
        results.write_text("{}")
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
        from automated_security_helper.cli.mcp_server import run_ash_scan

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_scan_directory",
                new_callable=AsyncMock,
                return_value={"success": True, "scan_id": "scan-allowed"},
            ),
            patch(
                "automated_security_helper.cli.mcp_server.asyncio.create_task"
            ) as mock_task,
        ):
            mock_task.return_value = MagicMock()
            result = await run_ash_scan(
                ctx=mock_ctx, source_dir=str(project), clean_output=True
            )

        assert result["success"] is True
        assert not results.exists()


class TestResolveScanTarget:
    """The policy hands back what it canonicalized, so consumers stop re-deriving it."""

    def test_a_permitted_target_comes_back_resolved(self, tmp_path, monkeypatch):
        real = tmp_path / "real-repo"
        real.mkdir()
        link = tmp_path / "link-to-repo"
        link.symlink_to(real, target_is_directory=True)
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))

        resolution = resolve_scan_target(str(link))

        assert resolution.error is None
        assert resolution.resolved == real.resolve()

    def test_a_refused_target_carries_no_resolved_path(self, tmp_path, monkeypatch):
        permitted = tmp_path / "permitted"
        permitted.mkdir()
        refused = tmp_path / "elsewhere"
        refused.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(permitted))

        resolution = resolve_scan_target(str(refused))

        assert resolution.resolved is None
        assert resolution.error is not None

    def test_require_refuses_a_resolution_that_carries_neither_field(self):
        """The accessor's own contract, since consumers build paths from it.

        Not reachable through either constructor -- both set exactly one field --
        so it is exercised directly rather than left as an untested branch.
        """
        with pytest.raises(ValueError, match="check .error"):
            ScanTargetResolution().require()

    def test_require_returns_the_resolved_path(self, tmp_path):
        assert ScanTargetResolution(resolved=tmp_path).require() == tmp_path

    def test_validate_scan_target_still_returns_only_the_refusal(
        self, tmp_path, monkeypatch
    ):
        """The older signature keeps working for the callers that only ask yes/no."""
        permitted = tmp_path / "permitted"
        permitted.mkdir()
        refused = tmp_path / "elsewhere"
        refused.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(permitted))

        assert validate_scan_target(str(permitted)) is None
        assert validate_scan_target(str(refused)) is not None


class TestValidateOutputTree:
    """The containment check itself, exercised without a consumer in the way."""

    def test_a_real_relative_tree_is_permitted(self, tmp_path):
        assert validate_output_tree(tmp_path, ".ash", "ash_output") is None

    def test_a_symlinked_component_is_refused_even_when_it_points_inside(
        self, tmp_path
    ):
        """Containment alone would accept this, which is why the symlink test exists.

        ``.ash`` linked to a sibling *inside* the target resolves to a contained
        path, so the containment comparison passes and the write still lands
        somewhere the caller did not name. The candidate itself has to be a real
        directory -- the same rule the zip member handling applies to symlink
        entries.
        """
        inside = tmp_path / "somewhere-else-inside"
        inside.mkdir()
        (tmp_path / ".ash").symlink_to(inside, target_is_directory=True)

        error = validate_output_tree(tmp_path, ".ash", "ash_output")

        assert error is not None
        assert error.context["error_category"] == "invalid_path"

    def test_a_symlinked_component_pointing_outside_is_refused(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        target = tmp_path / "repo"
        target.mkdir()
        (target / ".ash").symlink_to(outside, target_is_directory=True)

        assert validate_output_tree(target, ".ash", "ash_output") is not None

    def test_the_refusal_names_the_component_that_failed(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        target = tmp_path / "repo"
        target.mkdir()
        (target / ".ash").symlink_to(outside, target_is_directory=True)

        error = validate_output_tree(target, ".ash", "ash_output")

        assert error is not None
        assert ".ash" in str(error)
